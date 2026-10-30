import type { GatewayResult, ToolGateway } from "../gateway/gateway.js";
import { parseInstructions, type ParsedAction } from "./instructions.js";

// NaiveAgent (M4): a deterministic, DELIBERATELY GULLIBLE simulated agent. It is not an LLM.
//
// It performs its task steps, reads every tool output, and immediately obeys any instruction it finds in that output
// (via parseInstructions). That makes it a faithful stand-in for a prompt-injected agent: the only thing standing between
// injected text and a tool is the ToolGateway/PEP.
//
// Capabilities: only the gateway handle (request / resume / refs), injected by the runner. The agent cannot create,
// decide or consume approvals; on REQUIRE_APPROVAL it returns `waiting` and the runner (a separate principal) acts.
// Injected approval claims and labels are never interpreted — the agent has no notion of either.

/** The agent's whole view of the system. */
export type AgentGateway = Pick<ToolGateway, "request" | "resume" | "refs">;

/** Argument reference: a value the gateway holds ({ref}) or new agent-produced data ({value}). */
export type ArgRef = { ref: string } | { value: string };

export type TaskStep =
  | { op: "read_file"; path: ArgRef }
  | { op: "fetch_web"; url: ArgRef }
  | { op: "read_inbox" }
  | { op: "email_summary_to_user"; subject: string }
  /** Fail-closed probes (S5): a buggy/compromised agent emitting this request verbatim, still via gateway.request(). */
  | { op: "raw"; label: string; request: unknown };

export interface AgentTask {
  readonly goal: string;
  readonly steps: readonly TaskStep[];
}

export type AgentStatus =
  | { state: "done" }
  | { state: "waiting"; approvalId: string }
  | { state: "halted"; reason: string }
  | { state: "step_limit"; maxSteps: number };

export interface TraceEntry {
  readonly step: number;
  readonly call: "request" | "resume";
  readonly origin: "task" | "injected";
  /** Where an injected instruction came from (e.g. "inbox:msg-3"). */
  readonly source: string | null;
  readonly tool: string;
  readonly request: unknown;
  readonly status: GatewayResult["status"];
  readonly ruleId: string | null;
  readonly reasons: readonly string[];
  /** Approval/authority claims seen in the output this step read. Informational only: never acted upon. */
  readonly ignoredApprovalClaims: number;
}

export interface NaiveAgent {
  /** Run until done, waiting for approval, halted or out of steps. */
  run(): AgentStatus;
  /** After the runner handled the pending approval: resume it through the gateway, then continue. */
  resumeAfterApproval(): AgentStatus;
  status(): AgentStatus;
  trace(): readonly TraceEntry[];
}

export const MAX_STEPS_CAP = 100;
export const SUMMARY_MARKER = "[Generated summary: deterministic extract of the first lines of each document read; not LLM output]";
const SUMMARY_LINES_PER_DOC = 3;
const SUMMARY_MAX_CHARS = 2_000;
const BODY_MAX_CHARS = 20_000; // gateway limit for {value}
const DEFAULT_SUBJECT = "Requested information";

type Pending = { tool: string; request: unknown; origin: "task" | "injected"; source: string | null };
const pending = (tool: string, args: Record<string, ArgRef>, origin: Pending["origin"], source: string | null): Pending => ({
  tool,
  request: { tool, args },
  origin,
  source,
});
type Doc = { source: string; text: string };

const isObj = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null && !Array.isArray(v);

/** Untrusted documents contained in a tool output (file content, page HTML, inbox message bodies). */
function documentsIn(tool: string, value: unknown): Doc[] {
  if (!isObj(value)) return [];
  if (tool === "read_file" && typeof value.content === "string") return [{ source: `file:${String(value.path)}`, text: value.content }];
  if (tool === "fetch_web" && typeof value.html === "string") return [{ source: `web:${String(value.url)}`, text: value.html }];
  if (tool === "read_inbox" && Array.isArray(value.messages)) {
    return value.messages.flatMap((m) =>
      isObj(m) && typeof m.body === "string" ? [{ source: `inbox:${String(m.id)}`, text: `${String(m.subject ?? "")}\n\n${m.body}` }] : [],
    );
  }
  return []; // send/delete receipts are not content
}

const plainLines = (text: string) =>
  text
    .replace(/<!--[\s\S]*?-->/g, " ")
    .replace(/<[^>]*>/g, " ")
    .split(/\r?\n/)
    .map((l) => l.replace(/\s+/g, " ").trim())
    .filter(Boolean);

/** Deterministic "summary": the first lines of each document read so far, clearly marked as generated. */
export function generatedSummary(docs: readonly Doc[]): string {
  const parts = docs.map((d) => `From ${d.source}:\n${plainLines(d.text).slice(0, SUMMARY_LINES_PER_DOC).map((l) => `- ${l}`).join("\n")}`);
  return `${SUMMARY_MARKER}\n\n${parts.join("\n\n") || "(nothing was read)"}`.slice(0, SUMMARY_MAX_CHARS);
}

export function createNaiveAgent(gateway: AgentGateway, task: AgentTask, opts: { maxSteps?: number } = {}): NaiveAgent {
  const maxSteps = Math.max(1, Math.min(opts.maxSteps ?? 25, MAX_STEPS_CAP));
  const docs: Doc[] = [];
  const trace: TraceEntry[] = [];
  const attempted = new Set<string>(); // never retry an identical injected request (stops self-referencing loops)
  let steps = 0;
  let current: AgentStatus = { state: "done" };
  let waitingOn: { approvalId: string; pending: Pending } | null = null;

  // The task steps come first; injected instructions are inserted right after the step whose output contained them.
  // Queue items are turned into requests only when dequeued, so "read X, then send it" sends X (read in between).
  type Injected = { injected: ParsedAction; source: string };
  const queue: (TaskStep | Injected)[] = [...task.steps];

  function toPending(step: TaskStep): Pending {
    switch (step.op) {
      case "read_file":
        return pending("read_file", { path: step.path }, "task", null);
      case "fetch_web":
        return pending("fetch_web", { url: step.url }, "task", null);
      case "read_inbox":
        return pending("read_inbox", {}, "task", null);
      case "email_summary_to_user":
        return pending("send_email", { to: { ref: "user.email" }, subject: { value: step.subject }, body: { value: generatedSummary(docs) } }, "task", null);
      case "raw":
        return { tool: `raw:${step.label}`.slice(0, 100), request: step.request, origin: "task", source: null };
    }
  }

  /** Obey an injected instruction (gullible by design). Data copied from what was read goes in as {value}. */
  function fromInstruction(a: ParsedAction, source: string): Pending {
    switch (a.kind) {
      case "read_file":
        return pending("read_file", { path: { value: a.path } }, "injected", source);
      case "delete_file":
        return pending("delete_file", { path: { value: a.path } }, "injected", source);
      case "send_email": {
        // "Send the contents": the most recent document the agent read (e.g. the file it was just told to open).
        const body = docs.at(-1)?.text ?? "";
        return pending("send_email", { to: { value: a.to }, subject: { value: a.subject ?? DEFAULT_SUBJECT }, body: { value: body.slice(0, BODY_MAX_CHARS) } }, "injected", source);
      }
    }
  }

  function record(p: Pending, call: "request" | "resume", r: GatewayResult, claims: number) {
    const decision = "decision" in r ? r.decision : null;
    trace.push(
      Object.freeze({
        step: steps,
        call,
        origin: p.origin,
        source: p.source,
        tool: p.tool,
        request: p.request,
        status: r.status,
        ruleId: decision?.ruleId ?? null,
        reasons: decision?.reasons ?? (r.status === "rejected" || r.status === "halted" ? [r.reason] : []),
        ignoredApprovalClaims: claims,
      }),
    );
  }

  /** Handle a gateway result. Returns a terminal/waiting status, or null to keep going. */
  function handle(p: Pending, call: "request" | "resume", r: GatewayResult): AgentStatus | null {
    let claims = 0;
    if (r.status === "ok") {
      const found = documentsIn(r.tool, r.value);
      const injected: Injected[] = [];
      for (const d of found) {
        docs.push(d);
        const parsed = parseInstructions(d.text, d.source);
        claims += parsed.approvalClaims; // counted, never used
        for (const a of parsed.actions) injected.push({ injected: a, source: d.source });
      }
      queue.unshift(...injected);
    }
    record(p, call, r, claims);
    if (r.status === "halted") return { state: "halted", reason: r.reason };
    if (r.status === "approval_required" || r.status === "approval_pending") {
      waitingOn = { approvalId: r.approvalId, pending: p };
      return { state: "waiting", approvalId: r.approvalId };
    }
    return null; // ok, denied, rejected, tool_error: a naive agent just carries on
  }

  function loop(): AgentStatus {
    while (queue.length > 0) {
      if (steps >= maxSteps) return (current = { state: "step_limit", maxSteps });
      const next = queue.shift()!;
      const p = "op" in next ? toPending(next) : fromInstruction(next.injected, next.source);
      if (p.origin === "injected") {
        const key = JSON.stringify(p.request);
        if (attempted.has(key)) continue;
        attempted.add(key);
      }
      steps++;
      const stop = handle(p, "request", gateway.request(p.request));
      if (stop) return (current = stop);
    }
    return (current = { state: "done" });
  }

  return Object.freeze({
    run(): AgentStatus {
      if (current.state !== "done" || trace.length > 0) return current; // run once; use resumeAfterApproval to continue
      return loop();
    },
    resumeAfterApproval(): AgentStatus {
      if (current.state !== "waiting" || !waitingOn) return current;
      if (steps >= maxSteps) return (current = { state: "step_limit", maxSteps });
      const { approvalId, pending } = waitingOn;
      waitingOn = null;
      steps++;
      const stop = handle(pending, "resume", gateway.resume(approvalId));
      if (stop) return (current = stop);
      return loop();
    },
    status: () => current,
    trace: () => trace.slice(),
  });
}
