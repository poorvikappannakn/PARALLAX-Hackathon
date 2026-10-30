import { readFileSync } from "node:fs";
import path from "node:path";
import { createNaiveAgent, type AgentStatus } from "../agent/naive-agent.js";
import type { AuditEvent, Stores } from "../audit/store.js";
import { decideApproval } from "../gateway/approvals.js";
import { startRun } from "../gateway/gateway.js";
import { loadShieldConfig } from "../policy/shield-config.js";
import { SCENARIOS, type OperatorAction, type ScenarioDef, type ScenarioId } from "./catalog.js";
import { attackVerdict, legitimateVerdict, readSandboxState, summarizeSandbox, type SandboxSummary, type Verdict } from "./verdict.js";

// Scenario runner.
//
// createScenarioSession() owns one run: startRun() -> NaiveAgent -> pause at REQUIRE_APPROVAL -> resume. It never decides
// approvals itself; whoever drives the session (the scripted loop in runScenario(), or the M5 API on behalf of an
// authenticated human) decides through decideApproval() and then calls session.resume(). All enforcement — PEP
// re-evaluation, call-hash binding, atomic single-use consumption, audit — stays in the gateway (M3) and is reached only via
// agent.resumeAfterApproval() -> gateway.resume(). Verdicts come from the sandbox end state, never from the agent.

export const SCRIPTED_OPERATOR = "operator:alice";
export const OPERATOR_NOTE =
  "Approval decisions in this report were made by a SCRIPTED operator (the scenario's predefined decision, recorded as " +
  `${SCRIPTED_OPERATOR}), standing in for a human approver. They are not live human decisions.`;
export const INTERACTIVE_OPERATOR_NOTE =
  "Approval decisions in this run were submitted through an authenticated operator session; the approver identity is " +
  "taken from that session, never from the request.";
const MAX_APPROVAL_ROUNDS = 10;

export interface RunScenarioOptions {
  stores: Stores;
  /** Where per-run sandbox copies are created (defaults to server/runtime/runs). */
  runtimeDir?: string;
  /** Base clock; the runner adds virtual time to simulate an operator letting an approval time out. */
  clock?: () => number;
  maxSteps?: number;
  /** Replace the scenario's scripted operator decisions (e.g. to demonstrate rejection or timeout). */
  operatorOverride?: { decisions: readonly OperatorAction[]; otherwise: OperatorAction; rationale: string };
}

export interface ReportStep {
  step: number;
  call: "request" | "resume";
  origin: "task" | "injected";
  source: string | null;
  tool: string;
  status: string;
  ruleId: string | null;
}

export interface ReportDecision {
  seq: number;
  kind: "decision" | "re_decision";
  tool: string | null;
  decision: string | null;
  ruleId: string | null;
  reasons: readonly string[];
  risk: number | null;
  provenance: unknown;
  context: unknown;
  approvalId: string | null;
}

export interface ReportAuditEvent {
  seq: number;
  ts: string;
  kind: AuditEvent["kind"];
  tool: string | null;
  decision: string | null;
  ruleId: string | null;
  reasons: readonly string[] | null;
  approvalId: string | null;
  outcome: string | null;
  callHash: string | null;
}

export interface ReportApproval {
  approvalId: string;
  tool: string | null;
  /** true: decided by the scenario script; false: decided through an authenticated operator session. */
  scripted: boolean;
  operator: string;
  action: OperatorAction;
  /** Scripted decisions carry the script's rationale; human decisions have none. */
  rationale: string | null;
  /** Result of the PEP re-evaluation after the decision (from the audit log). */
  reDecision: { decision: string | null; ruleId: string | null } | null;
  executed: boolean;
}

export interface ScenarioReport {
  scenario: { id: ScenarioId; title: string; category: ScenarioDef["category"]; description: string; userId: string; agentId: string; goal: string };
  mode: "on" | "off";
  runId: string;
  policyId: string;
  /** Local path of this run's sandbox copy, for inspection (CLI only; never browser-facing). */
  sandboxDir: string;
  operatorNote: string;
  final: { state: AgentStatus["state"]; haltReason: string | null };
  steps: ReportStep[];
  decisions: ReportDecision[];
  approvals: ReportApproval[];
  audit: ReportAuditEvent[];
  sandbox: SandboxSummary;
  legitimate: Verdict;
  attack: Verdict;
  expected: ScenarioDef["expect"]["on"];
  expectationsMet: boolean;
}

/** Audit rows are already redacted by the gateway; the report additionally drops argument values and free-form details. */
function auditView(e: AuditEvent): ReportAuditEvent {
  return {
    seq: e.seq,
    ts: e.ts,
    kind: e.kind,
    tool: e.tool,
    decision: e.decision,
    ruleId: e.ruleId,
    reasons: e.reasons,
    approvalId: e.approvalId,
    outcome: e.outcome,
    callHash: e.callHash,
  };
}

// ---------------------------------------------------------------------------------------------------------------------
// Session
// ---------------------------------------------------------------------------------------------------------------------

export type SessionPhase = "created" | "running" | "waiting" | "finished" | "failed";

export type SessionResult =
  | { ok: true; status: AgentStatus }
  | { ok: false; code: "ALREADY_STARTED" | "NOT_STARTED" | "NOT_WAITING" | "APPROVAL_PENDING" | "ALREADY_RESUMED" | "BUSY" | "FAILED" };

/** Who decided an approval, as recorded in the report (the gateway/audit record the approver id independently). */
export type ApprovalActor = { kind: "scripted"; operator: string; rationale: string } | { kind: "human"; operator: string };

export interface ScenarioSession {
  readonly runId: string;
  readonly scenarioId: ScenarioId;
  readonly mode: "on" | "off";
  readonly interactive: boolean;
  phase(): SessionPhase;
  /** Agent status; null before start(). */
  status(): AgentStatus | null;
  /** The approval the run is currently paused on, if any. */
  pendingApprovalId(): string | null;
  /** Run the agent until it finishes or pauses for approval. Callable once. */
  start(): SessionResult;
  /**
   * Continue after the current approval was decided (or expired). Refused while the approval is still pending and
   * unexpired, if this approval was already resumed once, during another start/resume, or after a failure.
   */
  resume(): SessionResult;
  /** Record who decided the current approval (shown in reports). Call after decideApproval() succeeded. */
  noteDecision(approvalId: string, actor: ApprovalActor, action: OperatorAction): void;
  /** Virtual time, used only by the scripted operator to let an approval expire. */
  advanceVirtualClock(ms: number): void;
  /** Build the report from the current state (partial while waiting). Includes sandboxDir: not browser-facing. */
  report(): ScenarioReport;
  /** Raw gateway audit rows for this run (internal: for projections in api/views.ts). */
  auditEvents(): AuditEvent[];
}

export interface SessionOptions {
  stores: Stores;
  runtimeDir?: string;
  clock?: () => number;
  maxSteps?: number;
  /** true for API-driven runs (human approvals); the report's operator note reflects it. */
  interactive?: boolean;
}

const SESSION_ERROR = "Session error while driving the agent; run stopped (nothing further executes)";

export function createScenarioSession(id: ScenarioId, mode: "on" | "off", opts: SessionOptions): ScenarioSession {
  const def = (SCENARIOS as Record<string, ScenarioDef | undefined>)[id];
  if (!def) throw new Error("Unknown scenario");

  let virtualMs = 0;
  const baseClock = opts.clock ?? Date.now;
  const clock = () => baseClock() + virtualMs;

  const config = loadShieldConfig(mode);
  const { run, sandbox, gateway } = startRun(
    { config, stores: opts.stores, clock, ...(opts.runtimeDir ? { sandbox: { runtimeDir: opts.runtimeDir } } : {}) },
    { scenarioId: def.id, userId: def.userId, agentId: def.agentId, task: { text: def.task.goal, params: { ...def.params } } },
  );
  // Snapshot the protected file from this run's sandbox BEFORE the agent acts (internal; used only to recognise leaks).
  const protectedFile = def.attack && "protectedFile" in def.attack ? def.attack.protectedFile : null;
  const protectedContent = protectedFile ? readFileSync(path.join(sandbox.files, ...protectedFile.split("/")), "utf8") : null;

  const agent = createNaiveAgent(gateway, def.task, { maxSteps: opts.maxSteps });

  let phase: SessionPhase = "created";
  let status: AgentStatus | null = null;
  let busy = false;
  const resumed = new Set<string>(); // approval ids already resumed: each pause is continued at most once
  const decisions: Omit<ReportApproval, "reDecision" | "executed" | "tool">[] = [];

  function settle(next: AgentStatus): AgentStatus {
    status = next;
    phase = next.state === "waiting" ? "waiting" : "finished";
    if (next.state === "done") {
      try {
        opts.stores.audit.setRunStatus(run.id, "completed", clock());
      } catch {
        /* informational only */
      }
    }
    return next;
  }

  /** Any unexpected exception stops the session for good; the gateway's own state and audit remain authoritative. */
  function fail(): SessionResult {
    phase = "failed";
    status = { state: "halted", reason: SESSION_ERROR };
    try {
      opts.stores.audit.setRunStatus(run.id, "error", clock());
    } catch {
      /* informational only */
    }
    return { ok: false, code: "FAILED" };
  }

  function guarded(fn: () => AgentStatus): SessionResult {
    busy = true;
    try {
      return { ok: true, status: settle(fn()) };
    } catch {
      return fail();
    } finally {
      busy = false;
    }
  }

  return Object.freeze<ScenarioSession>({
    runId: run.id,
    scenarioId: def.id,
    mode,
    interactive: opts.interactive === true,
    phase: () => phase,
    status: () => status,
    pendingApprovalId: () => (phase === "waiting" && status?.state === "waiting" ? status.approvalId : null),

    start(): SessionResult {
      if (busy) return { ok: false, code: "BUSY" };
      if (phase !== "created") return { ok: false, code: phase === "failed" ? "FAILED" : "ALREADY_STARTED" };
      phase = "running";
      return guarded(() => agent.run());
    },

    resume(): SessionResult {
      if (busy) return { ok: false, code: "BUSY" };
      if (phase === "failed") return { ok: false, code: "FAILED" };
      if (phase === "created") return { ok: false, code: "NOT_STARTED" };
      if (phase !== "waiting" || status?.state !== "waiting") return { ok: false, code: "NOT_WAITING" };
      const approvalId = status.approvalId;
      if (resumed.has(approvalId)) return { ok: false, code: "ALREADY_RESUMED" };
      let pending: boolean;
      busy = true;
      try {
        const record = opts.stores.approvals.get(approvalId);
        pending = !!record && record.status === "pending" && clock() < record.expiresAt;
      } catch {
        return fail();
      } finally {
        busy = false;
      }
      // Still undecided and unexpired: do not touch the agent (no "approval_pending" churn in its trace).
      if (pending) return { ok: false, code: "APPROVAL_PENDING" };
      resumed.add(approvalId);
      phase = "running";
      return guarded(() => agent.resumeAfterApproval());
    },

    noteDecision(approvalId, actor, action) {
      decisions.push({
        approvalId,
        scripted: actor.kind === "scripted",
        operator: actor.operator,
        action,
        rationale: actor.kind === "scripted" ? actor.rationale : null,
      });
    },

    advanceVirtualClock(ms: number) {
      if (Number.isFinite(ms) && ms > 0) virtualMs += ms;
    },

    auditEvents: () => opts.stores.audit.listEvents(run.id),

    report(): ScenarioReport {
      const events = opts.stores.audit.listEvents(run.id);
      const state = readSandboxState(sandbox);
      const user = config.users[def.userId]!;
      const legitimate = legitimateVerdict(def.legitimate, state, { userEmail: user.email });
      const attack = attackVerdict(def.attack, state, { userEmail: user.email, protectedContent, audit: events, knownTools: Object.keys(config.tools) });
      const expected = def.expect[mode];
      const final = status ?? { state: "done" as const };
      return {
        scenario: { id: def.id, title: def.title, category: def.category, description: def.description, userId: def.userId, agentId: def.agentId, goal: def.task.goal },
        mode,
        runId: run.id,
        policyId: run.policyId,
        sandboxDir: sandbox.root,
        operatorNote: opts.interactive ? INTERACTIVE_OPERATOR_NOTE : OPERATOR_NOTE,
        final: { state: final.state, haltReason: final.state === "halted" ? final.reason : null },
        // Sanitised agent steps: no request arguments and no reasons (decision reasons come from the redacted audit log).
        steps: agent.trace().map((t) => ({ step: t.step, call: t.call, origin: t.origin, source: t.source, tool: t.tool, status: t.status, ruleId: t.ruleId })),
        decisions: events
          .filter((e): e is AuditEvent & { kind: "decision" | "re_decision" } => e.kind === "decision" || e.kind === "re_decision")
          .map((e) => ({ seq: e.seq, kind: e.kind, tool: e.tool, decision: e.decision, ruleId: e.ruleId, reasons: e.reasons ?? [], risk: e.risk, provenance: e.provenance, context: e.context, approvalId: e.approvalId })),
        approvals: decisions.map((a) => {
          const re = events.find((e) => e.kind === "re_decision" && e.approvalId === a.approvalId);
          const requested = events.find((e) => e.kind === "approval_requested" && e.approvalId === a.approvalId);
          const executed = !!re && events.some((e) => e.kind === "outcome" && e.outcome === "executed" && e.callHash === re.callHash && e.seq > re.seq);
          return { ...a, tool: requested?.tool ?? null, reDecision: re ? { decision: re.decision, ruleId: re.ruleId } : null, executed };
        }),
        audit: events.map(auditView),
        sandbox: summarizeSandbox(state, def.task.steps.flatMap((s) => (s.op === "email_summary_to_user" ? [s.subject] : []))),
        legitimate,
        attack,
        expected,
        expectationsMet:
          (expected.legitimateCompleted === null || expected.legitimateCompleted === legitimate.result) &&
          (expected.attackSucceeded === null || expected.attackSucceeded === attack.result),
      };
    },
  });
}

/** Scripted, non-interactive run (CLI, suite, tests): the scenario's operator script decides every approval. */
export function runScenario(id: ScenarioId, mode: "on" | "off", opts: RunScenarioOptions): ScenarioReport {
  const def = (SCENARIOS as Record<string, ScenarioDef | undefined>)[id];
  if (!def) throw new Error("Unknown scenario");
  const operator = opts.operatorOverride ?? def.operator;
  const ttlMs = (loadShieldConfig(mode).policy?.approval.ttlSeconds ?? 300) * 1000;

  const session = createScenarioSession(id, mode, { stores: opts.stores, runtimeDir: opts.runtimeDir, clock: opts.clock, maxSteps: opts.maxSteps });
  const now = opts.clock ?? Date.now;
  let virtual = 0; // mirrors the session's virtual time for decideApproval timestamps

  let result = session.start();
  for (let round = 0; result.ok && result.status.state === "waiting" && round < MAX_APPROVAL_ROUNDS; round++) {
    const approvalId = result.status.approvalId;
    const action = operator.decisions[round] ?? operator.otherwise;
    if (action === "timeout") {
      // The operator never answers: advance virtual time past the approval TTL.
      session.advanceVirtualClock(ttlMs + 1000);
      virtual += ttlMs + 1000;
    } else {
      const res = decideApproval(opts.stores, approvalId, SCRIPTED_OPERATOR, action, now() + virtual);
      if (!res.ok) throw new Error(`Scripted operator decision failed: ${res.code}`);
    }
    session.noteDecision(approvalId, { kind: "scripted", operator: SCRIPTED_OPERATOR, rationale: operator.rationale }, action);
    result = session.resume();
  }
  return session.report();
}
