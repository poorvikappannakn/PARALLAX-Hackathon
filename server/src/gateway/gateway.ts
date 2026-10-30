import { randomUUID } from "node:crypto";
import { z } from "zod";
import type { RunRecord, Stores, AuditEventInput, AuditEvent } from "../audit/store.js";
import type { ShieldConfig } from "../policy/shield-config.js";
import { createRunSandbox, type RunSandbox, type SandboxOptions } from "../sandbox/sandbox.js";
import { evaluate, type ApprovalEvidence, type Decision, type PepEnv, type ToolCallRequest } from "../shield/pep.js";
import type { DetectorResult } from "../shield/detector.js";
import { normalizeSandboxPath } from "../shield/paths.js";
import {
  confidentialityRank,
  extendContext,
  fromUser,
  generated,
  joinLabels,
  makeLabel,
  type Label,
  type Labeled,
} from "../shield/provenance.js";
import { createTicketAuthority } from "../shield/tickets.js";
import { createToolExecutor } from "../tools/index.js";

// ToolGateway: the trusted authority between an agent and its tools, and the only path to tool execution.
//
// Trust boundary (SYSTEM_ARCHITECTURE §6a):
//  - runId/agentId/userId come only from the server-side run record created in startRun().
//  - The agent never supplies labels. Each argument is either {ref} (a value the gateway holds, with the label the
//    gateway assigned) or {value} (new agent-produced data, labelled by the gateway as generated from the whole
//    run context — so it can never be more trusted than everything the agent has read).
//  - The run context label is owned here and only grows (joined with every tool output label).
//
// Order per call: trusted call construction -> PEP -> audit decision -> [approval] -> ticket -> executor -> audit outcome.
// Any audit write failure fails closed: no ticket/execution after a failed decision write; run halts after a failed outcome write.

export interface RunSpec {
  scenarioId: string;
  userId: string;
  agentId: string;
  task: { text: string; params?: Record<string, string> };
}

export interface GatewayDeps {
  config: ShieldConfig;
  stores: Stores;
  clock?: () => number;
  sandbox?: SandboxOptions;
}

export interface DecisionView {
  decision: Decision["decision"];
  ruleId: string;
  matchedRules: readonly string[];
  reasons: readonly string[];
  risk: number;
  policyVersion: string | null;
}

export type GatewayResult =
  | { status: "ok"; tool: string; ref: string; value: unknown; decision: DecisionView }
  | { status: "denied"; tool: string; decision: DecisionView }
  | { status: "approval_required"; tool: string; approvalId: string; expiresAt: number; decision: DecisionView }
  | { status: "approval_pending"; approvalId: string }
  | { status: "tool_error"; tool: string; code: string; message: string; decision: DecisionView }
  | { status: "rejected"; reason: string }
  | { status: "halted"; reason: string };

export interface ToolGateway {
  readonly runId: string;
  /** Submit an agent tool request: { tool, args: { name: {ref} | {value} } }. Nothing else is accepted. */
  request(raw: unknown): GatewayResult;
  /** Continue a call that required approval, after an operator decided it. */
  resume(approvalId: unknown): GatewayResult;
  /** Values the agent may reference (plain values only; labels stay with the gateway). */
  refs(): { ref: string; value: unknown }[];
  /** Current gateway-owned state (for UI/inspection). */
  state(): { halted: string | null; contextLabel: Label };
}

export interface StartedRun {
  run: RunRecord;
  sandbox: RunSandbox;
  gateway: ToolGateway;
}

const argSchema = z.union([
  z.object({ ref: z.string().min(1).max(100) }).strict(),
  z.object({ value: z.union([z.string().max(20_000), z.number().finite()]) }).strict(),
]);
const requestSchema = z
  .object({
    tool: z.string().min(1).max(100),
    args: z.record(z.string().regex(/^[a-z][a-z0-9_]{0,30}$/), argSchema),
  })
  .strict();

const PARAM_NAME = /^[a-z][a-z0-9_]{0,30}$/;
const has = (o: object, k: string) => Object.prototype.hasOwnProperty.call(o, k);
const MAX_UNTRUSTED_TEXTS = 20;
// Exactly the format produced by the approval store: `appr-${randomUUID()}`.
const APPROVAL_ID = /^appr-[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const APPROVAL_ID_LENGTH = 41;

function view(d: Decision): DecisionView {
  return { decision: d.decision, ruleId: d.ruleId, matchedRules: d.matchedRules, reasons: d.reasons, risk: d.risk, policyVersion: d.policyVersion };
}

/** Strip gateway labels before handing values to the agent. */
function plain(v: unknown): unknown {
  if (Array.isArray(v)) return v.map(plain);
  if (v && typeof v === "object") {
    const keys = Object.keys(v);
    if (keys.length === 2 && has(v, "value") && has(v, "label")) return plain((v as Labeled<unknown>).value);
    return Object.fromEntries(keys.map((k) => [k, plain((v as Record<string, unknown>)[k])]));
  }
  return v;
}

/** Audit copy of arguments: confidential/secret values are redacted; provenance is kept in full. */
function auditArgs(call: ToolCallRequest): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [name, arg] of Object.entries(call.args)) {
    const { value, label } = arg as Labeled<unknown>;
    out[name] =
      confidentialityRank(label.confidentiality) >= confidentialityRank("CONFIDENTIAL")
        ? `[REDACTED ${label.confidentiality}]`
        : typeof value === "string" && value.length > 2000
          ? `${value.slice(0, 2000)}…`
          : value;
  }
  return out;
}

type Sensitive = { text: string; level: string };

/**
 * CONFIDENTIAL/SECRET argument values (plus their normalised path form, since PEP reasons echo that) that must not
 * appear in any audit field. Longest first so overlapping values are fully replaced.
 */
function sensitiveValues(call: ToolCallRequest): Sensitive[] {
  const out: Sensitive[] = [];
  for (const arg of Object.values(call.args)) {
    const { value, label } = arg as Labeled<unknown>;
    if (confidentialityRank(label.confidentiality) < confidentialityRank("CONFIDENTIAL")) continue;
    if (typeof value !== "string" && typeof value !== "number") continue;
    const text = String(value);
    if (text.length === 0) continue;
    out.push({ text, level: label.confidentiality });
    const normalized = normalizeSandboxPath(text);
    if (normalized && normalized !== text) out.push({ text: normalized, level: label.confidentiality });
  }
  return out.sort((a, b) => b.text.length - a.text.length);
}

const escapeRegExp = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

/** Recursively replaces sensitive values (case-insensitively) in every string of an audit field. */
function scrub<T>(v: T, sensitive: readonly Sensitive[]): T {
  if (sensitive.length === 0) return v;
  if (typeof v === "string") {
    let s: string = v;
    for (const { text, level } of sensitive) s = s.replace(new RegExp(escapeRegExp(text), "gi"), `[REDACTED ${level}]`);
    return s as T;
  }
  if (Array.isArray(v)) return v.map((x) => scrub(x, sensitive)) as T;
  if (v && typeof v === "object") {
    return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, scrub(x, sensitive)])) as T;
  }
  return v;
}

/** Detector evidence for the audit log: scores and pattern ids only. Excerpts are never stored (they quote content). */
function auditDetector(d: DetectorResult) {
  return { score: d.score, patterns: d.hits.map((h) => ({ pattern: h.pattern, weight: h.weight })) };
}

function provenanceOf(call: ToolCallRequest): Record<string, Label> {
  return Object.fromEntries(Object.entries(call.args).map(([k, a]) => [k, (a as Labeled<unknown>).label]));
}

export function startRun(deps: GatewayDeps, spec: RunSpec): StartedRun {
  const clock = deps.clock ?? Date.now;
  const { config, stores } = deps;
  if (!has(config.users, spec.userId)) throw new Error(`Unknown user ${spec.userId}`);
  if (!has(config.profiles, spec.agentId)) throw new Error(`Unknown agent ${spec.agentId}`);
  const params = spec.task.params ?? {};
  for (const [k, v] of Object.entries(params)) {
    if (!PARAM_NAME.test(k) || typeof v !== "string") throw new Error(`Invalid task parameter ${k}`);
  }

  const run: RunRecord = Object.freeze({
    id: `run-${randomUUID()}`,
    scenarioId: spec.scenarioId,
    shieldMode: config.mode,
    policyId: config.policy?.policyVersion ?? "none",
    userId: spec.userId,
    agentId: spec.agentId,
  });
  const sandbox = createRunSandbox(run.id, deps.sandbox);
  stores.audit.createRun(run, clock());
  stores.audit.append(
    { runId: run.id, kind: "run_started", userId: run.userId, agentId: run.agentId, shieldMode: run.shieldMode, policyId: run.policyId, detail: { scenarioId: run.scenarioId, task: spec.task.text, params, policyError: config.policyError } },
    clock(),
  );
  return { run, sandbox, gateway: createGateway(deps, run, sandbox, spec) };
}

function createGateway(deps: GatewayDeps, run: RunRecord, sandbox: RunSandbox, spec: RunSpec): ToolGateway {
  const clock = deps.clock ?? Date.now;
  const { config, stores } = deps;
  const user = config.users[run.userId]!;

  // Ticket issuer stays private to this gateway; the executor only gets the redeemer.
  const { issuer, redeemer } = createTicketAuthority({ clock });
  const executor = createToolExecutor(redeemer);

  // Gateway-owned value store and taint state.
  const values = new Map<string, Labeled<unknown>>();
  values.set("task.text", fromUser(spec.task.text, "user:task"));
  for (const [k, v] of Object.entries(spec.task.params ?? {})) values.set(`task.${k}`, fromUser(v, "user:task"));
  values.set("user.email", fromUser(user.email, "user:profile"));
  let contextLabel: Label = makeLabel("TRUSTED", "INTERNAL", ["user:task"]);
  const untrustedTexts: string[] = [];
  const pending = new Map<string, ToolCallRequest>(); // approvalId -> the exact trusted call awaiting approval
  let outputs = 0;
  let halted: string | null = null;

  const identity = { runId: run.id, userId: run.userId, agentId: run.agentId, shieldMode: run.shieldMode, policyId: run.policyId };

  function halt(reason: string): GatewayResult {
    halted = reason;
    try {
      stores.audit.append({ ...identity, kind: "run_halted", detail: { reason } }, clock());
    } catch {
      /* audit unavailable; the in-memory halt still blocks further actions */
    }
    try {
      stores.audit.setRunStatus(run.id, "audit_failure", clock());
    } catch {
      /* ignore */
    }
    return { status: "halted", reason };
  }

  /** Write an audit row or halt. Returns null if the write failed (caller must stop). */
  function write(e: Omit<AuditEventInput, keyof typeof identity>): AuditEvent | null {
    try {
      return stores.audit.append({ ...identity, ...e }, clock());
    } catch {
      return null;
    }
  }

  function pepEnv(approval?: ApprovalEvidence): PepEnv {
    return {
      policy: config.policy,
      tools: config.tools,
      profiles: config.profiles,
      users: config.users,
      now: clock(),
      untrustedContent: untrustedTexts,
      ...(approval ? { approval } : {}),
    };
  }

  // Tool and argument NAMES are agent-controlled and unlabelled, so they could smuggle data read earlier into the audit
  // log. Only names that exist in the tool manifests are recorded verbatim; anything else is replaced by a placeholder.
  const auditTool = (tool: string) => (has(config.tools, tool) ? tool : "[unknown tool]");

  function auditNames(call: ToolCallRequest): { rename: (k: string) => string; sensitive: Sensitive[] } {
    const manifest = has(config.tools, call.tool) ? config.tools[call.tool] : undefined;
    const map = new Map<string, string>();
    for (const name of Object.keys(call.args)) {
      if (!manifest || !has(manifest.args, name)) map.set(name, `[unexpected argument ${map.size + 1}]`);
    }
    const sensitive: Sensitive[] = [...map.keys()].map((name) => ({ text: `"${name}"`, level: "UNVERIFIED NAME" }));
    if (!manifest) sensitive.push({ text: `"${call.tool}"`, level: "UNVERIFIED NAME" });
    return { rename: (k) => map.get(k) ?? k, sensitive };
  }

  const renameKeys = <T>(o: Record<string, T>, rename: (k: string) => string) =>
    Object.fromEntries(Object.entries(o).map(([k, v]) => [rename(k), v]));

  function decisionEvent(kind: "decision" | "re_decision", call: ToolCallRequest, d: Decision, approvalId?: string) {
    const names = auditNames(call);
    return {
      kind,
      tool: auditTool(call.tool),
      args: renameKeys(auditArgs(call), names.rename),
      provenance: renameKeys(provenanceOf(call), names.rename),
      context: call.contextLabel,
      decision: d.decision,
      ruleId: d.ruleId,
      reasons: scrub([...d.reasons], [...sensitiveValues(call), ...names.sensitive].sort((a, b) => b.text.length - a.text.length)),
      risk: d.risk,
      detector: auditDetector(d.detector),
      callHash: d.callHash,
      approvalId: approvalId ?? d.approvalId,
    } as const;
  }

  /** Build the call from trusted run state. Agent input contributes only tool name, arg names and plain values. */
  function buildCall(raw: unknown): { ok: true; call: ToolCallRequest } | { ok: false; reason: string } {
    const parsed = requestSchema.safeParse(raw);
    if (!parsed.success) return { ok: false, reason: "Malformed agent request (only {tool, args:{name:{ref}|{value}}} is accepted)" };
    const args: Record<string, Labeled<unknown>> = {};
    for (const [name, arg] of Object.entries(parsed.data.args)) {
      if ("ref" in arg) {
        const v = values.get(arg.ref);
        if (!v) return { ok: false, reason: `Unknown value reference for argument "${name}"` }; // ref text not echoed
        args[name] = v;
      } else {
        // New data from the agent: provenance is the whole run context (cannot be upgraded by the agent).
        args[name] = generated([contextLabel], arg.value);
      }
    }
    return { ok: true, call: { runId: run.id, agentId: run.agentId, userId: run.userId, tool: parsed.data.tool, args, contextLabel } };
  }

  function execute(call: ToolCallRequest, decision: Decision): GatewayResult {
    let ticket;
    try {
      ticket = issuer.issue(decision, call);
    } catch (e) {
      const reason = `F0: execution ticket refused (${(e as Error).message})`;
      if (!write({ kind: "outcome", tool: call.tool, callHash: decision.callHash, outcome: "blocked", detail: { reason } })) {
        return halt("Audit write failed for a refused ticket");
      }
      return deniedF0(call.tool, decision, reason);
    }
    const result = executor.execute(call, ticket, sandbox);
    const outcome = write({
      kind: "outcome",
      tool: call.tool,
      callHash: decision.callHash,
      outcome: result.ok ? "executed" : "failed",
      detail: result.ok
        ? { outputLabel: result.output.label }
        : scrub({ code: result.code, message: result.message }, sensitiveValues(call)),
    });
    if (!outcome) {
      return halt(
        result.ok
          ? `Outcome audit write failed after ${call.tool} executed; run halted (the sandbox action happened but is unlogged)`
          : `Outcome audit write failed after ${call.tool} failed; run halted`,
      );
    }
    if (!result.ok) return { status: "tool_error", tool: call.tool, code: result.code, message: result.message, decision: view(decision) };

    // Taint tracking: everything the tool returned joins the run context (grow-only).
    contextLabel = extendContext(contextLabel, result.output.label);
    const ref = `out-${++outputs}`;
    values.set(ref, result.output);
    const agentValue = plain(result.output.value);
    if (result.output.label.integrity === "UNTRUSTED") {
      untrustedTexts.push(JSON.stringify(agentValue).slice(0, 20_000));
      if (untrustedTexts.length > MAX_UNTRUSTED_TEXTS) untrustedTexts.shift();
    }
    return { status: "ok", tool: call.tool, ref, value: agentValue, decision: view(decision) };
  }

  /** Any unexpected exception (e.g. database read failure) halts the run: fail closed, never half-execute. */
  function contained(op: string, fn: () => GatewayResult): GatewayResult {
    if (halted) return { status: "halted", reason: halted };
    try {
      return fn();
    } catch {
      return halt(`Unexpected gateway error during ${op}; run halted`);
    }
  }

  function requestUnchecked(raw: unknown): GatewayResult {
      const built = buildCall(raw);
      if (!built.ok) {
        if (!write({ kind: "request_rejected", detail: { reason: built.reason } })) return halt("Audit write failed for a rejected request");
        return { status: "rejected", reason: built.reason };
      }
      const call = built.call;
      const decision = evaluate(call, pepEnv());

      // Safeguard 2: the decision is recorded before anything else happens.
      const decided = write(decisionEvent("decision", call, decision));
      if (!decided) return halt(`Decision audit write failed for ${auditTool(call.tool)}; nothing was executed`);

      if (decision.decision === "DENY") return { status: "denied", tool: call.tool, decision: view(decision) };

      if (decision.decision === "REQUIRE_APPROVAL") {
        if (!config.policy || !decision.callHash) return { status: "denied", tool: call.tool, decision: view(decision) };
        const expiresAt = clock() + config.policy.approval.ttlSeconds * 1000;
        try {
          const approval = stores.transaction(() => {
            const a = stores.approvals.create(
              { runId: run.id, auditEventId: decided.id, tool: call.tool, callHash: decision.callHash!, requesterId: run.agentId, expiresAt },
              clock(),
            );
            stores.audit.append({ ...identity, kind: "approval_requested", tool: call.tool, callHash: decision.callHash, approvalId: a.id, risk: decision.risk }, clock());
            stores.audit.setRunStatus(run.id, "awaiting_approval", clock());
            return a;
          });
          pending.set(approval.id, call);
          return { status: "approval_required", tool: call.tool, approvalId: approval.id, expiresAt, decision: view(decision) };
        } catch {
          return halt(`Could not record approval request for ${call.tool}; nothing was executed`);
        }
      }

      return execute(call, decision);
  }

  function deniedF0(tool: string, decision: Decision, reason: string): GatewayResult {
    return { status: "denied", tool, decision: { ...view(decision), decision: "DENY", ruleId: "F0", matchedRules: ["F0"], reasons: [reason] } };
  }

  function resumeUnchecked(approvalId: unknown): GatewayResult {
      // Ids are caller-supplied: only the exact server-generated format (`appr-<uuid v4>`, 41 chars) is ever persisted.
      // Anything else is audited with a fixed reason and no copy of the input.
      if (typeof approvalId !== "string" || approvalId.length !== APPROVAL_ID_LENGTH || !APPROVAL_ID.test(approvalId)) {
        const reason = "Malformed approval id";
        if (!write({ kind: "request_rejected", detail: { reason } })) return halt("Audit write failed for a rejected resume");
        return { status: "rejected", reason };
      }
      const stored = pending.get(approvalId);
      if (!stored) {
        // Replays of a used approval (and unknown ids) are refused and audited; nothing is re-evaluated or executed.
        const reason = "No pending call for this approval in this run";
        if (!write({ kind: "request_rejected", approvalId, detail: { reason } })) return halt("Audit write failed for a rejected resume");
        return { status: "rejected", reason };
      }
      const record = stores.approvals.get(approvalId);
      if (!record || record.runId !== run.id) {
        // Store inconsistency (row missing or bound to another run): drop the held call so it can never be resumed,
        // audit with a fixed reason (id is already format-validated), execute nothing.
        pending.delete(approvalId);
        const reason = "Approval does not belong to this run";
        if (!write({ kind: "request_rejected", approvalId, detail: { reason } })) return halt("Audit write failed for a rejected resume");
        return { status: "rejected", reason };
      }
      const expired = clock() >= record.expiresAt;
      if (record.status === "pending" && !expired) return { status: "approval_pending", approvalId };

      // Re-evaluate the exact stored call (same tool, labelled args, identities => same call hash) with the CURRENT
      // run context joined in. The context is not part of the hash and can only make the decision stricter.
      const call: ToolCallRequest = { ...stored, contextLabel: joinLabels([stored.contextLabel, contextLabel]) };

      if (record.status === "pending" && expired) {
        pending.delete(approvalId);
        const reason = "F0: approval expired before an operator decided";
        if (!write({ kind: "re_decision", tool: call.tool, decision: "DENY", ruleId: "F0", reasons: [reason], callHash: record.callHash, approvalId })) {
          return halt("Audit write failed for an expired approval");
        }
        return { status: "denied", tool: call.tool, decision: { decision: "DENY", ruleId: "F0", matchedRules: ["F0"], reasons: [reason], risk: 100, policyVersion: run.policyId } };
      }

      // Re-evaluate through the PEP with the approval as evidence. DENY rules run first.
      const evidence: ApprovalEvidence = {
        id: record.id,
        status: record.status,
        callHash: record.callHash,
        requesterId: record.requesterId,
        approverId: record.approverId,
        expiresAt: record.expiresAt,
        used: record.used,
      };
      const decision = evaluate(call, pepEnv(evidence));
      pending.delete(approvalId);
      try {
        stores.audit.setRunStatus(run.id, "running", clock());
      } catch {
        /* status is informational; audit rows below are the source of truth */
      }

      if (decision.decision === "ALLOW" && decision.ruleId.endsWith("+APPROVED") && decision.callHash) {
        let stage = "audit" as "audit" | "consume" | "commit"; // assigned inside the transaction callback
        try {
          stores.transaction(() => {
            stores.audit.append({ ...identity, ...decisionEvent("re_decision", call, decision, approvalId) }, clock());
            stage = "consume";
            if (!stores.approvals.consume(approvalId, decision.callHash!, clock())) throw new Error("not consumed");
            stage = "commit";
          });
        } catch {
          // The transaction was rolled back: the approval is unconsumed and nothing has executed.
          if (stage !== "consume") {
            return halt("Audit write failed while recording the approved re-decision; approval not consumed, nothing executed");
          }
          const reason = "F0: approval could not be consumed (already used, expired or bound to a different call)";
          if (!write({ kind: "re_decision", tool: call.tool, decision: "DENY", ruleId: "F0", reasons: [reason], callHash: decision.callHash, approvalId })) {
            return halt("Audit write failed for a rejected approval");
          }
          return deniedF0(call.tool, decision, reason);
        }
        return execute(call, decision);
      }

      if (!write(decisionEvent("re_decision", call, decision, approvalId))) return halt("Audit write failed for re-evaluation");
      return { status: "denied", tool: call.tool, decision: view(decision) };
  }

  return Object.freeze({
    runId: run.id,

    request(raw: unknown): GatewayResult {
      return contained("request", () => requestUnchecked(raw));
    },

    resume(approvalId: unknown): GatewayResult {
      return contained("resume", () => resumeUnchecked(approvalId));
    },

    refs() {
      return [...values.entries()].map(([ref, v]) => ({ ref, value: plain(v.value) }));
    },

    state() {
      return { halted, contextLabel };
    },
  });
}
