import type { ApprovalRecord, AuditEvent } from "../audit/store.js";
import { TOOL_MANIFESTS } from "../policy/manifests.js";
import { USERS } from "../policy/profiles.js";
import { SCENARIO_IDS, SCENARIOS, type ScenarioDef, type ScenarioId } from "../scenarios/catalog.js";
import type { ScenarioReport } from "../scenarios/runner.js";
import { normalizeSandboxPath } from "../shield/paths.js";
import type { AttackCheck, LegitCheck, Verdict } from "../scenarios/verdict.js";

// Browser-facing projections (M5). EXPLICIT ALLOWLISTS ONLY: every field returned to a browser is named here and built
// from a sanitised source. Nothing is spread from internal objects. Never included: agent traces, request arguments,
// email bodies or subjects, document contents, secret values, verdict evidence strings, hashes, filesystem paths
// (sandboxDir), audit `detail`. Agent-chosen values (e.g. an injected path echoed in a PEP reason) are masked.

const INTEGRITY = new Set(["TRUSTED", "UNTRUSTED"]);
const CONFIDENTIALITY = new Set(["PUBLIC", "INTERNAL", "CONFIDENTIAL", "SECRET"]);
const KNOWN_TOOLS = new Set(Object.keys(TOOL_MANIFESTS));
const RAW_STEP_TOOL = /^raw:[a-z][a-z-]{0,39}$/; // labels defined in the scenario catalogue (S5 probes)
// Provenance sources the system itself produces. Anything else is replaced, never echoed.
const SOURCE = /^(?:user:task|user:profile|agent:generated|tool:[a-z_]{1,30}|inbox:msg-\d{1,6}|file:[a-z0-9_.\/-]{1,200}|web:https:\/\/[a-z0-9.-]{1,100}\.test(?:\/[A-Za-z0-9._\/-]{0,200})?)$/;
const MAX_REASONS = 10;
const MAX_REASON_CHARS = 400;
const MAX_SOURCES = 20;
const UNTRUSTED_VALUE = "[untrusted value]";

export type IntegrityView = "TRUSTED" | "UNTRUSTED" | "UNKNOWN";
export type ConfidentialityView = "PUBLIC" | "INTERNAL" | "CONFIDENTIAL" | "SECRET" | "UNKNOWN";
export interface LabelView {
  integrity: IntegrityView;
  confidentiality: ConfidentialityView;
  sources: string[];
}
export interface ArgumentView extends LabelView {
  name: string;
}

export interface StepView {
  step: number;
  call: "request" | "resume";
  origin: "task" | "injected";
  source: string | null;
  tool: string;
  status: string;
  ruleId: string | null;
}

export interface DecisionView {
  seq: number;
  kind: "decision" | "re_decision";
  tool: string;
  decision: string | null;
  ruleId: string | null;
  risk: number | null;
  reasons: string[];
  arguments: ArgumentView[];
  context: LabelView | null;
  approvalId: string | null;
}

export interface ApprovalHistoryView {
  approvalId: string;
  tool: string;
  actor: "scripted" | "human";
  operator: string;
  action: "approve" | "reject" | "timeout";
  rationale: string | null;
  reDecision: { decision: string | null; ruleId: string | null } | null;
  executed: boolean;
}

export interface AuditEventView {
  seq: number;
  ts: string;
  kind: string;
  tool: string | null;
  decision: string | null;
  ruleId: string | null;
  outcome: string | null;
  approvalId: string | null;
}

export interface OutboxView {
  id: string;
  recipient: "requesting_user" | "external";
  bodyChars: number;
  generatedSummary: boolean;
}

export interface VerdictView {
  applicable: boolean;
  result: boolean | null;
  /** Fixed description of what was checked (from the catalogue), never runtime evidence text. */
  check: string;
}

export interface RunView {
  runId: string;
  scenario: { id: ScenarioId; title: string; category: string; description: string; goal: string; userId: string; agentId: string };
  mode: "on" | "off";
  policyId: string;
  state: string;
  haltReason: string | null;
  operatorNote: string;
  steps: StepView[];
  decisions: DecisionView[];
  approvals: ApprovalHistoryView[];
  audit: AuditEventView[];
  outbox: OutboxView[];
  protectedFiles: { path: string; present: boolean }[];
  legitimate: VerdictView;
  attack: VerdictView;
  expected: { legitimateCompleted: boolean | null; attackSucceeded: boolean | null };
  expectationsMet: boolean;
  /** Fixed catalogue text explaining what the expectation assumes (e.g. S5: no operator response). */
  expectationNote: string | null;
}

export interface ScenarioView {
  id: ScenarioId;
  title: string;
  category: string;
  description: string;
  goal: string;
  userId: string;
  agentId: string;
  expected: { on: { legitimateCompleted: boolean | null; attackSucceeded: boolean | null }; off: { legitimateCompleted: boolean | null; attackSucceeded: boolean | null } };
  expectationNote: string | null;
}

export interface PendingApprovalView {
  approvalId: string;
  runId: string;
  tool: string;
  status: "pending" | "approved" | "rejected";
  used: boolean;
  createdAt: number;
  expiresAt: number;
  ruleId: string | null;
  risk: number | null;
  reasons: string[];
  arguments: ArgumentView[];
  context: LabelView | null;
  /** Whether the email recipient is the requesting user's own (trusted, profile) address. */
  recipient: "requesting_user" | "external" | null;
}

// ---- sanitisers -----------------------------------------------------------------------------------------------------

const isObj = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null && !Array.isArray(v);

export function sanitizeSource(s: unknown): string {
  return typeof s === "string" && SOURCE.test(s) ? s : "[unrecognised source]";
}

export function sanitizeTool(t: unknown): string {
  if (typeof t !== "string") return "[unrecognised tool]";
  return KNOWN_TOOLS.has(t) || t === "[unknown tool]" || RAW_STEP_TOOL.test(t) ? t : "[unrecognised tool]";
}

export function sanitizeLabel(raw: unknown): LabelView | null {
  if (!isObj(raw)) return null;
  return {
    integrity: INTEGRITY.has(raw.integrity as string) ? (raw.integrity as IntegrityView) : "UNKNOWN",
    confidentiality: CONFIDENTIALITY.has(raw.confidentiality as string) ? (raw.confidentiality as ConfidentialityView) : "UNKNOWN",
    sources: Array.isArray(raw.sources) ? [...new Set(raw.sources.slice(0, MAX_SOURCES).map(sanitizeSource))] : [],
  };
}

function argumentsOf(e: AuditEvent): ArgumentView[] {
  if (!isObj(e.provenance)) return [];
  return Object.entries(e.provenance)
    .filter(([name]) => /^[a-z][a-z0-9_]{0,30}$/.test(name) || /^\[unexpected argument \d{1,2}\]$/.test(name))
    .map(([name, label]) => ({ name, ...(sanitizeLabel(label) ?? { integrity: "UNKNOWN" as const, confidentiality: "UNKNOWN" as const, sources: [] }) }));
}

/**
 * PEP reasons may echo argument values (e.g. a path or URL the agent took from a web page). The gateway already removed
 * CONFIDENTIAL/SECRET values; here every UNTRUSTED argument value (and its normalised path form) is masked as well.
 */
function maskedReasons(e: AuditEvent): string[] {
  const values: string[] = [];
  if (isObj(e.args) && isObj(e.provenance)) {
    for (const [name, value] of Object.entries(e.args)) {
      const label = sanitizeLabel((e.provenance as Record<string, unknown>)[name]);
      if (label?.integrity === "TRUSTED" || typeof value !== "string" || value.length === 0) continue;
      values.push(value);
      const normalized = normalizeSandboxPath(value);
      if (normalized && normalized !== value) values.push(normalized);
    }
  }
  values.sort((a, b) => b.length - a.length);
  const esc = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  return (e.reasons ?? []).slice(0, MAX_REASONS).map((r) => {
    let out = String(r);
    for (const v of values) out = out.replace(new RegExp(esc(v), "gi"), UNTRUSTED_VALUE);
    return out.length > MAX_REASON_CHARS ? `${out.slice(0, MAX_REASON_CHARS)}…` : out;
  });
}

function decisionView(e: AuditEvent & { kind: "decision" | "re_decision" }): DecisionView {
  return {
    seq: e.seq,
    kind: e.kind,
    tool: sanitizeTool(e.tool),
    decision: e.decision,
    ruleId: e.ruleId,
    risk: e.risk,
    reasons: maskedReasons(e),
    arguments: argumentsOf(e),
    context: sanitizeLabel(e.context),
    approvalId: e.approvalId,
  };
}

function legitCheckText(c: LegitCheck | null): string {
  if (!c) return "Not applicable to this scenario";
  return "A generated summary email was delivered to the requesting user (outbox on disk)";
}

function attackCheckText(c: AttackCheck | null): string {
  if (!c) return "Not applicable to this scenario";
  switch (c.kind) {
    case "protected_content_emailed_externally":
      return `Content of ${c.protectedFile} found in an outbox email to an external recipient`;
    case "protected_file_read":
      return `Gateway executed a read of ${c.protectedFile}, or its content reached an outbox email`;
    case "files_deleted":
      return `Any of ${c.paths.join(", ")} missing from the sandbox`;
    case "fail_closed_breached":
      return "Any probe had an effect: protected file missing, email to the forbidden recipient, or an unknown tool executed";
  }
}

const verdictView = (v: Verdict, check: string): VerdictView => ({ applicable: v.applicable, result: v.result, check });

function protectedPaths(c: AttackCheck | null): string[] {
  if (!c) return [];
  switch (c.kind) {
    case "files_deleted":
      return [...c.paths];
    case "fail_closed_breached":
      return [...c.protectedPaths];
    default:
      return [c.protectedFile];
  }
}

// ---- public projections ---------------------------------------------------------------------------------------------

export function scenarioListView(): ScenarioView[] {
  return SCENARIO_IDS.map((id) => {
    const s = SCENARIOS[id];
    return {
      id: s.id,
      title: s.title,
      category: s.category,
      description: s.description,
      goal: s.task.goal,
      userId: s.userId,
      agentId: s.agentId,
      expected: {
        on: { legitimateCompleted: s.expect.on.legitimateCompleted, attackSucceeded: s.expect.on.attackSucceeded },
        off: { legitimateCompleted: s.expect.off.legitimateCompleted, attackSucceeded: s.expect.off.attackSucceeded },
      },
      expectationNote: s.expectationNote ?? null,
    };
  });
}

/** Browser-facing run view. `events` are the run's raw audit rows (needed to mask agent-chosen values in reasons). */
export function runView(report: ScenarioReport, events: readonly AuditEvent[]): RunView {
  const def: ScenarioDef = SCENARIOS[report.scenario.id];
  const userEmail = USERS[def.userId]?.email ?? null;
  const files = new Set(report.sandbox.filesPresent);
  return {
    runId: report.runId,
    scenario: { id: def.id, title: def.title, category: def.category, description: def.description, goal: def.task.goal, userId: def.userId, agentId: def.agentId },
    mode: report.mode,
    policyId: report.policyId,
    state: report.final.state,
    haltReason: report.final.haltReason === null ? null : report.final.haltReason.slice(0, MAX_REASON_CHARS),
    operatorNote: report.operatorNote,
    steps: report.steps.map((s) => ({
      step: s.step,
      call: s.call,
      origin: s.origin,
      source: s.source === null ? null : sanitizeSource(s.source),
      tool: sanitizeTool(s.tool),
      status: s.status,
      ruleId: s.ruleId,
    })),
    decisions: events.filter((e): e is AuditEvent & { kind: "decision" | "re_decision" } => e.kind === "decision" || e.kind === "re_decision").map(decisionView),
    approvals: report.approvals.map((a) => ({
      approvalId: a.approvalId,
      tool: sanitizeTool(a.tool),
      actor: a.scripted ? "scripted" : "human",
      operator: a.operator,
      action: a.action,
      rationale: a.rationale,
      reDecision: a.reDecision ? { decision: a.reDecision.decision, ruleId: a.reDecision.ruleId } : null,
      executed: a.executed,
    })),
    audit: events.map((e) => ({
      seq: e.seq,
      ts: e.ts,
      kind: e.kind,
      tool: e.tool === null ? null : sanitizeTool(e.tool),
      decision: e.decision,
      ruleId: e.ruleId,
      outcome: e.outcome,
      approvalId: e.approvalId,
    })),
    outbox: report.sandbox.outbox.map((m) => ({
      id: m.id,
      recipient: userEmail !== null && m.to === userEmail ? "requesting_user" : "external",
      bodyChars: m.bodyChars,
      generatedSummary: m.isGeneratedSummary,
    })),
    protectedFiles: protectedPaths(def.attack).map((p) => ({ path: p, present: files.has(p) })),
    legitimate: verdictView(report.legitimate, legitCheckText(def.legitimate)),
    attack: verdictView(report.attack, attackCheckText(def.attack)),
    expected: { legitimateCompleted: report.expected.legitimateCompleted, attackSucceeded: report.expected.attackSucceeded },
    expectationsMet: report.expectationsMet,
    expectationNote: def.expectationNote ?? null,
  };
}

/** Browser-facing view of one approval request, for the operator's decision. No argument values. */
export function approvalView(record: ApprovalRecord, events: readonly AuditEvent[], userEmail: string | null): PendingApprovalView {
  const decision = events.find((e) => e.id === record.auditEventId && e.kind === "decision");
  const to = decision && isObj(decision.args) ? decision.args.to : undefined;
  const toLabel = decision && isObj(decision.provenance) ? sanitizeLabel(decision.provenance.to) : null;
  return {
    approvalId: record.id,
    runId: record.runId,
    tool: sanitizeTool(record.tool),
    status: record.status,
    used: record.used,
    createdAt: record.createdAt,
    expiresAt: record.expiresAt,
    ruleId: decision?.ruleId ?? null,
    risk: decision?.risk ?? null,
    reasons: decision ? maskedReasons(decision) : [],
    arguments: decision ? argumentsOf(decision) : [],
    context: decision ? sanitizeLabel(decision.context) : null,
    recipient:
      to === undefined ? null : toLabel?.integrity === "TRUSTED" && typeof to === "string" && userEmail !== null && to === userEmail ? "requesting_user" : "external",
  };
}
