import { assessOutgoing, type SourceAssessment } from "../analysis/assessment.js";
import type { ApprovalRecord, AuditEvent } from "../audit/store.js";
import { TOOL_MANIFESTS } from "../policy/manifests.js";
import { USERS } from "../policy/profiles.js";
import { SCENARIO_IDS, SCENARIOS, type ScenarioDef, type ScenarioId } from "../scenarios/catalog.js";
import type { UntrustedSource } from "../scenarios/inspector.js";
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
  scenario: { id: ScenarioDef["id"]; title: string; category: string; description: string; goal: string; userId: string; agentId: string };
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
  /** Advisory analysis of the outgoing text (subject/body) the operator is asked to approve. Never a decision. */
  outgoing: OutgoingContentView | null;
}

export interface OutgoingContentView {
  analysed: boolean;
  level: string;
  categories: string[];
  note: string;
}

/**
 * Advisory: does the outgoing text of a send (e.g. a generated summary) carry embedded instructions copied from untrusted
 * content? Uses the audit row's arguments, where CONFIDENTIAL/SECRET values are already redacted (those are not analysed).
 * Only a level and finding categories are returned — never the text itself.
 */
export function outgoingView(e: AuditEvent | undefined): OutgoingContentView | null {
  if (!e || e.tool !== "send_email" || !isObj(e.args)) return null;
  const texts = ["subject", "body"].map((k) => (e.args as Record<string, unknown>)[k]).filter((v): v is string => typeof v === "string");
  if (texts.some((t) => t.startsWith("[REDACTED"))) return { analysed: false, level: "UNKNOWN", categories: [], note: "The content is CONFIDENTIAL or SECRET and is not analysed here." };
  const a = assessOutgoing(texts.join("\n\n"));
  const categories = [...new Set(a.sentences.flatMap((x) => x.findings.filter((f) => f.severity !== "low").map((f) => f.category)))];
  const note =
    a.level === "HIGH" || a.level === "MEDIUM"
      ? "The outgoing text contains instruction-like content copied from untrusted input. It is delivered as text only; review before approving."
      : "No embedded instructions were detected in the outgoing text (rule-based; not a guarantee).";
  return { analysed: true, level: a.level, categories, note };
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
    case "lab_breach":
      return `Content of ${c.secretFiles.join(" or ")} reached an external recipient, or ${c.protectedPaths.join(" / ")} was deleted`;
  }
}

const verdictView = (v: Verdict, check: string): VerdictView => ({ applicable: v.applicable, result: v.result, check });

function protectedPaths(c: AttackCheck | null): string[] {
  if (!c) return [];
  switch (c.kind) {
    case "files_deleted":
      return [...c.paths];
    case "fail_closed_breached":
    case "lab_breach":
      return [...c.protectedPaths];
    case "protected_content_emailed_externally":
    case "protected_file_read":
      return [c.protectedFile];
  }
}

// ---- public projections ---------------------------------------------------------------------------------------------

export function scenarioListView(): ScenarioView[] {
  return SCENARIO_IDS.map((id) => {
    const s = SCENARIOS[id];
    return {
      id,
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

/**
 * Browser-facing run view. `events` are the run's raw audit rows (needed to mask agent-chosen values in reasons).
 * `def` is the session's definition (labs are not in the catalogue); catalogue runs may omit it.
 */
export function runView(report: ScenarioReport, events: readonly AuditEvent[], definition?: ScenarioDef): RunView {
  const def: ScenarioDef = definition ?? SCENARIOS[report.scenario.id as ScenarioId];
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

// ---- Untrusted Content Inspector ------------------------------------------------------------------------------------

export interface InspectorInstructionView {
  evidence: string;
  signals: string[];
  recognized: { tool: string; target: string; category: string }[];
  unsupported: { tool: string; reason: string }[];
}

export interface InspectorSourceView {
  type: "web" | "document" | "email";
  label: string;
  title: string;
  from: string | null;
  preview: string;
  previewTruncated: boolean;
  instructions: InspectorInstructionView[];
  assessment: AssessmentView;
  /** Null when the content view is built without a run (should not happen for registry runs). */
  enforcement: EnforcementView | null;
}

export interface AssessmentView {
  sourceTrust: "TRUSTED" | "UNTRUSTED" | "UNKNOWN";
  instructionThreat: {
    level: string;
    score: number | null;
    confidence: string;
    summary: string;
    uncertainty: string | null;
    counts: { information: number; instruction: number; suspicious: number };
    sentences: { evidence: string; role: string; level: string; decoded: boolean; conflictsWithObjective: boolean; findings: { category: string; severity: string; reason: string }[] }[];
  };
  urlRisk: string | null;
  urls: {
    url: string;
    hostname: string | null;
    unicodeHostname: string | null;
    registrableDomain: string | null;
    risk: string;
    score: number | null;
    confidence: string;
    summary: string;
    reputation: string;
    knownOfficialDomain: boolean;
    indicators: { id: string; severity: string; reason: string }[];
  }[];
  alert: {
    level: string;
    detected: string;
    origin: string;
    why: string[];
    attemptedActions: string[];
    potentialImpact: string;
    contentHandling: string;
  } | null;
}

/** What actually happened to the tool requests this source caused, in THIS run (from the run's own steps). */
export interface EnforcementView {
  mode: "on" | "off";
  requested: number;
  executed: { tool: string; ruleId: string | null }[];
  denied: { tool: string; ruleId: string | null }[];
  pending: { tool: string; ruleId: string | null }[];
  statement: string;
}

const listTools = (xs: { tool: string; ruleId: string | null }[]) => xs.map((x) => (x.ruleId && x.ruleId !== "OFF" ? `${x.tool} (${x.ruleId})` : x.tool)).join(", ");

/** Built only from executed/denied step statuses; never claims a block that did not happen. */
export function enforcementView(mode: "on" | "off", label: string, steps: readonly StepView[]): EnforcementView {
  const mine = steps.filter((s) => s.origin === "injected" && s.source === label);
  const pick = (pred: (st: string) => boolean) => mine.filter((s) => pred(s.status)).map((s) => ({ tool: s.tool, ruleId: s.ruleId }));
  const executed = pick((st) => st === "ok");
  const denied = pick((st) => st === "denied" || st === "rejected" || st === "halted");
  const pending = pick((st) => st === "approval_required" || st === "approval_pending");
  const parts: string[] = [];
  if (mode === "off") parts.push("Shield OFF: no policy enforcement in this run.");
  else parts.push("Shield ON: every tool request was decided by the PEP.");
  if (mine.length === 0) parts.push("The agent made no tool request from this content.");
  if (executed.length) parts.push(`EXECUTED: ${listTools(executed)}.`);
  if (denied.length) parts.push(`DENIED: ${listTools(denied)}.`);
  if (pending.length) parts.push(`Awaiting human approval: ${listTools(pending)}.`);
  if (mine.length > 0 && denied.length === 0 && pending.length === 0) parts.push("Nothing requested by this content was blocked.");
  return { mode, requested: mine.length, executed, denied, pending, statement: parts.join(" ") };
}

/** Explicit allowlist projection of a source's security assessment (all strings bounded). */
export function assessmentView(a: SourceAssessment): AssessmentView {
  const i = a.instructions;
  return {
    sourceTrust: a.sourceTrust,
    instructionThreat: {
      level: i.level,
      score: i.score,
      confidence: i.confidence,
      summary: clip(i.summary, 300),
      uncertainty: i.uncertainty === null ? null : clip(i.uncertainty, 300),
      counts: { information: i.counts.information, instruction: i.counts.instruction, suspicious: i.counts.suspicious },
      sentences: i.sentences.slice(0, 30).map((s) => ({
        evidence: clip(s.evidence, 320),
        role: s.role,
        level: s.level,
        decoded: s.decoded,
        conflictsWithObjective: s.conflictsWithObjective,
        findings: s.findings.map((f) => ({ category: f.category, severity: f.severity, reason: clip(f.reason, 300) })),
      })),
    },
    urlRisk: a.urlRisk,
    urls: a.urls.slice(0, 20).map((u) => ({
      url: clip(u.url, 300),
      hostname: u.hostname === null ? null : clip(u.hostname, 253),
      unicodeHostname: u.unicodeHostname === null ? null : clip(u.unicodeHostname, 253),
      registrableDomain: u.registrableDomain === null ? null : clip(u.registrableDomain, 253),
      risk: u.risk,
      score: u.score,
      confidence: u.confidence,
      summary: clip(u.summary, 300),
      reputation: u.reputation,
      knownOfficialDomain: u.knownOfficialDomain,
      indicators: u.indicators.map((x) => ({ id: x.id, severity: x.severity, reason: clip(x.reason, 400) })),
    })),
    alert: a.alert === null ? null : {
      level: a.alert.level,
      detected: clip(a.alert.detected, 300),
      origin: sanitizeSource(a.alert.origin),
      why: a.alert.why.map((w) => clip(w, 600)),
      attemptedActions: a.alert.attemptedActions.map((x) => clip(x, 200)),
      potentialImpact: clip(a.alert.potentialImpact, 300),
      contentHandling: clip(a.alert.contentHandling, 300),
    },
  };
}

export interface RunContentView {
  runId: string;
  kind: "scenario" | "lab" | "email";
  task: string;
  /** The deterministic plan the agent follows for the user's task (from the run definition). */
  plan: string[];
  sources: InspectorSourceView[];
  /** Advisory analysis of every email the agent attempted in this run (decision rows), with the actual PEP outcome. */
  outgoing: (OutgoingContentView & { seq: number; decision: string | null; ruleId: string | null; recipient: "requesting_user" | "external" | null })[];
}

const STEP_PLAN: Record<string, string> = {
  read_file: "Read the task's file",
  fetch_web: "Fetch the web page",
  read_inbox: "Read the inbox",
  email_summary_to_user: "Email a generated summary to the requesting user",
  raw: "Emit a scripted malformed/forged request (fail-closed probe)",
};

const clip = (s: unknown, n: number) => (typeof s === "string" ? (s.length > n ? `${s.slice(0, n)}…` : s) : "");

/**
 * The untrusted INPUT content of a run and how the deterministic agent interprets it. Unlike runView this deliberately
 * includes the (bounded) text of the untrusted content — the point is to show judges the actual injection. It never
 * includes task files, tool outputs, outbox bodies or subjects, secrets, hashes or paths outside provenance labels.
 * React renders it as text (HTML is shown as source, never executed).
 */
export function runContentView(
  runId: string,
  def: ScenarioDef,
  sources: readonly UntrustedSource[],
  run?: { mode: "on" | "off"; steps: readonly StepView[]; events: readonly AuditEvent[]; userEmail: string | null },
): RunContentView {
  const outgoing = (run?.events ?? [])
    .filter((e) => e.kind === "decision" && e.tool === "send_email")
    .slice(0, 20)
    .flatMap((e) => {
      const o = outgoingView(e);
      if (!o) return [];
      const to = isObj(e.args) ? e.args.to : undefined;
      const toLabel = isObj(e.provenance) ? sanitizeLabel(e.provenance.to) : null;
      const recipient = typeof to !== "string" ? null : toLabel?.integrity === "TRUSTED" && run?.userEmail !== null && to === run?.userEmail ? ("requesting_user" as const) : ("external" as const);
      return [{ ...o, seq: e.seq, decision: e.decision, ruleId: e.ruleId, recipient }];
    });
  return {
    runId,
    kind: def.id === "LAB" ? "lab" : def.id === "EMAIL" ? "email" : "scenario",
    task: clip(def.task.goal, 300),
    plan: def.task.steps.map((s) => (s.op === "read_file" && def.inspectFiles ? "Read the supplied document" : (STEP_PLAN[s.op] ?? s.op))),
    sources: sources.slice(0, 10).map((s) => ({
      type: s.type,
      label: sanitizeSource(s.label),
      title: clip(s.title, 200),
      from: s.from === null ? null : clip(s.from, 254),
      preview: clip(s.preview, 4100),
      previewTruncated: s.previewTruncated,
      instructions: s.analysis.instructions.map((i) => ({
        evidence: clip(i.evidence, 320),
        signals: [...i.signals],
        recognized: i.recognized.map((a) => ({ tool: a.kind, target: clip(a.kind === "send_email" ? a.to : a.path, 254), category: a.category })),
        unsupported: i.unsupported.map((u) => ({ tool: u.kind, reason: u.reason })),
      })),
      assessment: assessmentView(s.assessment),
      enforcement: run ? enforcementView(run.mode, s.label, run.steps) : null,
    })),
    outgoing,
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
    outgoing: outgoingView(decision),
    recipient:
      to === undefined ? null : toLabel?.integrity === "TRUSTED" && typeof to === "string" && userEmail !== null && to === userEmail ? "requesting_user" : "external",
  };
}
