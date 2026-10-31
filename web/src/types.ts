// Mirrors of the server's browser-facing projections (server/src/api/views.ts, suite.ts, runs.ts). Read-only data.

export type Mode = "on" | "off";

export interface Label {
  integrity: "TRUSTED" | "UNTRUSTED" | "UNKNOWN";
  confidentiality: "PUBLIC" | "INTERNAL" | "CONFIDENTIAL" | "SECRET" | "UNKNOWN";
  sources: string[];
}
export interface Argument extends Label {
  name: string;
}

export interface Expectation {
  legitimateCompleted: boolean | null;
  attackSucceeded: boolean | null;
}

export interface Scenario {
  id: string;
  title: string;
  category: string;
  description: string;
  goal: string;
  userId: string;
  agentId: string;
  expected: { on: Expectation; off: Expectation };
  expectationNote: string | null;
}

export interface Step {
  step: number;
  call: "request" | "resume";
  origin: "task" | "injected";
  source: string | null;
  tool: string;
  status: string;
  ruleId: string | null;
}

export interface Decision {
  seq: number;
  kind: "decision" | "re_decision";
  tool: string;
  decision: string | null;
  ruleId: string | null;
  risk: number | null;
  reasons: string[];
  arguments: Argument[];
  context: Label | null;
  approvalId: string | null;
}

export interface AuditEvent {
  seq: number;
  ts: string;
  kind: string;
  tool: string | null;
  decision: string | null;
  ruleId: string | null;
  outcome: string | null;
  approvalId: string | null;
}

export interface ApprovalHistory {
  approvalId: string;
  tool: string;
  actor: "scripted" | "human";
  operator: string;
  action: "approve" | "reject" | "timeout";
  rationale: string | null;
  reDecision: { decision: string | null; ruleId: string | null } | null;
  executed: boolean;
}

export interface Verdict {
  applicable: boolean;
  result: boolean | null;
  check: string;
}

export interface Run {
  runId: string;
  scenario: { id: string; title: string; category: string; description: string; goal: string; userId: string; agentId: string };
  mode: Mode;
  policyId: string;
  state: string;
  haltReason: string | null;
  operatorNote: string;
  steps: Step[];
  decisions: Decision[];
  approvals: ApprovalHistory[];
  audit: AuditEvent[];
  outbox: { id: string; recipient: "requesting_user" | "external"; bodyChars: number; generatedSummary: boolean }[];
  protectedFiles: { path: string; present: boolean }[];
  legitimate: Verdict;
  attack: Verdict;
  expected: Expectation;
  expectationsMet: boolean;
  expectationNote: string | null;
}

export interface PendingApproval {
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
  arguments: Argument[];
  context: Label | null;
  recipient: "requesting_user" | "external" | null;
  outgoing: OutgoingContent | null;
}

export interface RunSummary {
  runId: string;
  scenarioId: string;
  kind: "scenario" | "lab" | "email";
  title: string;
  mode: Mode;
  state: string;
  createdAt: number;
  finishedAt: number | null;
  pendingApprovalId: string | null;
}

export interface SuiteSide {
  runId: string;
  state: string;
  legitimate: Verdict;
  attack: Verdict;
  expectationsMet: boolean;
  denied: { tool: string; ruleId: string | null }[];
  approvals: { tool: string; action: string; result: string | null; executed: boolean }[];
  outbox: { total: number; external: number };
  protectedFiles: { path: string; present: boolean }[];
}

export interface SuiteResult {
  note: string;
  generatedAt: number;
  scenarios: { id: string; title: string; category: string; off: SuiteSide; on: SuiteSide }[];
  totals: { runs: number; expectationsMet: number; attacksSucceededOff: number; attacksSucceededOn: number };
}

// ---- inspector, labs, overview, audit explorer ----------------------------------------------------------------------

export interface InspectorInstruction {
  evidence: string;
  signals: string[];
  recognized: { tool: string; target: string; category: string }[];
  unsupported: { tool: string; reason: string }[];
}

export interface InspectorSource {
  type: "web" | "document" | "email";
  label: string;
  title: string;
  from: string | null;
  preview: string;
  previewTruncated: boolean;
  instructions: InspectorInstruction[];
  assessment: SecurityAssessment;
  enforcement: Enforcement | null;
}

export interface OutgoingContent {
  analysed: boolean;
  level: ThreatLevel;
  categories: string[];
  note: string;
}

export interface Enforcement {
  mode: Mode;
  requested: number;
  executed: { tool: string; ruleId: string | null }[];
  denied: { tool: string; ruleId: string | null }[];
  pending: { tool: string; ruleId: string | null }[];
  statement: string;
}

export type ThreatLevel = "LOW" | "MEDIUM" | "HIGH" | "UNKNOWN";

export interface UrlFinding {
  url: string;
  hostname: string | null;
  unicodeHostname: string | null;
  registrableDomain: string | null;
  risk: ThreatLevel;
  score: number | null;
  confidence: string;
  summary: string;
  reputation: string;
  knownOfficialDomain: boolean;
  indicators: { id: string; severity: string; reason: string }[];
}

export interface SecurityAlert {
  level: "MEDIUM" | "HIGH";
  detected: string;
  origin: string;
  why: string[];
  attemptedActions: string[];
  potentialImpact: string;
  contentHandling: string;
}

export interface SecurityAssessment {
  sourceTrust: "TRUSTED" | "UNTRUSTED" | "UNKNOWN";
  instructionThreat: {
    level: ThreatLevel;
    score: number | null;
    confidence: string;
    summary: string;
    uncertainty: string | null;
    counts: { information: number; instruction: number; suspicious: number };
    sentences: { evidence: string; role: string; level: ThreatLevel; decoded: boolean; conflictsWithObjective: boolean; findings: { category: string; severity: string; reason: string }[] }[];
  };
  urlRisk: ThreatLevel | null;
  urls: UrlFinding[];
  alert: SecurityAlert | null;
}

export interface RunContent {
  runId: string;
  kind: "scenario" | "lab" | "email";
  task: string;
  plan: string[];
  sources: InspectorSource[];
  outgoing: (OutgoingContent & { seq: number; decision: string | null; ruleId: string | null; recipient: "requesting_user" | "external" | null })[];
}

export interface LabPlan {
  steps: string[];
  sendsSummary: boolean;
}

export interface ParsedEmail {
  from: string;
  to: string;
  subject: string;
  body: string;
  bodyFormat: "text" | "html";
  notes: string[];
}

export interface EmailSample {
  id: "vendor-legit" | "vendor-injection" | "docs-deletion";
  label: string;
  description: string;
  email: ParsedEmail;
}

export interface Overview {
  runs: number;
  live: number;
  waiting: number;
  decisions: { allow: number; deny: number; approval: number };
  attacksBlocked: number;
  attacksSucceeded: number;
}

export interface AuditExplorerEvent {
  ts: string;
  runId: string;
  scenarioId: string;
  mode: Mode;
  seq: number;
  kind: string;
  tool: string | null;
  decision: string | null;
  ruleId: string | null;
  outcome: string | null;
  reason: string | null;
  threat: { instruction: ThreatLevel | null; url: ThreatLevel | null; alerts: number };
}

export interface SessionInfo {
  operator: { id: string; displayName: string };
  csrfToken: string;
  expiresAt: number;
}
