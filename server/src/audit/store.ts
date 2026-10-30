import { randomUUID } from "node:crypto";
import type { DatabaseSync } from "node:sqlite";

// Persistence for runs, audit events and approvals (node:sqlite).
// audit_events is APPLICATION-LEVEL append-only: this module exposes no update or delete for it. That is not
// OS-level tamper-proofing — anyone with write access to the database file can still alter it.

const SCHEMA = `
CREATE TABLE IF NOT EXISTS runs (
  id TEXT PRIMARY KEY,
  scenario_id TEXT NOT NULL,
  shield_mode TEXT NOT NULL CHECK (shield_mode IN ('on','off')),
  policy_id TEXT NOT NULL,
  user_id TEXT NOT NULL,
  agent_id TEXT NOT NULL,
  status TEXT NOT NULL,
  started_at TEXT NOT NULL,
  ended_at TEXT
);
CREATE TABLE IF NOT EXISTS audit_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  run_id TEXT NOT NULL REFERENCES runs(id),
  seq INTEGER NOT NULL,
  ts TEXT NOT NULL,
  kind TEXT NOT NULL,
  user_id TEXT NOT NULL,
  agent_id TEXT NOT NULL,
  shield_mode TEXT NOT NULL,
  policy_id TEXT,
  tool TEXT,
  args_json TEXT,
  provenance_json TEXT,
  context_json TEXT,
  decision TEXT,
  rule_id TEXT,
  reasons_json TEXT,
  risk INTEGER,
  detector_json TEXT,
  call_hash TEXT,
  approval_id TEXT,
  outcome TEXT,
  detail_json TEXT,
  UNIQUE (run_id, seq)
);
CREATE INDEX IF NOT EXISTS idx_audit_run_seq ON audit_events (run_id, seq);
CREATE TABLE IF NOT EXISTS approvals (
  id TEXT PRIMARY KEY,
  run_id TEXT NOT NULL REFERENCES runs(id),
  audit_event_id INTEGER NOT NULL REFERENCES audit_events(id),
  tool TEXT NOT NULL,
  call_hash TEXT NOT NULL,
  requester_id TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('pending','approved','rejected')),
  approver_id TEXT,
  created_at INTEGER NOT NULL,
  decided_at INTEGER,
  expires_at INTEGER NOT NULL,
  used INTEGER NOT NULL DEFAULT 0,
  consumed_at INTEGER
);
CREATE INDEX IF NOT EXISTS idx_approvals_status ON approvals (status);
`;

export type ShieldMode = "on" | "off";
export type RunStatus = "running" | "awaiting_approval" | "completed" | "halted" | "audit_failure" | "error";
export type AuditKind =
  | "run_started"
  | "request_rejected"
  | "decision"
  | "approval_requested"
  | "approval_decided"
  | "re_decision"
  | "outcome"
  | "run_halted";

export interface RunRecord {
  id: string;
  scenarioId: string;
  shieldMode: ShieldMode;
  policyId: string;
  userId: string;
  agentId: string;
}

export interface AuditEventInput {
  runId: string;
  kind: AuditKind;
  userId: string;
  agentId: string;
  shieldMode: ShieldMode;
  policyId?: string | null;
  tool?: string | null;
  args?: unknown;
  provenance?: unknown;
  context?: unknown;
  decision?: string | null;
  ruleId?: string | null;
  reasons?: readonly string[] | null;
  risk?: number | null;
  detector?: unknown;
  callHash?: string | null;
  approvalId?: string | null;
  outcome?: string | null;
  detail?: unknown;
}

export interface AuditEvent {
  id: number;
  runId: string;
  seq: number;
  ts: string;
  kind: AuditKind;
  userId: string;
  agentId: string;
  shieldMode: ShieldMode;
  policyId: string | null;
  tool: string | null;
  args: unknown;
  provenance: unknown;
  context: unknown;
  decision: string | null;
  ruleId: string | null;
  reasons: string[] | null;
  risk: number | null;
  detector: unknown;
  callHash: string | null;
  approvalId: string | null;
  outcome: string | null;
  detail: unknown;
}

export interface AuditStore {
  createRun(run: RunRecord, now: number): void;
  getRun(runId: string): (RunRecord & { status: RunStatus }) | null;
  setRunStatus(runId: string, status: RunStatus, now: number): void;
  append(event: AuditEventInput, now: number): AuditEvent;
  listEvents(runId: string): AuditEvent[];
}

export interface ApprovalRecord {
  id: string;
  runId: string;
  auditEventId: number;
  tool: string;
  callHash: string;
  requesterId: string;
  status: "pending" | "approved" | "rejected";
  approverId: string | null;
  createdAt: number;
  decidedAt: number | null;
  expiresAt: number;
  used: boolean;
  consumedAt: number | null;
}

export interface ApprovalStore {
  create(input: { runId: string; auditEventId: number; tool: string; callHash: string; requesterId: string; expiresAt: number }, now: number): ApprovalRecord;
  get(id: string): ApprovalRecord | null;
  /** Pending -> approved/rejected. Returns false if the approval was not pending (no change). */
  setDecision(id: string, status: "approved" | "rejected", approverId: string, now: number): boolean;
  /** Atomic single-use consumption. True only if exactly one unused, approved, unexpired, hash-matching row was updated. */
  consume(id: string, callHash: string, now: number): boolean;
  listPending(): ApprovalRecord[];
}

export interface Stores {
  audit: AuditStore;
  approvals: ApprovalStore;
  /** Runs fn inside BEGIN IMMEDIATE ... COMMIT; rolls back and rethrows on error. */
  transaction<T>(fn: () => T): T;
}

const json = (v: unknown) => (v === undefined ? null : JSON.stringify(v));
const parse = (v: unknown) => (typeof v === "string" ? JSON.parse(v) : null);
const iso = (ms: number) => new Date(ms).toISOString();

type Row = Record<string, unknown>;

function toEvent(r: Row): AuditEvent {
  return {
    id: Number(r.id),
    runId: String(r.run_id),
    seq: Number(r.seq),
    ts: String(r.ts),
    kind: r.kind as AuditKind,
    userId: String(r.user_id),
    agentId: String(r.agent_id),
    shieldMode: r.shield_mode as ShieldMode,
    policyId: (r.policy_id as string | null) ?? null,
    tool: (r.tool as string | null) ?? null,
    args: parse(r.args_json),
    provenance: parse(r.provenance_json),
    context: parse(r.context_json),
    decision: (r.decision as string | null) ?? null,
    ruleId: (r.rule_id as string | null) ?? null,
    reasons: parse(r.reasons_json),
    risk: r.risk === null || r.risk === undefined ? null : Number(r.risk),
    detector: parse(r.detector_json),
    callHash: (r.call_hash as string | null) ?? null,
    approvalId: (r.approval_id as string | null) ?? null,
    outcome: (r.outcome as string | null) ?? null,
    detail: parse(r.detail_json),
  };
}

function toApproval(r: Row): ApprovalRecord {
  return {
    id: String(r.id),
    runId: String(r.run_id),
    auditEventId: Number(r.audit_event_id),
    tool: String(r.tool),
    callHash: String(r.call_hash),
    requesterId: String(r.requester_id),
    status: r.status as ApprovalRecord["status"],
    approverId: (r.approver_id as string | null) ?? null,
    createdAt: Number(r.created_at),
    decidedAt: r.decided_at === null ? null : Number(r.decided_at),
    expiresAt: Number(r.expires_at),
    used: Number(r.used) === 1,
    consumedAt: r.consumed_at === null ? null : Number(r.consumed_at),
  };
}

export function createStores(db: DatabaseSync): Stores {
  db.exec(SCHEMA);

  const insertRun = db.prepare(
    "INSERT INTO runs (id, scenario_id, shield_mode, policy_id, user_id, agent_id, status, started_at) VALUES (?, ?, ?, ?, ?, ?, 'running', ?)",
  );
  const selectRun = db.prepare("SELECT * FROM runs WHERE id = ?");
  const updateRunStatus = db.prepare("UPDATE runs SET status = ?, ended_at = ? WHERE id = ?");
  // Sequence allocation and insert are one statement, so they are atomic (SQLite serialises writers; the demo is single
  // process). UNIQUE(run_id, seq) is the backstop: a conflicting writer gets an error, i.e. the audit write fails closed.
  const insertEvent = db.prepare(`INSERT INTO audit_events
    (run_id, seq, ts, kind, user_id, agent_id, shield_mode, policy_id, tool, args_json, provenance_json, context_json,
     decision, rule_id, reasons_json, risk, detector_json, call_hash, approval_id, outcome, detail_json)
    SELECT ?1, COALESCE(MAX(seq), 0) + 1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20
    FROM audit_events WHERE run_id = ?1`);
  const selectEvent = db.prepare("SELECT * FROM audit_events WHERE id = ?");
  const selectEvents = db.prepare("SELECT * FROM audit_events WHERE run_id = ? ORDER BY seq");

  const insertApproval = db.prepare(`INSERT INTO approvals
    (id, run_id, audit_event_id, tool, call_hash, requester_id, status, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, 'pending', ?, ?)`);
  const selectApproval = db.prepare("SELECT * FROM approvals WHERE id = ?");
  const decideApproval = db.prepare(
    "UPDATE approvals SET status = ?, approver_id = ?, decided_at = ? WHERE id = ? AND status = 'pending' AND used = 0",
  );
  const consumeApproval = db.prepare(`UPDATE approvals SET used = 1, consumed_at = ?
    WHERE id = ? AND used = 0 AND status = 'approved' AND expires_at > ? AND call_hash = ?`);
  const selectPending = db.prepare("SELECT * FROM approvals WHERE status = 'pending' AND used = 0 ORDER BY created_at");

  const audit: AuditStore = {
    createRun(run, now) {
      insertRun.run(run.id, run.scenarioId, run.shieldMode, run.policyId, run.userId, run.agentId, iso(now));
    },
    getRun(runId) {
      const r = selectRun.get(runId) as Row | undefined;
      if (!r) return null;
      return {
        id: String(r.id),
        scenarioId: String(r.scenario_id),
        shieldMode: r.shield_mode as ShieldMode,
        policyId: String(r.policy_id),
        userId: String(r.user_id),
        agentId: String(r.agent_id),
        status: r.status as RunStatus,
      };
    },
    setRunStatus(runId, status, now) {
      updateRunStatus.run(status, status === "running" || status === "awaiting_approval" ? null : iso(now), runId);
    },
    append(e, now) {
      const res = insertEvent.run(
        e.runId, iso(now), e.kind, e.userId, e.agentId, e.shieldMode, e.policyId ?? null, e.tool ?? null,
        json(e.args), json(e.provenance), json(e.context), e.decision ?? null, e.ruleId ?? null, json(e.reasons),
        e.risk ?? null, json(e.detector), e.callHash ?? null, e.approvalId ?? null, e.outcome ?? null, json(e.detail),
      );
      return toEvent(selectEvent.get(res.lastInsertRowid) as Row);
    },
    listEvents(runId) {
      return (selectEvents.all(runId) as Row[]).map(toEvent);
    },
  };

  const approvals: ApprovalStore = {
    create(input, now) {
      const id = `appr-${randomUUID()}`;
      insertApproval.run(id, input.runId, input.auditEventId, input.tool, input.callHash, input.requesterId, now, input.expiresAt);
      return toApproval(selectApproval.get(id) as Row);
    },
    get(id) {
      const r = selectApproval.get(id) as Row | undefined;
      return r ? toApproval(r) : null;
    },
    setDecision(id, status, approverId, now) {
      return Number(decideApproval.run(status, approverId, now, id).changes) === 1;
    },
    consume(id, callHash, now) {
      return Number(consumeApproval.run(now, id, now, callHash).changes) === 1;
    },
    listPending() {
      return (selectPending.all() as Row[]).map(toApproval);
    },
  };

  function transaction<T>(fn: () => T): T {
    db.exec("BEGIN IMMEDIATE");
    try {
      const out = fn();
      db.exec("COMMIT");
      return out;
    } catch (e) {
      db.exec("ROLLBACK");
      throw e;
    }
  }

  return { audit: Object.freeze(audit), approvals: Object.freeze(approvals), transaction };
}
