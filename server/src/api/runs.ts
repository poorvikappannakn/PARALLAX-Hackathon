import type { Stores } from "../audit/store.js";
import { decideApproval } from "../gateway/approvals.js";
import { USERS } from "../policy/profiles.js";
import type { LabId, ScenarioId } from "../scenarios/catalog.js";
import { createLabSession, type LabPlan, type LabSource } from "../scenarios/lab.js";
import { createScenarioSession, type ScenarioSession, type SessionOptions } from "../scenarios/runner.js";
import { approvalView, runContentView, runView, type PendingApprovalView, type RunContentView, type RunView } from "./views.js";

export interface AuditExplorerEvent {
  ts: string;
  runId: string;
  scenarioId: string;
  mode: "on" | "off";
  seq: number;
  kind: string;
  tool: string | null;
  decision: string | null;
  ruleId: string | null;
  outcome: string | null;
  /** First policy reason of a decision row (already masked by runView). */
  reason: string | null;
}

// In-memory registry of interactive runs (M5.3–M5.5).
//
// Each run is ONE createScenarioSession(): one startRun(), one gateway, one agent. The registry executes it one gateway call
// per tick (paced by `stepDelayMs`), so browsers see steps as they happen, and pauses at REQUIRE_APPROVAL until an
// authenticated operator decides through decideApproval() — then resumes the SAME session. All enforcement (PEP, call-hash
// binding, single-use consumption, audit) stays in the gateway; this module only drives and observes.
// Every event payload is built from the explicit-allowlist projections in views.ts.

export type RunEventName = "snapshot" | "step" | "decision" | "audit" | "approval_required" | "state" | "done" | "failed";
export interface RunEvent {
  readonly id: number;
  readonly event: RunEventName;
  readonly data: unknown;
}
export type Subscriber = (e: RunEvent) => void;

export interface RunSummary {
  runId: string;
  scenarioId: ScenarioId | LabId;
  kind: "scenario" | "lab" | "email";
  title: string;
  mode: "on" | "off";
  state: string;
  createdAt: number;
  finishedAt: number | null;
  pendingApprovalId: string | null;
}

export interface RegistryOptions {
  stores: Stores;
  clock: () => number;
  runtimeDir?: string;
  /** Delay between gateway calls of a live run (demo pacing). 0 in tests. */
  stepDelayMs: number;
  maxLive?: number;
  maxFinished?: number;
  maxEventsPerRun?: number;
  maxSubscribersPerRun?: number;
  maxSubscribersTotal?: number;
  /** How often waiting runs are checked for expired approvals (they then resume and fail closed). */
  expiryCheckMs?: number;
  /** Test hook: wraps the stores a new session uses (e.g. to inject faults). */
  sessionStores?: (s: Stores) => Stores;
}

interface LiveRun {
  session: ScenarioSession;
  createdAt: number;
  finishedAt: number | null;
  events: RunEvent[];
  nextId: number;
  subscribers: Set<Subscriber>;
  sentSteps: number;
  sentAuditSeq: number;
  sentDecisionSeq: number;
  lastState: string;
  notifiedApproval: string | null;
  resumeRequested: boolean;
  timer: ReturnType<typeof setTimeout> | null;
  settledWaiters: (() => void)[];
}

export type DecideResult =
  | { ok: true; run: RunView }
  | { ok: false; code: "NOT_FOUND" | "CONFLICT" | "EXPIRED" | "FORBIDDEN" | "AUDIT_FAILURE" };

export type SubscribeResult =
  | { ok: true; replay: RunEvent[]; finished: boolean; unsubscribe: () => void }
  | { ok: false; code: "NOT_FOUND" | "TOO_MANY_SUBSCRIBERS" };

const isLive = (r: LiveRun) => r.session.phase() !== "finished" && r.session.phase() !== "failed";

export function createRunRegistry(opts: RegistryOptions) {
  const maxLive = opts.maxLive ?? 10;
  const maxFinished = opts.maxFinished ?? 50;
  const maxEvents = opts.maxEventsPerRun ?? 500;
  const maxSubsPerRun = opts.maxSubscribersPerRun ?? 10;
  const maxSubsTotal = opts.maxSubscribersTotal ?? 100;
  const runs = new Map<string, LiveRun>();
  let subscriberCount = 0;

  const currentView = (r: LiveRun): RunView => runView(r.session.report(), r.session.auditEvents(), r.session.def);

  function emit(r: LiveRun, event: RunEventName, data: unknown) {
    const e: RunEvent = Object.freeze({ id: r.nextId++, event, data });
    r.events.push(e);
    if (r.events.length > maxEvents) r.events.shift();
    for (const sub of [...r.subscribers]) {
      try {
        sub(e);
      } catch {
        r.subscribers.delete(sub); // a broken subscriber never affects the run
      }
    }
  }

  /** Emit what changed since the last tick, using the same projection as GET /api/runs/:id. */
  function emitChanges(r: LiveRun): RunView {
    const v = currentView(r);
    for (const s of v.steps.slice(r.sentSteps)) emit(r, "step", s);
    r.sentSteps = v.steps.length;
    for (const d of v.decisions.filter((d) => d.seq > r.sentDecisionSeq)) emit(r, "decision", d);
    r.sentDecisionSeq = Math.max(r.sentDecisionSeq, ...v.decisions.map((d) => d.seq));
    for (const a of v.audit.filter((a) => a.seq > r.sentAuditSeq)) emit(r, "audit", a);
    r.sentAuditSeq = Math.max(r.sentAuditSeq, ...v.audit.map((a) => a.seq));
    const phase = r.session.phase();
    const stateKey = `${phase}:${v.state}`;
    if (stateKey !== r.lastState) {
      r.lastState = stateKey;
      emit(r, "state", { phase, state: v.state });
    }
    return v;
  }

  function finish(r: LiveRun) {
    r.finishedAt = opts.clock();
    for (const w of r.settledWaiters.splice(0)) w();
    // Bounded retention: drop the oldest finished runs (never live or waiting ones).
    const finished = [...runs.values()].filter((x) => !isLive(x)).sort((a, b) => (a.finishedAt ?? 0) - (b.finishedAt ?? 0));
    while (finished.length > maxFinished) {
      const old = finished.shift()!;
      subscriberCount -= old.subscribers.size;
      old.subscribers.clear();
      runs.delete(old.session.runId);
    }
  }

  function schedule(r: LiveRun) {
    if (r.timer) return;
    r.timer = setTimeout(() => tick(r), opts.stepDelayMs);
  }

  /** One gateway call (or a resume), then publish the changes. Never retries anything. */
  function tick(r: LiveRun) {
    r.timer = null;
    const s = r.session;
    try {
      const phase = s.phase();
      const result =
        phase === "created" ? s.start(1) : phase === "running" ? s.advance(1) : phase === "waiting" && r.resumeRequested ? s.resume(1) : null;
      if (result && phase === "waiting") r.resumeRequested = false;
      const v = emitChanges(r);
      const now = s.phase();
      if (now === "running") return schedule(r);
      if (now === "waiting") {
        const id = s.pendingApprovalId();
        if (id && id !== r.notifiedApproval) {
          r.notifiedApproval = id;
          const record = opts.stores.approvals.get(id);
          if (record) emit(r, "approval_required", approvalView(record, s.auditEvents(), USERS[s.report().scenario.userId]?.email ?? null));
        }
        for (const w of r.settledWaiters.splice(0)) w();
        return;
      }
      // A gateway halt (fail-closed, e.g. audit write failure) is a failure, not a normal completion.
      emit(r, now === "failed" || v.state === "halted" ? "failed" : "done", { run: v });
      finish(r);
    } catch {
      // Observation failed (e.g. storage error). The session itself contains its failures; stop driving this run.
      emit(r, "failed", { run: null, reason: "Run could not be observed; stopped" });
      if (!r.finishedAt) finish(r);
    }
  }

  function requestResume(r: LiveRun) {
    r.resumeRequested = true;
    schedule(r);
  }

  // Waiting runs whose approval expired are resumed so the gateway records the fail-closed F0 decision.
  const expiryTimer = setInterval(() => {
    for (const r of runs.values()) {
      const id = r.session.pendingApprovalId();
      if (!id || r.resumeRequested) continue;
      try {
        const rec = opts.stores.approvals.get(id);
        if (rec && rec.status === "pending" && opts.clock() >= rec.expiresAt) requestResume(r);
      } catch {
        /* checked again next interval */
      }
    }
  }, opts.expiryCheckMs ?? 5000);
  expiryTimer.unref();

  const summary = (r: LiveRun): RunSummary => ({
    runId: r.session.runId,
    scenarioId: r.session.scenarioId,
    kind: r.session.def.id === "LAB" ? "lab" : r.session.def.id === "EMAIL" ? "email" : "scenario",
    title: r.session.def.title,
    mode: r.session.mode,
    state: r.session.status()?.state ?? "created",
    createdAt: r.createdAt,
    finishedAt: r.finishedAt,
    pendingApprovalId: r.session.pendingApprovalId(),
  });

  const sessionOptions = (): SessionOptions => ({
    stores: opts.sessionStores ? opts.sessionStores(opts.stores) : opts.stores,
    clock: opts.clock,
    interactive: true,
    ...(opts.runtimeDir ? { runtimeDir: opts.runtimeDir } : {}),
  });
  const hasCapacity = (n: number) => [...runs.values()].filter(isLive).length + n <= maxLive;

  /** Register and start driving one session (catalogue scenario or lab). */
  function register(session: ScenarioSession): RunView {
    if (runs.has(session.runId)) throw new Error("Duplicate run id"); // random UUIDs; defensive
      const r: LiveRun = {
        session,
        createdAt: opts.clock(),
        finishedAt: null,
        events: [],
        nextId: 1,
        subscribers: new Set(),
        sentSteps: 0,
        sentAuditSeq: 0,
        sentDecisionSeq: 0,
        lastState: "",
        notifiedApproval: null,
        resumeRequested: false,
        timer: null,
        settledWaiters: [],
      };
      runs.set(session.runId, r);
      const v = emitChanges(r); // run_started audit row + initial state
      schedule(r);
      return v;
  }

  return {
    start(scenarioId: ScenarioId, mode: "on" | "off"): { ok: true; run: RunView } | { ok: false; code: "CAPACITY" } {
      if (!hasCapacity(1)) return { ok: false, code: "CAPACITY" };
      return { ok: true, run: register(createScenarioSession(scenarioId, mode, sessionOptions())) };
    },

    /**
     * Lab runs: one isolated session (own sandbox, own copy of the content) per requested mode, all with the same task
     * and content. Capacity is checked for all of them up front.
     */
    startLab(task: string, source: LabSource, plan: LabPlan, modes: readonly ("on" | "off")[]): { ok: true; runs: RunView[] } | { ok: false; code: "CAPACITY" } {
      if (!hasCapacity(modes.length)) return { ok: false, code: "CAPACITY" };
      return { ok: true, runs: modes.map((m) => register(createLabSession(task, source, plan, m, sessionOptions()))) };
    },

    /** Untrusted input content of a run, for the inspector. */
    content(runId: string): RunContentView | null {
      const r = runs.get(runId);
      return r ? runContentView(runId, r.session.def, r.session.inspector()) : null;
    },

    /** Aggregates over the runs held in memory (real decisions only). */
    overview() {
      const all = [...runs.values()];
      const views = all.map(currentView);
      const decisions = views.flatMap((v) => v.decisions.filter((d) => d.kind === "decision"));
      return {
        runs: all.length,
        live: all.filter((r) => r.session.phase() === "running" || r.session.phase() === "created").length,
        waiting: all.filter((r) => r.session.phase() === "waiting").length,
        decisions: {
          allow: decisions.filter((d) => d.decision === "ALLOW").length,
          deny: decisions.filter((d) => d.decision === "DENY").length,
          approval: decisions.filter((d) => d.decision === "REQUIRE_APPROVAL").length,
        },
        attacksBlocked: views.filter((v) => v.mode === "on" && v.attack.applicable && v.attack.result === false && v.state !== "waiting").length,
        attacksSucceeded: views.filter((v) => v.attack.applicable && v.attack.result === true).length,
      };
    },

    /** Audit events of all runs held in memory, newest first (allowlisted fields + masked policy reason). */
    auditExplorer(limit = 500): AuditExplorerEvent[] {
      const out: AuditExplorerEvent[] = [];
      for (const r of runs.values()) {
        const v = currentView(r);
        const reasons = new Map(v.decisions.map((d) => [d.seq, d.reasons[0] ?? null]));
        for (const e of v.audit) {
          out.push({ ts: e.ts, runId: v.runId, scenarioId: v.scenario.id, mode: v.mode, seq: e.seq, kind: e.kind, tool: e.tool, decision: e.decision, ruleId: e.ruleId, outcome: e.outcome, reason: reasons.get(e.seq) ?? null });
        }
      }
      return out.sort((a, b) => (a.ts < b.ts ? 1 : a.ts > b.ts ? -1 : b.seq - a.seq)).slice(0, limit);
    },

    view(runId: string): RunView | null {
      const r = runs.get(runId);
      return r ? currentView(r) : null;
    },

    list(): RunSummary[] {
      return [...runs.values()].sort((a, b) => b.createdAt - a.createdAt).map(summary);
    },

    pendingApprovals(): PendingApprovalView[] {
      const out: PendingApprovalView[] = [];
      for (const r of runs.values()) {
        const id = r.session.pendingApprovalId();
        if (!id) continue;
        const rec = opts.stores.approvals.get(id);
        if (!rec || rec.status !== "pending" || rec.used) continue;
        out.push(approvalView(rec, r.session.auditEvents(), USERS[r.session.report().scenario.userId]?.email ?? null));
      }
      return out;
    },

    /**
     * Human decision. The approver id comes from the caller's authenticated session. Persistence, operator check, expiry
     * and single-decision rules are decideApproval()'s (M3); execution happens only via the session's gateway resume.
     */
    decide(approvalId: string, operatorId: string, verdict: "approve" | "reject"): DecideResult {
      const r = [...runs.values()].find((x) => x.session.pendingApprovalId() === approvalId);
      if (!r) {
        const rec = opts.stores.approvals.get(approvalId);
        return { ok: false, code: rec && rec.status !== "pending" ? "CONFLICT" : "NOT_FOUND" };
      }
      if (r.resumeRequested) return { ok: false, code: "CONFLICT" }; // already decided / resuming
      const res = decideApproval(opts.stores, approvalId, operatorId, verdict, opts.clock());
      if (!res.ok) {
        if (res.code === "EXPIRED") requestResume(r); // let the gateway record F0 "expired"
        return { ok: false, code: res.code };
      }
      r.session.noteDecision(approvalId, { kind: "human", operator: operatorId }, verdict);
      requestResume(r);
      return { ok: true, run: currentView(r) };
    },

    subscribe(runId: string, sub: Subscriber, lastEventId: number | null): SubscribeResult {
      const r = runs.get(runId);
      if (!r) return { ok: false, code: "NOT_FOUND" };
      if (r.subscribers.size >= maxSubsPerRun || subscriberCount >= maxSubsTotal) return { ok: false, code: "TOO_MANY_SUBSCRIBERS" };
      const latest = r.nextId - 1;
      const first = r.events[0]?.id ?? r.nextId;
      // Resume from Last-Event-ID when every missed event is still buffered; otherwise start from a fresh snapshot.
      const replay: RunEvent[] =
        lastEventId !== null && lastEventId <= latest && lastEventId + 1 >= first
          ? r.events.filter((e) => e.id > lastEventId)
          : [{ id: latest, event: "snapshot", data: { run: currentView(r) } }];
      const finished = !isLive(r);
      if (finished) return { ok: true, replay, finished, unsubscribe: () => {} };
      r.subscribers.add(sub);
      subscriberCount++;
      let active = true;
      return {
        ok: true,
        replay,
        finished,
        unsubscribe: () => {
          if (!active) return;
          active = false;
          if (r.subscribers.delete(sub)) subscriberCount--;
        },
      };
    },

    /** Resolves when the run is waiting for approval or finished (tests, suite). */
    settled(runId: string): Promise<void> {
      const r = runs.get(runId);
      if (!r || !isLive(r) || (r.session.phase() === "waiting" && !r.resumeRequested && !r.timer)) return Promise.resolve();
      return new Promise((resolve) => r.settledWaiters.push(resolve));
    },

    subscriberCount: () => subscriberCount,
    /** Internal (tests): the live session object, to prove resume continues the same instance. */
    sessionOf: (runId: string) => runs.get(runId)?.session ?? null,

    close() {
      clearInterval(expiryTimer);
      for (const r of runs.values()) if (r.timer) clearTimeout(r.timer);
    },
  };
}

export type RunRegistry = ReturnType<typeof createRunRegistry>;
