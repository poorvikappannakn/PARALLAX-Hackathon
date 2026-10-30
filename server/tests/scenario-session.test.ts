import { readdirSync, readFileSync } from "node:fs";
import path from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import type { Stores } from "../src/audit/store.js";
import { decideApproval } from "../src/gateway/approvals.js";
import { createScenarioSession, INTERACTIVE_OPERATOR_NOTE, runScenario, type ScenarioSession, type SessionResult } from "../src/scenarios/runner.js";
import { memoryStores } from "./gateway-harness.js";
import { tempRuntime } from "./tool-harness.js";

const rt = tempRuntime();
afterAll(rt.cleanup);

const HUMAN = "operator:alice";
const outbox = (s: ScenarioSession) => readdirSync(path.join(s.report().sandboxDir, "outbox"));

function interactive(id: Parameters<typeof createScenarioSession>[0] = "S1", extra: { stores?: Stores; clock?: () => number } = {}) {
  const stores = extra.stores ?? memoryStores().stores;
  const session = createScenarioSession(id, "on", { stores, runtimeDir: rt.dir, interactive: true, clock: extra.clock });
  return { session, stores };
}
const waitingId = (r: SessionResult) => {
  if (!r.ok || r.status.state !== "waiting") throw new Error(`expected waiting, got ${JSON.stringify(r)}`);
  return r.status.approvalId;
};

describe("interactive session: human approval pauses and resumes the SAME run", () => {
  it("start -> waiting -> (resume refused while pending) -> human approves -> resume -> done, one email", () => {
    const { session, stores } = interactive();
    const runId = session.runId;
    expect(session.phase()).toBe("created");
    const approvalId = waitingId(session.start());
    expect(session.phase()).toBe("waiting");
    expect(session.pendingApprovalId()).toBe(approvalId);

    // Undecided: refused without touching the agent (its trace does not grow).
    const stepsBefore = session.report().steps.length;
    expect(session.resume()).toEqual({ ok: false, code: "APPROVAL_PENDING" });
    expect(session.report().steps).toHaveLength(stepsBefore);
    expect(outbox(session)).toEqual([]);

    expect(decideApproval(stores, approvalId, HUMAN, "approve", Date.now()).ok).toBe(true);
    session.noteDecision(approvalId, { kind: "human", operator: HUMAN }, "approve");
    expect(session.resume()).toEqual({ ok: true, status: { state: "done" } });
    expect(session.phase()).toBe("finished");
    expect(session.runId).toBe(runId);
    expect(outbox(session)).toHaveLength(1);

    const report = session.report();
    expect(report.runId).toBe(runId);
    expect(report.operatorNote).toBe(INTERACTIVE_OPERATOR_NOTE);
    expect(report.approvals).toEqual([
      { approvalId, tool: "send_email", scripted: false, operator: HUMAN, action: "approve", rationale: null, reDecision: { decision: "ALLOW", ruleId: "A1+APPROVED" }, executed: true },
    ]);
    // The audit trail of the one run contains exactly one approval cycle.
    expect(report.audit.map((e) => e.kind)).toEqual([
      "run_started", "decision", "outcome", "decision", "approval_requested", "approval_decided", "re_decision", "outcome",
    ]);
    expect(stores.audit.getRun(runId)?.status).toBe("completed");
  });

  it("lifecycle guards: no second start, no resume before start, no second resume, no resume after finish", () => {
    const { session, stores } = interactive();
    expect(session.resume()).toEqual({ ok: false, code: "NOT_STARTED" });
    const approvalId = waitingId(session.start());
    expect(session.start()).toEqual({ ok: false, code: "ALREADY_STARTED" });
    decideApproval(stores, approvalId, HUMAN, "approve", Date.now());
    expect(session.resume().ok).toBe(true);
    expect(session.resume()).toEqual({ ok: false, code: "NOT_WAITING" });
    expect(session.start()).toEqual({ ok: false, code: "ALREADY_STARTED" });
    expect(outbox(session)).toHaveLength(1); // still exactly one email
  });

  it("re-entrant resume during a resume is refused (BUSY) and does not execute twice", () => {
    const base = memoryStores().stores;
    let session: ScenarioSession | null = null;
    let inner: SessionResult | null = null;
    const reentrant: Stores = {
      ...base,
      approvals: {
        ...base.approvals,
        consume: (id, hash, now) => {
          inner ??= session!.resume(); // a second driver tries to resume while the first is inside the gateway
          return base.approvals.consume(id, hash, now);
        },
      },
    };
    session = createScenarioSession("S1", "on", { stores: reentrant, runtimeDir: rt.dir, interactive: true });
    const approvalId = waitingId(session.start());
    decideApproval(base, approvalId, HUMAN, "approve", Date.now());
    expect(session.resume()).toEqual({ ok: true, status: { state: "done" } });
    expect(inner).toEqual({ ok: false, code: "BUSY" });
    expect(outbox(session)).toHaveLength(1);
  });

  it("human rejection: the gateway denies on re-evaluation (F0); the run finishes without sending", () => {
    const { session, stores } = interactive();
    const approvalId = waitingId(session.start());
    decideApproval(stores, approvalId, HUMAN, "reject", Date.now());
    session.noteDecision(approvalId, { kind: "human", operator: HUMAN }, "reject");
    expect(session.resume()).toEqual({ ok: true, status: { state: "done" } });
    expect(session.report().approvals[0]).toMatchObject({ scripted: false, action: "reject", reDecision: { decision: "DENY", ruleId: "F0" }, executed: false });
    expect(outbox(session)).toEqual([]);
  });

  it("an approval that expires undecided can be resumed once and fails closed (F0 expired)", () => {
    let now = 1_900_000_000_000;
    const { session } = interactive("S1", { clock: () => now });
    waitingId(session.start());
    expect(session.resume()).toEqual({ ok: false, code: "APPROVAL_PENDING" });
    now += 301_000;
    expect(session.resume()).toEqual({ ok: true, status: { state: "done" } });
    expect(session.report().decisions.at(-1)).toMatchObject({ kind: "re_decision", ruleId: "F0", reasons: ["F0: approval expired before an operator decided"] });
    expect(outbox(session)).toEqual([]);
  });

  it("if resuming fails after the approval was persisted: session FAILED, nothing executes, never retried", () => {
    const base = memoryStores().stores;
    let broken = false;
    const flaky: Stores = {
      ...base,
      approvals: {
        ...base.approvals,
        get: (id) => {
          if (broken) throw new Error("SQLITE_IOERR");
          return base.approvals.get(id);
        },
      },
    };
    const { session } = interactive("S1", { stores: flaky });
    const approvalId = waitingId(session.start());
    expect(decideApproval(base, approvalId, HUMAN, "approve", Date.now()).ok).toBe(true); // persisted
    broken = true;
    expect(session.resume()).toEqual({ ok: false, code: "FAILED" });
    broken = false;
    expect(session.phase()).toBe("failed");
    expect(session.status()).toEqual({ state: "halted", reason: expect.stringMatching(/Session error/) });
    expect(session.resume()).toEqual({ ok: false, code: "FAILED" }); // no automatic or manual retry
    expect(session.start()).toEqual({ ok: false, code: "FAILED" });
    expect(outbox(session)).toEqual([]);
    expect(base.approvals.get(approvalId)).toMatchObject({ status: "approved", used: false }); // decided, never consumed
    expect(base.audit.getRun(session.runId)?.status).toBe("error");
    expect(session.report().final).toEqual({ state: "halted", haltReason: expect.stringMatching(/Session error/) });
  });
});

describe("runScenario() is rebuilt on the session and keeps its behaviour", () => {
  it("scripted approvals are still marked scripted with the script's rationale", () => {
    const { stores } = memoryStores();
    const r = runScenario("S2", "on", { stores, runtimeDir: rt.dir });
    expect(r.approvals.every((a) => a.scripted === true && typeof a.rationale === "string")).toBe(true);
    expect(r.operatorNote).toMatch(/SCRIPTED/);
    expect(r.expectationsMet).toBe(true);
  });

  it("the interactive flag only changes the operator note, never enforcement", () => {
    const a = createScenarioSession("S3", "on", { stores: memoryStores().stores, runtimeDir: rt.dir, interactive: true });
    const b = createScenarioSession("S3", "on", { stores: memoryStores().stores, runtimeDir: rt.dir });
    const ra = a.start();
    const rb = b.start();
    expect(ra.ok && rb.ok && ra.status.state).toBe(rb.ok ? rb.status.state : null);
    const strip = (s: ScenarioSession) => s.report().steps;
    expect(strip(a)).toEqual(strip(b));
    expect(readFileSync(path.join(a.report().sandboxDir, "files", "hr", "salaries.csv"), "utf8").length).toBeGreaterThan(0);
  });
});
