import { afterAll, describe, expect, it } from "vitest";
import type { Stores } from "../src/audit/store.js";
import { scenarioListView } from "../src/api/views.js";
import { SCENARIO_IDS, SCENARIOS } from "../src/scenarios/catalog.js";
import { apiHarness, FORBIDDEN } from "./api-harness.js";
import { tempRuntime } from "./tool-harness.js";

const rt = tempRuntime();
afterAll(rt.cleanup);

const FORBIDDEN_KEYS = /"(?:sandboxDir|trace|request|args|body|subject|content|html|detail|evidence|callHash|bodySha256|filesPresent|to)"\s*:/;

const pendingFor = async (h: Awaited<ReturnType<typeof apiHarness>>, runId: string) =>
  ((await h.call("GET", "/api/approvals?status=pending")).json() as { approvals: { approvalId: string; runId: string }[] }).approvals.filter((a) => a.runId === runId);

describe("M5.3 scenarios and runs", () => {
  it("GET /api/scenarios returns the catalogue projection only", async () => {
    const h = await apiHarness(rt.dir);
    const res = await h.call("GET", "/api/scenarios");
    expect(res.statusCode).toBe(200);
    expect(res.json()).toEqual({ scenarios: scenarioListView() });
  });

  it("POST /api/runs starts exactly one session; GET returns its sanitised view; the run completes", async () => {
    const h = await apiHarness(rt.dir);
    const res = await h.call("POST", "/api/runs", { scenarioId: "S4", mode: "on" });
    expect(res.statusCode).toBe(201);
    const { run } = res.json() as { run: { runId: string; scenario: { id: string }; mode: string } };
    expect(run).toMatchObject({ runId: expect.stringMatching(/^run-/), scenario: { id: "S4" }, mode: "on" });
    await h.ctx.registry.settled(run.runId);
    const after = (await h.getRun(run.runId)).run;
    // S4 ON: both injected deletes were denied (P1); the legitimate inbox summary now waits for human approval (A1).
    expect(after).toMatchObject({ runId: run.runId, state: "waiting", attack: { result: false } });
    expect(after.decisions.filter((d: any) => d.ruleId === "P1")).toHaveLength(2);
    expect(after.protectedFiles.every((f: any) => f.present)).toBe(true);
  });

  it.each([
    [{ scenarioId: "S1", mode: "on", operatorId: "operator:mallory" }],
    [{ scenarioId: "S1", mode: "on", steps: [{ op: "raw", request: { tool: "shell_exec" } }] }],
    [{ scenarioId: "S1", mode: "on", request: { tool: "delete_file", args: {} } }],
    [{ scenarioId: "S9", mode: "on" }],
    [{ scenarioId: "S1", mode: "maybe" }],
    [{ scenarioId: "S1" }],
    [{ scenarioId: ["S1"], mode: "on" }],
  ])("rejects body %j with 400 and starts nothing", async (payload) => {
    const h = await apiHarness(rt.dir);
    const res = await h.call("POST", "/api/runs", payload);
    expect(res.statusCode).toBe(400);
    expect(res.json()).toEqual({ error: { code: "BAD_REQUEST", message: "Malformed request" } });
    expect(h.ctx.registry.list()).toEqual([]);
  });

  it("requires a session and CSRF", async () => {
    const h = await apiHarness(rt.dir);
    expect((await h.call("POST", "/api/runs", { scenarioId: "S1", mode: "on" }, { auth: null })).statusCode).toBe(401);
    expect((await h.call("GET", "/api/runs", undefined, { auth: null })).statusCode).toBe(401);
    expect((await h.call("GET", "/api/scenarios", undefined, { auth: null })).statusCode).toBe(401);
    const noCsrf = await h.call("POST", "/api/runs", { scenarioId: "S1", mode: "on" }, { auth: { cookie: h.session.cookie, csrf: "" } });
    expect(noCsrf.statusCode).toBe(403);
    expect(h.ctx.registry.list()).toEqual([]);
  });

  it("unknown and malformed run ids: safe 404", async () => {
    const h = await apiHarness(rt.dir);
    for (const id of ["run-00000000-0000-4000-8000-000000000000", "not-a-run", "..%2F..%2Fetc", "run-x"]) {
      const res = await h.call("GET", `/api/runs/${id}`);
      expect(res.statusCode).toBe(404);
      expect(res.json()).toEqual({ error: { code: "NOT_FOUND", message: "Not found" } });
    }
  });

  it("capacity: at most N live/waiting runs (429); finished runs do not count", async () => {
    const h = await apiHarness(rt.dir, { registry: { maxLive: 2 } });
    await h.startRun("S1", "on"); // waits for approval
    await h.startRun("S1", "on"); // waits for approval
    const third = await h.call("POST", "/api/runs", { scenarioId: "S3", mode: "off" });
    expect(third.statusCode).toBe(429);
    expect(third.json()).toEqual({ error: { code: "CAPACITY", message: "Too many active runs; wait for one to finish" } });
  });

  it("bounded retention evicts the oldest finished runs, never waiting ones", async () => {
    const h = await apiHarness(rt.dir, { registry: { maxFinished: 2 } });
    const waiting = await h.startRun("S1", "on");
    const f1 = await h.startRun("S3", "off");
    const f2 = await h.startRun("S3", "off");
    const f3 = await h.startRun("S3", "off");
    expect((await h.call("GET", `/api/runs/${f1}`)).statusCode).toBe(404);
    for (const id of [waiting, f2, f3]) expect((await h.call("GET", `/api/runs/${id}`)).statusCode).toBe(200);
    expect((await h.getRun(waiting)).run.state).toBe("waiting");
    const list = (await h.call("GET", "/api/runs")).json() as { runs: { runId: string; pendingApprovalId: string | null }[] };
    expect(list.runs.map((r) => r.runId).sort()).toEqual([waiting, f2, f3].sort());
    expect(list.runs.find((r) => r.runId === waiting)!.pendingApprovalId).toMatch(/^appr-/);
  });
});

describe("M5.4 human approval resumes the SAME run", () => {
  it("approve: same run id and the same session/gateway instance continue; exactly one email; audit shows the human decision", async () => {
    const h = await apiHarness(rt.dir);
    const runId = await h.startRun("S1", "on");
    const sessionBefore = h.ctx.registry.sessionOf(runId);
    const before = (await h.getRun(runId)).run;
    expect(before.state).toBe("waiting");
    const [pending] = await pendingFor(h, runId);
    expect(pending).toMatchObject({ runId, tool: "send_email", status: "pending", ruleId: "A1", recipient: "requesting_user" });

    const res = await h.call("POST", `/api/approvals/${pending!.approvalId}/decision`, { verdict: "approve" });
    expect(res.statusCode).toBe(200);
    expect((res.json() as { run: { runId: string } }).run.runId).toBe(runId);
    await h.ctx.registry.settled(runId);

    expect(h.ctx.registry.sessionOf(runId)).toBe(sessionBefore); // same object: same gateway, same agent
    const after = (await h.getRun(runId)).run;
    expect(after).toMatchObject({ runId, state: "done", legitimate: { result: true } });
    expect(after.outbox).toHaveLength(1);
    expect(after.approvals).toEqual([
      { approvalId: pending!.approvalId, tool: "send_email", actor: "human", operator: "operator:alice", action: "approve", rationale: null, reDecision: { decision: "ALLOW", ruleId: "A1+APPROVED" }, executed: true },
    ]);
    expect(h.ctx.registry.list().filter((r) => r.scenarioId === "S1")).toHaveLength(1); // no second run was created
    const audit = h.ctx.stores.audit.listEvents(runId);
    expect(audit.map((e) => e.kind)).toEqual(["run_started", "decision", "outcome", "decision", "approval_requested", "approval_decided", "re_decision", "outcome"]);
    expect(audit.find((e) => e.kind === "approval_decided")).toMatchObject({ decision: "APPROVED", detail: { approverId: "operator:alice" } });
    expect(await pendingFor(h, runId)).toEqual([]);
  });

  it("reject: re-evaluation denies (F0); nothing sent; audit records the rejection", async () => {
    const h = await apiHarness(rt.dir);
    const runId = await h.startRun("S1", "on");
    const [p] = await pendingFor(h, runId);
    expect((await h.call("POST", `/api/approvals/${p!.approvalId}/decision`, { verdict: "reject" })).statusCode).toBe(200);
    await h.ctx.registry.settled(runId);
    const run = (await h.getRun(runId)).run;
    expect(run).toMatchObject({ state: "done", outbox: [], approvals: [{ actor: "human", action: "reject", reDecision: { decision: "DENY", ruleId: "F0" }, executed: false }] });
    expect(h.ctx.stores.audit.listEvents(runId).find((e) => e.kind === "approval_decided")).toMatchObject({ decision: "REJECTED" });
  });

  it("duplicate decisions are refused (409) and nothing executes twice", async () => {
    const h = await apiHarness(rt.dir);
    const runId = await h.startRun("S1", "on");
    const [p] = await pendingFor(h, runId);
    const url = `/api/approvals/${p!.approvalId}/decision`;
    const [a, b] = await Promise.all([h.call("POST", url, { verdict: "approve" }), h.call("POST", url, { verdict: "approve" })]);
    expect([a.statusCode, b.statusCode].sort()).toEqual([200, 409]);
    await h.ctx.registry.settled(runId);
    const late = await h.call("POST", url, { verdict: "reject" });
    expect(late.statusCode).toBe(409);
    expect(late.json()).toEqual({ error: { code: "CONFLICT", message: "Approval was already decided" } });
    const run = (await h.getRun(runId)).run;
    expect(run.outbox).toHaveLength(1);
    expect(h.ctx.stores.audit.listEvents(runId).filter((e) => e.kind === "approval_decided")).toHaveLength(1);
  });

  it("expired approval: decision refused (409 APPROVAL_EXPIRED); the run fails closed (F0 expired); nothing sent", async () => {
    const h = await apiHarness(rt.dir);
    const runId = await h.startRun("S1", "on");
    const [p] = await pendingFor(h, runId);
    h.advance(301_000);
    const res = await h.call("POST", `/api/approvals/${p!.approvalId}/decision`, { verdict: "approve" });
    expect(res.statusCode).toBe(409);
    expect((res.json() as { error: { code: string } }).error.code).toBe("APPROVAL_EXPIRED");
    await h.ctx.registry.settled(runId);
    const run = (await h.getRun(runId)).run;
    expect(run.state).toBe("done");
    expect(run.outbox).toEqual([]);
    expect(run.decisions.at(-1)).toMatchObject({ kind: "re_decision", ruleId: "F0", reasons: ["F0: approval expired before an operator decided"] });
  });

  it("forged, malformed and foreign approval ids are refused; client-chosen identity is rejected", async () => {
    const h = await apiHarness(rt.dir);
    const runId = await h.startRun("S1", "on");
    const [p] = await pendingFor(h, runId);
    expect((await h.call("POST", "/api/approvals/appr-00000000-0000-4000-8000-000000000000/decision", { verdict: "approve" })).statusCode).toBe(404);
    expect((await h.call("POST", "/api/approvals/appr-not-an-id/decision", { verdict: "approve" })).statusCode).toBe(404);
    expect((await h.call("POST", `/api/approvals/${p!.approvalId}/decision`, { verdict: "approve", operatorId: "operator:mallory" })).statusCode).toBe(400);
    expect((await h.call("POST", `/api/approvals/${p!.approvalId}/decision`, { verdict: "yes" })).statusCode).toBe(400);
    expect((await h.call("POST", `/api/approvals/${p!.approvalId}/decision`, { verdict: "approve" }, { auth: null })).statusCode).toBe(401);
    const noCsrf = await h.call("POST", `/api/approvals/${p!.approvalId}/decision`, { verdict: "approve" }, { auth: { cookie: h.session.cookie, csrf: "x" } });
    expect(noCsrf.statusCode).toBe(403);
    expect((await h.getRun(runId)).run.state).toBe("waiting"); // none of the above decided anything
    expect(h.ctx.stores.approvals.get(p!.approvalId)).toMatchObject({ status: "pending", used: false });
  });

  it("another operator session: its own CSRF token is required, and the approver is the session's operator", async () => {
    const h = await apiHarness(rt.dir);
    const runId = await h.startRun("S1", "on");
    const [p] = await pendingFor(h, runId);
    const other = await h.login();
    const crossed = await h.call("POST", `/api/approvals/${p!.approvalId}/decision`, { verdict: "approve" }, { auth: { cookie: other.cookie, csrf: h.session.csrf } });
    expect(crossed.statusCode).toBe(403);
    expect((await h.call("POST", `/api/approvals/${p!.approvalId}/decision`, { verdict: "approve" }, { auth: other })).statusCode).toBe(200);
    await h.ctx.registry.settled(runId);
    expect(h.ctx.stores.audit.listEvents(runId).find((e) => e.kind === "approval_decided")).toMatchObject({ detail: { approverId: "operator:alice" } });
  });

  it("DENY is never turned into an approval: S2 Shield ON offers only the user's own summary for approval", async () => {
    const h = await apiHarness(rt.dir);
    const runId = await h.startRun("S2", "on");
    const pending = await pendingFor(h, runId);
    expect(pending).toHaveLength(1);
    expect(pending[0]).toMatchObject({ tool: "send_email", recipient: "requesting_user", ruleId: "A1" });
    await h.call("POST", `/api/approvals/${pending[0]!.approvalId}/decision`, { verdict: "approve" });
    await h.ctx.registry.settled(runId);
    const run = (await h.getRun(runId)).run;
    expect(run.decisions.filter((d: any) => d.decision === "DENY").map((d: any) => d.ruleId)).toEqual(["P2", "P4", "P4"]);
    expect(run.outbox.map((m: any) => m.recipient)).toEqual(["requesting_user"]);
    expect(run.attack.result).toBe(false);
  });

  it("M7: S5 explains its expectation — a human may approve the legitimate email; probes are still refused", async () => {
    const h = await apiHarness(rt.dir);
    const s5 = ((await h.call("GET", "/api/scenarios")).json() as { scenarios: { id: string; expectationNote: string | null }[] }).scenarios;
    expect(s5.find((s) => s.id === "S5")!.expectationNote).toMatch(/scripted operator never answers/);
    expect(s5.filter((s) => s.id !== "S5").every((s) => s.expectationNote === null)).toBe(true);

    const runId = await h.startRun("S5", "on");
    const [p] = await pendingFor(h, runId);
    await h.call("POST", `/api/approvals/${p!.approvalId}/decision`, { verdict: "approve" });
    await h.ctx.registry.settled(runId);
    const run = (await h.getRun(runId)).run;
    expect(run).toMatchObject({ state: "done", legitimate: { result: true }, attack: { result: false }, expectationsMet: false });
    expect(run.expectationNote).toMatch(/human operator may legitimately approve/);
    expect(run.decisions.filter((d: any) => d.kind === "decision" && d.ruleId === "F0")).toHaveLength(4); // enforcement unchanged
    expect(run.outbox.map((m: any) => m.recipient)).toEqual(["requesting_user"]);
  });

  it("execution failure after a persisted approval: run stops (failed), never retried, server keeps serving", async () => {
    let broken = false;
    const sessionStores = (s: Stores): Stores => ({
      ...s,
      approvals: { ...s.approvals, get: (id) => (broken ? (() => { throw new Error("SQLITE_IOERR"); })() : s.approvals.get(id)) },
    });
    const h = await apiHarness(rt.dir, { registry: { sessionStores } });
    const runId = await h.startRun("S1", "on");
    const [p] = await pendingFor(h, runId);
    broken = true;
    expect((await h.call("POST", `/api/approvals/${p!.approvalId}/decision`, { verdict: "approve" })).statusCode).toBe(200);
    await h.ctx.registry.settled(runId);
    broken = false;
    const run = (await h.getRun(runId)).run;
    expect(run.state).toBe("halted");
    expect(run.haltReason).toMatch(/Session error/);
    expect(run.outbox).toEqual([]);
    expect(h.ctx.stores.approvals.get(p!.approvalId)).toMatchObject({ status: "approved", used: false });
    expect((await h.call("POST", `/api/approvals/${p!.approvalId}/decision`, { verdict: "approve" })).statusCode).toBe(409);
    expect((await h.call("GET", "/api/health")).statusCode).toBe(200);
  });
});

describe("API responses never leak sensitive data (all scenarios, both modes, human approvals)", () => {
  it.each(SCENARIO_IDS.flatMap((id) => (["off", "on"] as const).map((m) => [id, m] as const)))("%s Shield %s", async (id, mode) => {
    const h = await apiHarness(rt.dir);
    const runId = await h.startRun(id, mode);
    for (let i = 0; i < 5 && (await h.getRun(runId)).run.state === "waiting"; i++) {
      const [p] = await pendingFor(h, runId);
      const decision = await h.call("POST", `/api/approvals/${p!.approvalId}/decision`, { verdict: "approve" });
      for (const f of FORBIDDEN) expect(decision.body).not.toContain(f);
      await h.ctx.registry.settled(runId);
    }
    const bodies = [
      (await h.call("GET", `/api/runs/${runId}`)).body,
      (await h.call("GET", "/api/runs")).body,
      (await h.call("GET", "/api/approvals")).body,
    ];
    for (const body of bodies) {
      for (const f of FORBIDDEN) expect(body).not.toContain(f);
      expect(body).not.toMatch(FORBIDDEN_KEYS);
      expect(body).not.toContain(rt.dir);
      expect(body).not.toMatch(/runtime[\\/]runs|[A-Za-z]:\\\\|[0-9a-f]{64}/);
    }
    const run = (await h.getRun(runId)).run;
    // A human approving everything matches the scripted expectations, except S5 ON, which is catalogued as "the operator
    // never answers" (its status email is expected to expire). Approving it sends the email, so the expectation honestly fails.
    expect(run.expectationsMet).toBe(!(id === "S5" && mode === "on"));
    expect(run.attack.result).toBe(SCENARIOS[id].expect[mode].attackSucceeded);
  });
});
