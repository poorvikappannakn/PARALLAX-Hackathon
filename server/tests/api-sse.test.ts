import { afterAll, afterEach, describe, expect, it } from "vitest";
import type { Stores } from "../src/audit/store.js";
import { apiHarness, FORBIDDEN, freePort, sse } from "./api-harness.js";
import { tempRuntime } from "./tool-harness.js";

const rt = tempRuntime();
afterAll(rt.cleanup);

const opened: { close(): Promise<unknown> }[] = [];
afterEach(async () => {
  for (const a of opened.splice(0)) await a.close();
});

async function live(extra: Parameters<typeof apiHarness>[1] = {}) {
  const port = await freePort();
  const h = await apiHarness(rt.dir, { port, stepDelayMs: 25, ...extra });
  await h.app.listen({ host: "127.0.0.1", port });
  opened.push(h.app);
  const begin = async (scenarioId: string, mode: "on" | "off") => {
    const res = await h.call("POST", "/api/runs", { scenarioId, mode });
    return (res.json() as { run: { runId: string } }).run.runId;
  };
  const stream = (runId: string, headers: Record<string, string> = {}) => sse(port, `/api/runs/${runId}/events`, { cookie: h.session.cookie, ...headers });
  const approvalIdOf = (events: { event: string; data: any }[]) => events.find((e) => e.event === "approval_required")!.data.approvalId as string;
  return { ...h, port, begin, stream, approvalIdOf };
}

describe("M5.5 live run events (SSE)", () => {
  it("streams snapshot -> live steps -> approval_required -> (human decision) -> resumed steps -> done; ids increase", async () => {
    const h = await live();
    const runId = await h.begin("S1", "on");
    const s = h.stream(runId);
    let stateAtFirstStep: string | null = null;
    await s.until((ev) => {
      if (stateAtFirstStep === null && ev.some((e) => e.event === "step")) stateAtFirstStep = h.ctx.registry.view(runId)!.state;
      return ev.some((e) => e.event === "approval_required");
    });
    // The first step arrived while the run was still executing: updates are live, not replayed after the fact.
    expect(stateAtFirstStep).toBe("running");
    expect(s.events[0]!.event).toBe("snapshot");
    const approval = s.events.find((e) => e.event === "approval_required")!.data;
    expect(approval).toMatchObject({ runId, tool: "send_email", status: "pending", ruleId: "A1", recipient: "requesting_user" });

    expect((await h.call("POST", `/api/approvals/${approval.approvalId}/decision`, { verdict: "approve" })).statusCode).toBe(200);
    await s.ended; // the server closes the stream after "done"
    const names = s.events.map((e) => e.event);
    expect(names.at(-1)).toBe("done");
    expect(names).toContain("decision");
    expect(names).toContain("audit");
    expect(names.filter((n) => n === "state").length).toBeGreaterThanOrEqual(2);
    const steps = s.events.filter((e) => e.event === "step").map((e) => [e.data.call, e.data.tool, e.data.status]);
    expect(steps).toEqual([["request", "read_file", "ok"], ["request", "send_email", "approval_required"], ["resume", "send_email", "ok"]]);
    const ids = s.events.map((e) => e.id!);
    for (let i = 1; i < ids.length; i++) expect(ids[i]!).toBeGreaterThan(ids[i - 1]!);
    expect(s.events.at(-1)!.data.run).toMatchObject({ runId, state: "done", legitimate: { result: true } });
    expect(s.raw()).toMatch(/^retry: 3000/);
  });

  it("Last-Event-ID resumes exactly after the last received event (no snapshot, no duplicates)", async () => {
    const h = await live();
    const runId = await h.begin("S1", "on");
    const first = h.stream(runId);
    await first.until((ev) => ev.some((e) => e.event === "approval_required"));
    first.stop();
    const lastId = first.events.at(-1)!.id!;
    const second = h.stream(runId, { "last-event-id": String(lastId) });
    await new Promise((r) => setTimeout(r, 50));
    expect(second.events).toEqual([]); // nothing missed yet
    await h.call("POST", `/api/approvals/${h.approvalIdOf(first.events)}/decision`, { verdict: "approve" });
    await second.ended;
    expect(second.events[0]!.id).toBe(lastId + 1);
    expect(second.events.some((e) => e.event === "snapshot")).toBe(false);
    expect(second.events.at(-1)!.event).toBe("done");
  });

  it("a Last-Event-ID that fell out of the bounded buffer gets a fresh snapshot instead", async () => {
    const h = await live({ registry: { maxEventsPerRun: 3 } });
    const runId = await h.begin("S2", "on");
    await h.ctx.registry.settled(runId);
    const s = h.stream(runId, { "last-event-id": "1" });
    await s.until((ev) => ev.length > 0);
    expect(s.events[0]!.event).toBe("snapshot");
    s.stop();
  });

  it("multiple subscribers each receive the run to completion", async () => {
    const h = await live();
    const runId = await h.begin("S4", "off");
    const a = h.stream(runId);
    const b = h.stream(runId);
    await Promise.all([a.ended, b.ended]);
    for (const s of [a, b]) {
      expect(s.events.at(-1)!.event).toBe("done");
      expect(s.events.at(-1)!.data.run.attack.result).toBe(true);
    }
  });

  it("disconnected clients are cleaned up; per-run subscriber limit is enforced (429)", async () => {
    const h = await live({ registry: { maxSubscribersPerRun: 1 } });
    const runId = await h.begin("S1", "on");
    const a = h.stream(runId);
    await a.until((ev) => ev.length > 0);
    expect(h.ctx.registry.subscriberCount()).toBe(1);
    const b = h.stream(runId);
    await b.ended;
    expect(b.status()).toBe(429);
    a.stop();
    for (let i = 0; i < 40 && h.ctx.registry.subscriberCount() !== 0; i++) await new Promise((r) => setTimeout(r, 10));
    expect(h.ctx.registry.subscriberCount()).toBe(0);
    const c = h.stream(runId);
    await c.until((ev) => ev.length > 0);
    expect(c.status()).toBe(200);
    c.stop();
  });

  it("a finished run streams its snapshot and closes", async () => {
    const h = await live();
    const runId = await h.begin("S3", "on");
    await h.ctx.registry.settled(runId);
    await h.call("POST", `/api/approvals/${(await h.call("GET", "/api/approvals")).json().approvals[0].approvalId}/decision`, { verdict: "reject" });
    await h.ctx.registry.settled(runId);
    const s = h.stream(runId);
    await s.ended;
    expect(s.events.map((e) => e.event)).toEqual(["snapshot"]);
    expect(s.events[0]!.data.run).toMatchObject({ runId, state: "done" });
  });

  it("failure after approval is streamed as a 'failed' event", async () => {
    let broken = false;
    const sessionStores = (st: Stores): Stores => ({
      ...st,
      approvals: { ...st.approvals, get: (id) => (broken ? (() => { throw new Error("SQLITE_IOERR"); })() : st.approvals.get(id)) },
    });
    const h = await live({ registry: { sessionStores } });
    const runId = await h.begin("S1", "on");
    const s = h.stream(runId);
    await s.until((ev) => ev.some((e) => e.event === "approval_required"));
    broken = true;
    await h.call("POST", `/api/approvals/${h.approvalIdOf(s.events)}/decision`, { verdict: "approve" });
    await s.ended;
    broken = false;
    expect(s.events.at(-1)).toMatchObject({ event: "failed", data: { run: { state: "halted", outbox: [] } } });
  });

  it("M7 regression: a gateway halt (audit write failure, fail-closed) is streamed as 'failed', not 'done'", async () => {
    const sessionStores = (st: Stores): Stores => ({
      ...st,
      audit: { ...st.audit, append: (e, now) => (e.kind === "outcome" ? (() => { throw new Error("disk full"); })() : st.audit.append(e, now)) },
    });
    const h = await live({ registry: { sessionStores } });
    const runId = await h.begin("S3", "off");
    const s = h.stream(runId);
    await s.ended;
    expect(s.events.at(-1)).toMatchObject({ event: "failed", data: { run: { state: "halted" } } });
    expect(s.events.at(-1)!.data.run.haltReason).toMatch(/unlogged/);
  });

  it("sends heartbeats while a run waits (interval injectable; 15 s by default)", async () => {
    const h = await live({ sseHeartbeatMs: 30 });
    const runId = await h.begin("S1", "on");
    const s = h.stream(runId);
    await s.until((ev) => ev.some((e) => e.event === "approval_required"));
    await new Promise((r) => setTimeout(r, 120));
    expect(s.raw().match(/^: ping$/gm)?.length ?? 0).toBeGreaterThanOrEqual(2);
    s.stop();
  });

  it("requires authentication; unknown runs are 404", async () => {
    const h = await live();
    const runId = await h.begin("S3", "off");
    const anon = h.stream(runId, { cookie: "" });
    await anon.ended;
    expect(anon.status()).toBe(401);
    const unknown = h.stream("run-00000000-0000-4000-8000-000000000000");
    await unknown.ended;
    expect(unknown.status()).toBe(404);
  });

  it.each([["S2", "off"], ["S2", "on"], ["S3", "off"], ["S4", "off"]] as const)("%s Shield %s: the stream never carries secrets, bodies, subjects or paths", async (id, mode) => {
    const h = await live();
    const runId = await h.begin(id, mode);
    const s = h.stream(runId);
    await s.until((ev) => ev.some((e) => e.event === "done" || e.event === "approval_required"));
    const pending = s.events.find((e) => e.event === "approval_required");
    if (pending) await h.call("POST", `/api/approvals/${pending.data.approvalId}/decision`, { verdict: "approve" });
    await s.ended;
    for (const f of FORBIDDEN) expect(s.raw()).not.toContain(f);
    expect(s.raw()).not.toContain(rt.dir);
    expect(s.raw()).not.toMatch(/"(?:sandboxDir|trace|request|args|body|subject|content|html|detail|evidence|to)"\s*:/);
  });
});
