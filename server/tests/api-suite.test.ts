import { afterAll, describe, expect, it } from "vitest";
import { apiHarness, FORBIDDEN } from "./api-harness.js";
import { tempRuntime } from "./tool-harness.js";

const rt = tempRuntime();
afterAll(rt.cleanup);

describe("M5.6 POST /api/suite", () => {
  it("runs all scenarios in both modes with the existing scripted runner and returns a sanitised comparison", async () => {
    const h = await apiHarness(rt.dir);
    const res = await h.call("POST", "/api/suite", {});
    expect(res.statusCode).toBe(200);
    const suite = res.json() as any;
    expect(suite.note).toMatch(/not an LLM/);
    expect(suite.note).toMatch(/SCRIPTED/);
    expect(suite.totals).toEqual({ runs: 10, expectationsMet: 10, attacksSucceededOff: 3, attacksSucceededOn: 0 });
    const byId = Object.fromEntries(suite.scenarios.map((s: any) => [s.id, s]));
    expect(byId.S2.off).toMatchObject({ attack: { result: true }, denied: [], outbox: { total: 3, external: 2 } });
    expect(byId.S2.on).toMatchObject({ attack: { result: false }, outbox: { total: 1, external: 0 } });
    expect(byId.S2.on.denied).toEqual([{ tool: "read_file", ruleId: "P2" }, { tool: "send_email", ruleId: "P4" }, { tool: "send_email", ruleId: "P4" }]);
    expect(byId.S3.on.denied).toEqual([{ tool: "read_file", ruleId: "P2" }]);
    expect(byId.S4.on.denied).toEqual([{ tool: "delete_file", ruleId: "P1" }, { tool: "delete_file", ruleId: "P1" }]);
    expect(byId.S4.off.protectedFiles.every((f: any) => !f.present)).toBe(true);
    expect(byId.S4.on.protectedFiles.every((f: any) => f.present)).toBe(true);
    expect(byId.S5.on.approvals).toEqual([{ tool: "send_email", action: "timeout", result: "F0", executed: false }]);
    for (const f of FORBIDDEN) expect(res.body).not.toContain(f);
    expect(res.body).not.toContain(rt.dir);
    expect(res.body).not.toMatch(/"(?:sandboxDir|trace|request|args|body|subject|content|html|detail|evidence|to)"\s*:/);
    // Suite runs are scripted and are not added to the interactive registry.
    expect(h.ctx.registry.list()).toEqual([]);
  });

  it("requires session, CSRF and an empty JSON object", async () => {
    const h = await apiHarness(rt.dir);
    expect((await h.call("POST", "/api/suite", {}, { auth: null })).statusCode).toBe(401);
    expect((await h.call("POST", "/api/suite", {}, { auth: { cookie: h.session.cookie, csrf: "x" } })).statusCode).toBe(403);
    expect((await h.call("POST", "/api/suite", { scenarios: ["S1"] })).statusCode).toBe(400);
    expect((await h.call("POST", "/api/suite")).statusCode).toBe(415);
  });
});
