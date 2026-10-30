import { readdirSync } from "node:fs";
import path from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { evaluate } from "../src/shield/pep.js";
import { createTicketAuthority, TicketError } from "../src/shield/tickets.js";
import { createToolExecutor } from "../src/tools/index.js";
import { createRunSandbox } from "../src/sandbox/sandbox.js";
import { approvalFor, env, legitEmail, user, web } from "./helpers.js";
import { harness, tempRuntime } from "./tool-harness.js";

const rt = tempRuntime();
afterAll(rt.cleanup);

const issueCode = (fn: () => unknown) => {
  try {
    fn();
  } catch (e) {
    return e instanceof TicketError ? e.code : "other";
  }
  return "issued";
};

describe("ticket issuance", () => {
  it("issues only for PEP-produced ALLOW decisions", () => {
    const h = harness("on", rt.dir);
    const c = h.mk("read_file", { path: user("reports/q3-report.txt") });
    const d = evaluate(c, env("on"));
    expect(issueCode(() => h.issuer.issue(d, c))).toBe("issued");
  });

  it("refuses a forged decision object, even one copied from a real ALLOW", () => {
    const h = harness("on", rt.dir);
    const c = h.mk("read_file", { path: user("reports/q3-report.txt") });
    const real = evaluate(c, env("on"));
    expect(issueCode(() => h.issuer.issue({ ...real }, c))).toBe("NOT_PEP_DECISION");
    expect(issueCode(() => h.issuer.issue(JSON.parse(JSON.stringify(real)), c))).toBe("NOT_PEP_DECISION");
  });

  it("refuses DENY and REQUIRE_APPROVAL decisions", () => {
    const h = harness("on", rt.dir);
    const denied = h.mk("read_file", { path: web("secrets/api_keys.env") });
    expect(issueCode(() => h.issuer.issue(evaluate(denied, env("on")), denied))).toBe("NOT_ALLOWED");
    const email = legitEmail({ runId: h.runId });
    expect(issueCode(() => h.issuer.issue(evaluate(email, env("on")), email))).toBe("NOT_ALLOWED");
  });

  it("refuses to issue for a different call than the decision covered", () => {
    const h = harness("on", rt.dir);
    const allowed = h.mk("read_file", { path: user("reports/q3-report.txt") });
    const other = h.mk("read_file", { path: user("public/northwind-overview.txt") });
    expect(issueCode(() => h.issuer.issue(evaluate(allowed, env("on")), other))).toBe("CALL_MISMATCH");
  });

  it("an approved A2 decision (ALLOW +APPROVED) can be ticketed and executed once", () => {
    const h = harness("on", rt.dir);
    const c = legitEmail({ runId: h.runId });
    const d = evaluate(c, env("on", { approval: approvalFor(c) }));
    expect(d.ruleId).toBe("A2+APPROVED");
    const r = h.executor.execute(c, h.issuer.issue(d, c), h.sandbox);
    expect(r.ok).toBe(true);
  });
});

describe("ticket redemption", () => {
  it("executes once and rejects reuse", () => {
    const h = harness("on", rt.dir);
    const c = h.mk("read_file", { path: user("reports/q3-report.txt") });
    const t = h.issuer.issue(evaluate(c, env("on")), c);
    expect(h.executor.execute(c, t, h.sandbox).ok).toBe(true);
    const again = h.executor.execute(c, t, h.sandbox);
    expect(again).toMatchObject({ ok: false, code: "TICKET_REJECTED" });
    expect(!again.ok && again.message).toMatch(/REUSED/);
  });

  it.each([
    ["no ticket", undefined],
    ["null", null],
    ["a string id", "ticket-1"],
  ])("rejects %s", (_n, ticket) => {
    const h = harness("on", rt.dir);
    const c = h.mk("read_file", { path: user("reports/q3-report.txt") });
    const r = h.executor.execute(c, ticket, h.sandbox);
    expect(r).toMatchObject({ ok: false, code: "TICKET_REJECTED" });
    expect(!r.ok && r.message).toMatch(/FORGED/);
  });

  it("rejects a structurally identical copy of a genuine ticket", () => {
    const h = harness("on", rt.dir);
    const c = h.mk("read_file", { path: user("reports/q3-report.txt") });
    const t = h.issuer.issue(evaluate(c, env("on")), c);
    const r = h.executor.execute(c, { ...t }, h.sandbox);
    expect(!r.ok && r.message).toMatch(/FORGED/);
  });

  it("rejects a ticket from a different authority", () => {
    const a = harness("on", rt.dir);
    const b = harness("on", rt.dir);
    const c = a.mk("read_file", { path: user("reports/q3-report.txt") });
    const t = a.issuer.issue(evaluate(c, env("on")), c);
    expect(b.executor.execute(c, t, a.sandbox)).toMatchObject({ ok: false, code: "TICKET_REJECTED" });
  });

  it("rejects a modified call (different path) and burns the ticket", () => {
    const h = harness("on", rt.dir);
    const c = h.mk("read_file", { path: user("reports/q3-report.txt") });
    const t = h.issuer.issue(evaluate(c, env("on")), c);
    const swapped = { ...c, args: { path: user("secrets/api_keys.env") } };
    const r = h.executor.execute(swapped, t, h.sandbox);
    expect(!r.ok && r.message).toMatch(/MODIFIED/);
    const retry = h.executor.execute(c, t, h.sandbox);
    expect(!retry.ok && retry.message).toMatch(/REUSED/);
  });

  it("rejects a call whose provenance changed (same value, different label)", () => {
    const h = harness("on", rt.dir);
    const c = h.mk("read_file", { path: user("reports/q3-report.txt") });
    const t = h.issuer.issue(evaluate(c, env("on")), c);
    const relabelled = { ...c, args: { path: web("reports/q3-report.txt") } };
    expect(h.executor.execute(relabelled, t, h.sandbox)).toMatchObject({ ok: false, code: "TICKET_REJECTED" });
  });

  it.each([
    ["tool", { tool: "delete_file" }],
    ["run", { runId: "run-other" }],
    ["agent", { agentId: "agent:ops-assistant" }],
    ["user", { userId: "user:hana" }],
  ])("rejects a ticket replayed against a different %s", (_n, over) => {
    const h = harness("on", rt.dir);
    const c = h.mk("read_file", { path: user("reports/q3-report.txt") });
    const t = h.issuer.issue(evaluate(c, env("on")), c);
    expect(h.executor.execute({ ...c, ...over }, t, h.sandbox)).toMatchObject({ ok: false, code: "TICKET_REJECTED" });
  });

  it("rejects an expired ticket", () => {
    let now = 1_000;
    const h = harness("on", rt.dir, () => now);
    const c = h.mk("read_file", { path: user("reports/q3-report.txt") });
    const t = h.issuer.issue(evaluate(c, env("on")), c);
    now += 30_000;
    const r = h.executor.execute(c, t, h.sandbox);
    expect(!r.ok && r.message).toMatch(/EXPIRED/);
  });

  it("rejects a valid ticket presented with another run's sandbox", () => {
    const h = harness("on", rt.dir);
    const other = createRunSandbox(`${h.runId}-x`, { runtimeDir: rt.dir });
    const c = h.mk("read_file", { path: user("reports/q3-report.txt") });
    const t = h.issuer.issue(evaluate(c, env("on")), c);
    expect(h.executor.execute(c, t, other)).toMatchObject({ ok: false, code: "SANDBOX_MISMATCH" });
  });

  it("the executor exposes no way to issue tickets", () => {
    const { redeemer } = createTicketAuthority();
    const ex = createToolExecutor(redeemer);
    expect(Object.keys(ex)).toEqual(["execute"]);
    expect(Object.keys(redeemer)).toEqual(["redeem"]);
  });

  it("nothing is written when a send_email ticket is rejected", () => {
    const h = harness("on", rt.dir);
    const c = legitEmail({ runId: h.runId });
    expect(h.executor.execute(c, undefined, h.sandbox).ok).toBe(false);
    expect(readdirSync(path.join(h.sandbox.outbox))).toEqual([]);
  });
});
