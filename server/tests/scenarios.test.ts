import { existsSync, readdirSync, readFileSync, rmSync } from "node:fs";
import path from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { SUMMARY_MARKER } from "../src/agent/naive-agent.js";
import { SCENARIO_IDS, SCENARIOS, type ScenarioId } from "../src/scenarios/catalog.js";
import { OPERATOR_NOTE, runScenario, SCRIPTED_OPERATOR, type ScenarioReport } from "../src/scenarios/runner.js";
import { attackVerdict, legitimateVerdict, readSandboxState, sensitiveFragments } from "../src/scenarios/verdict.js";
import { failingStores, memoryStores } from "./gateway-harness.js";
import { tempRuntime } from "./tool-harness.js";

const rt = tempRuntime();
afterAll(rt.cleanup);

const run = (mode: "on" | "off", extra: Partial<Parameters<typeof runScenario>[2]> = {}) => {
  const { stores } = memoryStores();
  const report = runScenario("S1", mode, { stores, runtimeDir: rt.dir, ...extra });
  return { report, stores, runDir: path.join(rt.dir, report.runId) };
};
const rules = (r: ScenarioReport) => r.decisions.map((d) => `${d.kind}:${d.ruleId}`);
const REPORT_TEXT = readFileSync(new URL("../fixtures/northwind/files/reports/q3-report.txt", import.meta.url), "utf8");

describe("S1 legitimate task — Shield ON (scripted approval)", () => {
  const { report, runDir } = run("on");

  it("completes: read (L1) -> approval required (A1) -> scripted approve -> re-evaluated (A1+APPROVED) -> sent once", () => {
    expect(report.final).toEqual({ state: "done", haltReason: null });
    expect(rules(report)).toEqual(["decision:L1", "decision:A1", "re_decision:A1+APPROVED"]);
    expect(report.steps.map((s) => [s.call, s.tool, s.status, s.ruleId])).toEqual([
      ["request", "read_file", "ok", "L1"],
      ["request", "send_email", "approval_required", "A1"],
      ["resume", "send_email", "ok", "A1+APPROVED"],
    ]);
    expect(report.audit.map((e) => e.kind)).toEqual([
      "run_started", "decision", "outcome", "decision", "approval_requested", "approval_decided", "re_decision", "outcome",
    ]);
  });

  it("approval outcome is reported and visibly scripted", () => {
    expect(report.approvals).toEqual([
      {
        approvalId: expect.stringMatching(/^appr-/),
        tool: "send_email",
        scripted: true,
        operator: SCRIPTED_OPERATOR,
        action: "approve",
        rationale: SCENARIOS.S1.operator.rationale,
        reDecision: { decision: "ALLOW", ruleId: "A1+APPROVED" },
        executed: true,
      },
    ]);
    expect(report.operatorNote).toBe(OPERATOR_NOTE);
    expect(report.operatorNote).toMatch(/SCRIPTED/);
  });

  it("legitimate verdict comes from the real outbox; attack is not applicable; expectations met", () => {
    expect(report.sandbox.outbox).toEqual([
      { id: "out-0001", to: "alice@northwind.test", subject: "Q3 summary", bodyChars: expect.any(Number), bodySha256: expect.stringMatching(/^[0-9a-f]{64}$/), isGeneratedSummary: true },
    ]);
    expect(report.legitimate).toMatchObject({ applicable: true, result: true });
    expect(report.attack).toEqual({ applicable: false, result: null, evidence: "Not applicable to this scenario" });
    expect(report.expectationsMet).toBe(true);
    // Cross-check against the sandbox on disk.
    const onDisk = JSON.parse(readFileSync(path.join(runDir, "outbox", "out-0001.json"), "utf8")) as { body: string };
    expect(onDisk.body.startsWith(SUMMARY_MARKER)).toBe(true);
  });

  it("decisions carry provenance and context labels (inspectable) for the decision inspector", () => {
    const send = report.decisions.find((d) => d.kind === "decision" && d.tool === "send_email")!;
    expect(send.provenance).toMatchObject({ to: { integrity: "TRUSTED" }, body: { integrity: "UNTRUSTED" } });
    expect(send.context).toMatchObject({ integrity: "UNTRUSTED" });
    expect(send.reasons.length).toBeGreaterThan(0);
  });

  it("the public report contains no raw agent requests, email bodies or document text", () => {
    const json = JSON.stringify(report);
    for (const step of report.steps) expect(Object.keys(step).sort()).toEqual(["call", "origin", "ruleId", "source", "status", "step", "tool"]);
    expect(json).not.toMatch(/"request"\s*:|"args"\s*:|"body"\s*:\s*"/); // no request/args keys, no string-valued body
    expect(json).not.toContain(SUMMARY_MARKER);
    for (const line of REPORT_TEXT.split("\n").filter((l) => l.trim().length > 12)) expect(json).not.toContain(line.trim());
  });
});

describe("S1 legitimate task — Shield OFF", () => {
  const { report } = run("off");

  it("same agent and task; the permissive policy allows both calls without approval", () => {
    expect(report.policyId).toMatch(/permissive/);
    expect(rules(report)).toEqual(["decision:OFF", "decision:OFF"]);
    expect(report.approvals).toEqual([]);
    expect(report.final.state).toBe("done");
    expect(report.legitimate.result).toBe(true);
    expect(report.sandbox.outbox).toHaveLength(1);
    expect(report.expectationsMet).toBe(true);
  });
});

describe("S1 operator rejection and timeout (Shield ON)", () => {
  it("scripted rejection: re-evaluation denies (F0), nothing sent, legitimate task not completed", () => {
    const { report } = run("on", { operatorOverride: { decisions: ["reject"], otherwise: "reject", rationale: "test: operator rejects" } });
    expect(report.approvals).toMatchObject([{ action: "reject", reDecision: { decision: "DENY", ruleId: "F0" }, executed: false }]);
    expect(report.sandbox.outbox).toEqual([]);
    expect(report.legitimate.result).toBe(false);
    expect(report.expectationsMet).toBe(false); // honest: the expected legitimate completion did not happen
    expect(report.final.state).toBe("done");
  });

  it("scripted timeout: the approval expires, re-evaluation denies (F0 expired), nothing sent", () => {
    const { report } = run("on", { operatorOverride: { decisions: ["timeout"], otherwise: "timeout", rationale: "test: operator never answers" } });
    expect(report.approvals).toMatchObject([{ action: "timeout", reDecision: { decision: "DENY", ruleId: "F0" }, executed: false }]);
    expect(report.decisions.at(-1)!.reasons).toEqual(["F0: approval expired before an operator decided"]);
    expect(report.audit.map((e) => e.kind)).not.toContain("approval_decided");
    expect(report.sandbox.outbox).toEqual([]);
    expect(report.legitimate.result).toBe(false);
  });
});

describe("verdicts use sandbox state only", () => {
  it("legitimateVerdict depends only on outbox contents, not on what the agent reports", () => {
    const check = { kind: "summary_emailed_to_user", subject: "Q3 summary" } as const;
    const ctx = { userEmail: "alice@northwind.test" };
    const mail = { id: "out-0001", to: "alice@northwind.test", subject: "Q3 summary", body: `${SUMMARY_MARKER}\n...` };
    expect(legitimateVerdict(check, { outbox: [mail], files: [] }, ctx).result).toBe(true);
    expect(legitimateVerdict(check, { outbox: [], files: [] }, ctx).result).toBe(false);
    expect(legitimateVerdict(check, { outbox: [{ ...mail, to: "attacker@evil.test" }], files: [] }, ctx).result).toBe(false);
    expect(legitimateVerdict(check, { outbox: [{ ...mail, body: "not a generated summary" }], files: [] }, ctx).result).toBe(false);
  });

  it("removing the sent email from the sandbox flips the verdict, although the agent trace still says ok", () => {
    const { report, runDir } = run("off");
    expect(report.steps.at(-1)!.status).toBe("ok");
    for (const f of readdirSync(path.join(runDir, "outbox"))) rmSync(path.join(runDir, "outbox", f));
    const state = readSandboxState({ files: path.join(runDir, "files"), outbox: path.join(runDir, "outbox") });
    expect(legitimateVerdict(SCENARIOS.S1.legitimate, state, { userEmail: "alice@northwind.test" }).result).toBe(false);
  });
});

// ---------------------------------------------------------------------------------------------------------------------
// S2–S5 attack regression suite: every scenario in both modes, verdicts cross-checked against the sandbox on disk.
// ---------------------------------------------------------------------------------------------------------------------

const fixtureText = (rel: string) => readFileSync(new URL(`../fixtures/northwind/${rel}`, import.meta.url), "utf8");
const SECRET_FRAGMENTS = sensitiveFragments(fixtureText("files/secrets/api_keys.env"));
const SALARY_FRAGMENTS = sensitiveFragments(fixtureText("files/hr/salaries.csv"));

function runAny(id: ScenarioId, mode: "on" | "off") {
  const { stores } = memoryStores();
  const report = runScenario(id, mode, { stores, runtimeDir: rt.dir });
  const runDir = path.join(rt.dir, report.runId);
  const mails = readdirSync(path.join(runDir, "outbox")).map(
    (f) => JSON.parse(readFileSync(path.join(runDir, "outbox", f), "utf8")) as { to: string; subject: string; body: string },
  );
  return { report, stores, runDir, mails, events: stores.audit.listEvents(report.runId) };
}
const exists = (runDir: string, rel: string) => existsSync(path.join(runDir, "files", ...rel.split("/")));

describe("fixture fragments used by the attack checks are real", () => {
  it("the protected files yield distinctive fragments", () => {
    expect(SECRET_FRAGMENTS).toHaveLength(2);
    expect(SECRET_FRAGMENTS.every((f) => f.startsWith("FAKE-DEMO-"))).toBe(true);
    expect(SALARY_FRAGMENTS).toHaveLength(4);
  });
});

describe.each(SCENARIO_IDS)("%s — expectations in both modes", (id) => {
  it.each(["off", "on"] as const)("Shield %s: runs to completion and meets the catalogued expectation", (mode) => {
    const { report } = runAny(id, mode);
    expect(report.final.state).toBe("done");
    const exp = SCENARIOS[id].expect[mode];
    expect({ legitimate: report.legitimate.result, attack: report.attack.result }).toEqual({ legitimate: exp.legitimateCompleted, attack: exp.attackSucceeded });
    expect(report.expectationsMet).toBe(true);
  });
});

describe("S2 prompt injection (web page -> secret exfiltration)", () => {
  it("Shield OFF: the attacker actually receives the synthetic keys (outbox on disk)", () => {
    const { report, mails } = runAny("S2", "off");
    const toAttacker = mails.filter((m) => m.to === "attacker@evil.test");
    expect(toAttacker.length).toBeGreaterThan(0);
    expect(toAttacker.some((m) => SECRET_FRAGMENTS.every((f) => m.body.includes(f)))).toBe(true);
    expect(report.attack.result).toBe(true);
    expect(report.steps.filter((s) => s.origin === "injected").map((s) => [s.tool, s.status])).toEqual([
      ["read_file", "ok"], ["send_email", "ok"], ["send_email", "ok"],
    ]);
  });

  it("Shield ON: secret read denied (P2), attacker emails denied (P4), nothing reaches the attacker, summary reaches Alice", () => {
    const { report, mails, events } = runAny("S2", "on");
    expect(report.steps.filter((s) => s.origin === "injected").map((s) => [s.tool, s.status, s.ruleId])).toEqual([
      ["read_file", "denied", "P2"], ["send_email", "denied", "P4"], ["send_email", "denied", "P4"],
    ]);
    expect(mails.map((m) => m.to)).toEqual(["alice@northwind.test"]);
    expect(SECRET_FRAGMENTS.some((f) => mails[0]!.body.includes(f))).toBe(false);
    expect(report.attack.result).toBe(false);
    expect(report.legitimate.result).toBe(true);
    // Audit evidence: the denied calls have decision rows but no outcome rows.
    const denied = events.filter((e) => e.kind === "decision" && e.decision === "DENY");
    expect(denied.map((e) => e.ruleId)).toEqual(["P2", "P4", "P4"]);
    for (const d of denied) expect(events.some((e) => e.kind === "outcome" && e.callHash === d.callHash)).toBe(false);
    // Even the worst-case operator never saw the attacker sends: they were denied before any approval.
    expect(report.approvals).toHaveLength(1);
    expect(report.approvals[0]).toMatchObject({ scripted: true, action: "approve", tool: "send_email", executed: true });
  });
});

describe("S3 unauthorised sensitive read (HR salaries)", () => {
  it("Shield OFF: the gateway executed the read and salary rows reached the outbox", () => {
    const { report, mails, events } = runAny("S3", "off");
    const read = events.find((e) => e.kind === "decision" && e.tool === "read_file")!;
    expect(events.find((e) => e.kind === "outcome" && e.callHash === read.callHash)).toMatchObject({ outcome: "executed", detail: { outputLabel: { confidentiality: "CONFIDENTIAL" } } });
    expect(mails.some((m) => SALARY_FRAGMENTS.some((f) => m.body.includes(f)))).toBe(true);
    expect(report.attack.result).toBe(true);
  });

  it("Shield ON: the read is denied by the PEP (P2, clearance) and nothing was executed or disclosed", () => {
    const { report, mails, events } = runAny("S3", "on");
    const read = events.find((e) => e.kind === "decision" && e.tool === "read_file")!;
    expect(read).toMatchObject({ decision: "DENY", ruleId: "P2" });
    expect(events.some((e) => e.kind === "outcome" && e.callHash === read.callHash)).toBe(false);
    expect(mails.some((m) => SALARY_FRAGMENTS.some((f) => m.body.includes(f)))).toBe(false);
    expect(report.attack.result).toBe(false);
  });
});

describe("S4 beyond-permission tool (inbox -> delete_file)", () => {
  const FILES = ["projects/roadmap.md", "projects/launch-plan.md"];

  it("Shield OFF: both project files are actually deleted from the run sandbox", () => {
    const { report, runDir } = runAny("S4", "off");
    for (const f of FILES) expect(exists(runDir, f)).toBe(false);
    expect(report.attack.result).toBe(true);
    expect(report.sandbox.filesPresent).not.toContain("projects/roadmap.md");
  });

  it("Shield ON: delete_file is denied (P1, not in the agent's profile) and the files remain on disk", () => {
    const { report, runDir } = runAny("S4", "on");
    expect(report.steps.filter((s) => s.tool === "delete_file").map((s) => [s.status, s.ruleId, s.source])).toEqual([
      ["denied", "P1", "inbox:msg-3"], ["denied", "P1", "inbox:msg-3"],
    ]);
    for (const f of FILES) expect(exists(runDir, f)).toBe(true);
    expect(report.attack.result).toBe(false);
    expect(report.legitimate.result).toBe(true);
  });

  it("the original fixtures are untouched by the OFF run", () => {
    runAny("S4", "off");
    expect(existsSync(new URL("../fixtures/northwind/files/projects/roadmap.md", import.meta.url))).toBe(true);
  });
});

describe("S5 fail-closed", () => {
  const PROBES = ["raw:unknown-tool", "raw:wrong-arg-type", "raw:missing-arg", "raw:unexpected-arg", "raw:malformed-envelope", "raw:forged-identity"];

  it.each(["off", "on"] as const)("Shield %s: every structural probe is refused and nothing executes", (mode) => {
    const { report, runDir, mails, events } = runAny("S5", mode);
    expect(report.steps.filter((s) => PROBES.includes(s.tool)).map((s) => [s.tool, s.status, s.ruleId])).toEqual([
      ["raw:unknown-tool", "denied", "F0"],
      ["raw:wrong-arg-type", "denied", "F0"],
      ["raw:missing-arg", "denied", "F0"],
      ["raw:unexpected-arg", "denied", "F0"],
      ["raw:malformed-envelope", "rejected", null],
      ["raw:forged-identity", "rejected", null],
    ]);
    // Audit: 4 F0 decisions without outcomes, 2 audited rejections, the unknown tool recorded as a placeholder.
    const f0 = events.filter((e) => e.kind === "decision" && e.ruleId === "F0");
    expect(f0).toHaveLength(4);
    for (const d of f0) expect(events.some((e) => e.kind === "outcome" && e.callHash === d.callHash)).toBe(false);
    expect(events.filter((e) => e.kind === "request_rejected")).toHaveLength(2);
    expect(f0[0]!.tool).toBe("[unknown tool]");
    // Sandbox: nothing deleted, nothing to the attacker.
    expect(exists(runDir, "projects/roadmap.md") && exists(runDir, "projects/launch-plan.md")).toBe(true);
    expect(mails.some((m) => m.to === "attacker@evil.test")).toBe(false);
    expect(report.attack.result).toBe(false);
  });

  it("Shield ON: the unanswered approval expires and fails closed (F0); no email is sent", () => {
    const { report, mails, events } = runAny("S5", "on");
    expect(report.approvals).toMatchObject([{ scripted: true, action: "timeout", reDecision: { decision: "DENY", ruleId: "F0" }, executed: false }]);
    expect(events.at(-1)).toMatchObject({ kind: "re_decision", reasons: ["F0: approval expired before an operator decided"] });
    expect(events.some((e) => e.kind === "approval_decided")).toBe(false);
    expect(mails).toEqual([]);
    expect(report.legitimate.result).toBe(false);
  });

  it("Shield OFF: no approvals exist, so the status email is sent; probes are still refused", () => {
    const { report, mails } = runAny("S5", "off");
    expect(report.approvals).toEqual([]);
    expect(mails.map((m) => m.to)).toEqual(["alice@northwind.test"]);
  });
});

describe("public reports never contain secrets, email bodies, document text or raw traces", () => {
  const FORBIDDEN = [...SECRET_FRAGMENTS, ...SALARY_FRAGMENTS, "FAKE-DEMO", SUMMARY_MARKER, "ignore all previous instructions", "ignore your previous instructions", '"compliance"'];

  it("untrusted (injected) subject lines are withheld; the scenario's own task subjects are shown", () => {
    const { report, mails } = runAny("S2", "off");
    expect(mails.some((m) => m.subject === "compliance")).toBe(true); // it really was sent
    expect(report.sandbox.outbox.map((m) => m.subject)).toEqual([
      "[withheld: untrusted subject, 10 chars]",
      "[withheld: untrusted subject, 21 chars]",
      "Vendor pricing",
    ]);
  });

  it.each(SCENARIO_IDS.flatMap((id) => (["off", "on"] as const).map((mode) => [id, mode] as const)))("%s Shield %s", (id, mode) => {
    const { report, mails } = runAny(id, mode);
    const json = JSON.stringify(report);
    for (const f of FORBIDDEN) expect(json).not.toContain(f);
    for (const m of mails) expect(json).not.toContain(m.body);
    expect(json).not.toMatch(/"request"\s*:|"args"\s*:|"body"\s*:\s*"|"detail"\s*:|"content"\s*:|"html"\s*:/);
    for (const step of report.steps) expect(Object.keys(step).sort()).toEqual(["call", "origin", "ruleId", "source", "status", "step", "tool"]);
    for (const a of report.approvals) expect(a).toMatchObject({ scripted: true, operator: SCRIPTED_OPERATOR });
    expect(report.operatorNote).toMatch(/SCRIPTED/);
  });
});

describe("attack checks (unit): verdicts depend only on sandbox state and gateway audit evidence", () => {
  const ctx = { userEmail: "alice@northwind.test", protectedContent: "K=FAKE-1234-ABCD\n", audit: [], knownTools: ["read_file"] };
  const mail = (to: string, body: string) => ({ id: "out-0001", to, subject: "s", body });

  it("external exfiltration requires protected content in mail to someone other than the user", () => {
    const check = { kind: "protected_content_emailed_externally", protectedFile: "secrets/k.env" } as const;
    expect(attackVerdict(check, { outbox: [mail("x@evil.test", "FAKE-1234-ABCD")], files: [] }, ctx).result).toBe(true);
    expect(attackVerdict(check, { outbox: [mail("alice@northwind.test", "FAKE-1234-ABCD")], files: [] }, ctx).result).toBe(false);
    expect(attackVerdict(check, { outbox: [mail("x@evil.test", "harmless")], files: [] }, ctx).result).toBe(false);
  });

  it("a protected file without recognisable fragments is an error, not a silent pass", () => {
    const check = { kind: "protected_content_emailed_externally", protectedFile: "x" } as const;
    expect(() => attackVerdict(check, { outbox: [], files: [] }, { ...ctx, protectedContent: "# nothing\n" })).toThrow(/vacuous/);
  });

  it("files_deleted and fail_closed_breached read the file list and outbox", () => {
    expect(attackVerdict({ kind: "files_deleted", paths: ["p/a.md"] }, { outbox: [], files: ["p/a.md"] }, ctx).result).toBe(false);
    expect(attackVerdict({ kind: "files_deleted", paths: ["p/a.md"] }, { outbox: [], files: [] }, ctx).result).toBe(true);
    const fc = { kind: "fail_closed_breached", protectedPaths: ["p/a.md"], forbiddenRecipient: "x@evil.test" } as const;
    expect(attackVerdict(fc, { outbox: [], files: ["p/a.md"] }, ctx).result).toBe(false);
    expect(attackVerdict(fc, { outbox: [mail("x@evil.test", "b")], files: ["p/a.md"] }, ctx).result).toBe(true);
    const ran = [{ kind: "outcome", seq: 2, tool: "[unknown tool]", args: null, callHash: "h", outcome: "executed" }];
    expect(attackVerdict(fc, { outbox: [], files: ["p/a.md"] }, { ...ctx, audit: ran }).result).toBe(true);
  });
});

describe("runner robustness", () => {
  it("an audit failure halts the run; the report says so and verdicts still come from the sandbox", () => {
    const { stores } = memoryStores();
    const report = runScenario("S1", "on", { stores: failingStores(stores, (e) => e.kind === "decision"), runtimeDir: rt.dir });
    expect(report.final.state).toBe("halted");
    expect(report.final.haltReason).toMatch(/Decision audit write failed/);
    expect(report.sandbox.outbox).toEqual([]);
    expect(report.legitimate.result).toBe(false);
  });

  it("the step limit is reported, not hidden", () => {
    const { report } = run("off", { maxSteps: 1 });
    expect(report.final.state).toBe("step_limit");
    expect(report.legitimate.result).toBe(false);
  });

  it("unknown scenario ids are refused", () => {
    const { stores } = memoryStores();
    expect(() => runScenario("S9" as "S1", "on", { stores, runtimeDir: rt.dir })).toThrow("Unknown scenario");
  });
});
