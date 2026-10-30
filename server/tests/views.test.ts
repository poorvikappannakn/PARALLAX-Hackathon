import { readFileSync } from "node:fs";
import { afterAll, describe, expect, it } from "vitest";
import { SUMMARY_MARKER } from "../src/agent/naive-agent.js";
import { approvalView, runView, sanitizeLabel, sanitizeSource, sanitizeTool, scenarioListView } from "../src/api/views.js";
import { SCENARIO_IDS, SCENARIOS, type ScenarioId } from "../src/scenarios/catalog.js";
import { createScenarioSession, runScenario } from "../src/scenarios/runner.js";
import { sensitiveFragments } from "../src/scenarios/verdict.js";
import { memoryStores } from "./gateway-harness.js";
import { tempRuntime } from "./tool-harness.js";

const rt = tempRuntime();
afterAll(rt.cleanup);

const fixtureText = (rel: string) => readFileSync(new URL(`../fixtures/northwind/${rel}`, import.meta.url), "utf8");
const SUBJECTS = SCENARIO_IDS.flatMap((id) => SCENARIOS[id].task.steps.flatMap((s) => (s.op === "email_summary_to_user" ? [s.subject] : [])));
const FORBIDDEN = [
  ...sensitiveFragments(fixtureText("files/secrets/api_keys.env")),
  ...sensitiveFragments(fixtureText("files/hr/salaries.csv")),
  "FAKE-DEMO",
  SUMMARY_MARKER,
  "ignore all previous instructions",
  "ignore your previous instructions",
  "Revenue: INR 48.2 crore",
  "compliance",
  "Requested information",
  ...SUBJECTS, // even trusted task subjects are never shown (text equality is not provenance)
];
const FORBIDDEN_KEYS = /"(?:sandboxDir|trace|request|args|body|subject|content|html|detail|evidence|callHash|bodySha256|filesPresent|to)"\s*:/;

function view(id: ScenarioId, mode: "on" | "off") {
  const { stores } = memoryStores();
  const report = runScenario(id, mode, { stores, runtimeDir: rt.dir });
  return { report, view: runView(report, stores.audit.listEvents(report.runId)) };
}

describe("run view: explicit allowlist", () => {
  it("has exactly the approved top-level and nested keys", () => {
    const { view: v } = view("S2", "on");
    expect(Object.keys(v).sort()).toEqual(
      ["approvals", "attack", "audit", "decisions", "expected", "expectationNote", "expectationsMet", "haltReason", "legitimate", "mode", "operatorNote", "outbox", "policyId", "protectedFiles", "runId", "scenario", "state", "steps"].sort(),
    );
    expect(Object.keys(v.steps[0]!).sort()).toEqual(["call", "origin", "ruleId", "source", "status", "step", "tool"]);
    expect(Object.keys(v.decisions[0]!).sort()).toEqual(["approvalId", "arguments", "context", "decision", "kind", "reasons", "risk", "ruleId", "seq", "tool"]);
    expect(Object.keys(v.audit[0]!).sort()).toEqual(["approvalId", "decision", "kind", "outcome", "ruleId", "seq", "tool", "ts"]);
    expect(Object.keys(v.outbox[0]!).sort()).toEqual(["bodyChars", "generatedSummary", "id", "recipient"]);
    expect(Object.keys(v.attack).sort()).toEqual(["applicable", "check", "result"]);
    expect(Object.keys(v.approvals[0]!).sort()).toEqual(["action", "actor", "approvalId", "executed", "operator", "rationale", "reDecision", "tool"]);
  });

  it.each(SCENARIO_IDS.flatMap((id) => (["off", "on"] as const).map((m) => [id, m] as const)))(
    "%s Shield %s: no secrets, bodies, subjects, document text, paths, hashes or raw structures",
    (id, mode) => {
      const { report, view: v } = view(id, mode);
      const json = JSON.stringify(v);
      for (const f of FORBIDDEN) expect(json).not.toContain(f);
      expect(json).not.toMatch(FORBIDDEN_KEYS);
      expect(json).not.toContain(report.sandboxDir);
      expect(json).not.toContain(rt.dir);
      expect(json).not.toMatch(/runtime[\\/]runs|[A-Za-z]:\\\\|[0-9a-f]{64}/);
      expect(v.expectationsMet).toBe(report.expectationsMet);
    },
  );

  it("outbox recipients are categorised, never printed (S2 OFF: two external, one requesting user)", () => {
    const { view: v } = view("S2", "off");
    expect(v.outbox.map((m) => m.recipient)).toEqual(["external", "external", "requesting_user"]);
    // (The address does appear in the trusted catalogue description; the runtime projections never carry it.)
    expect(JSON.stringify({ outbox: v.outbox, steps: v.steps, decisions: v.decisions, audit: v.audit, attack: v.attack })).not.toContain("attacker@evil.test");
  });

  it("agent-chosen values echoed in PEP reasons are masked (S2 ON: the injected secret path)", () => {
    const { view: v } = view("S2", "on");
    const p2 = v.decisions.find((d) => d.ruleId === "P2")!;
    expect(p2.reasons.join(" ")).toContain("[untrusted value]");
    expect(p2.reasons.join(" ")).not.toContain("secrets/api_keys.env");
    expect(p2.arguments).toEqual([{ name: "path", integrity: "UNTRUSTED", confidentiality: "INTERNAL", sources: expect.arrayContaining(["agent:generated"]) }]);
  });

  it("trusted task values in reasons stay readable (S3 ON: the user's own requested path)", () => {
    const { view: v } = view("S3", "on");
    const p2 = v.decisions.find((d) => d.ruleId === "P2")!;
    expect(p2.reasons.join(" ")).toContain("hr/salaries.csv");
  });

  it("verdicts expose a fixed check description, not runtime evidence", () => {
    const { report, view: v } = view("S4", "off");
    expect(v.attack).toEqual({ applicable: true, result: true, check: "Any of projects/roadmap.md, projects/launch-plan.md missing from the sandbox" });
    expect(JSON.stringify(v)).not.toContain(report.attack.evidence);
    expect(v.protectedFiles).toEqual([{ path: "projects/roadmap.md", present: false }, { path: "projects/launch-plan.md", present: false }]);
  });
});

describe("sanitisers", () => {
  it("replace unrecognised provenance sources, tools and labels instead of echoing them", () => {
    expect(sanitizeSource("web:https://vendor.contoso.test/pricing")).toBe("web:https://vendor.contoso.test/pricing");
    expect(sanitizeSource("inbox:msg-3")).toBe("inbox:msg-3");
    expect(sanitizeSource("web:https://evil.example.com/x?k=FAKE-DEMO")).toBe("[unrecognised source]");
    expect(sanitizeSource("file:C:\\Users\\x")).toBe("[unrecognised source]");
    expect(sanitizeTool("send_email")).toBe("send_email");
    expect(sanitizeTool("raw:unknown-tool")).toBe("raw:unknown-tool");
    expect(sanitizeTool("nw_1001_asha_3200000")).toBe("[unrecognised tool]");
    expect(sanitizeLabel({ integrity: "TRUSTED!", confidentiality: "TOP", sources: ["x", "user:task"] })).toEqual({ integrity: "UNKNOWN", confidentiality: "UNKNOWN", sources: ["[unrecognised source]", "user:task"] });
    expect(sanitizeLabel("nope")).toBeNull();
  });
});

describe("scenario list and approval views", () => {
  it("scenario list exposes catalogue metadata only (no task steps, params, scripts or checks)", () => {
    const list = scenarioListView();
    expect(list.map((s) => s.id)).toEqual([...SCENARIO_IDS]);
    const json = JSON.stringify(list);
    expect(json).not.toMatch(/"(?:steps|params|operator|raw|request|attack|legitimate|task)"\s*:|shell_exec/);
    for (const s of SUBJECTS) expect(json).not.toContain(s);
  });

  it("pending approval view: rule, masked reasons, labels and recipient category; no argument values", () => {
    const { stores } = memoryStores();
    const session = createScenarioSession("S2", "on", { stores, runtimeDir: rt.dir, interactive: true });
    const r = session.start();
    if (!r.ok || r.status.state !== "waiting") throw new Error("expected waiting");
    const record = stores.approvals.get(r.status.approvalId)!;
    const v = approvalView(record, stores.audit.listEvents(session.runId), "alice@northwind.test");
    expect(v).toMatchObject({ approvalId: record.id, runId: session.runId, tool: "send_email", status: "pending", used: false, ruleId: "A1", recipient: "requesting_user" });
    expect(v.arguments.map((a) => [a.name, a.integrity])).toEqual([["to", "TRUSTED"], ["subject", "UNTRUSTED"], ["body", "UNTRUSTED"]]);
    const json = JSON.stringify(v);
    for (const f of FORBIDDEN) expect(json).not.toContain(f);
    expect(json).not.toContain("alice@northwind.test");
    expect(json).not.toMatch(FORBIDDEN_KEYS);
  });
});
