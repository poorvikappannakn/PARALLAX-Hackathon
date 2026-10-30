import { existsSync, readFileSync } from "node:fs";
import path from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { SUMMARY_MARKER } from "../src/agent/naive-agent.js";
import { formatList, main, parseArgs, USAGE } from "../src/cli/scenarios.js";
import { openDatabase } from "../src/db/sqlite.js";
import { createStores } from "../src/audit/store.js";
import { sensitiveFragments } from "../src/scenarios/verdict.js";
import { tempRuntime } from "./tool-harness.js";

const rt = tempRuntime();
afterAll(rt.cleanup);

function cli(...argv: string[]) {
  const out: string[] = [];
  const err: string[] = [];
  const code = main(argv, { out: (s) => out.push(s), err: (s) => err.push(s), runtimeDir: rt.dir });
  return { code, out: out.join("\n"), err: err.join("\n") };
}

const fixtureText = (rel: string) => readFileSync(new URL(`../fixtures/northwind/${rel}`, import.meta.url), "utf8");
const FORBIDDEN = [
  ...sensitiveFragments(fixtureText("files/secrets/api_keys.env")),
  ...sensitiveFragments(fixtureText("files/hr/salaries.csv")),
  "FAKE-DEMO",
  SUMMARY_MARKER,
  "ignore all previous instructions",
  "ignore your previous instructions",
  "Revenue: INR 48.2 crore",
  '"compliance"', // injected subject line: withheld from reports
];

describe("argument parsing", () => {
  it.each([
    [[], { cmd: "help" }],
    [["--help"], { cmd: "help" }],
    [["list"], { cmd: "list" }],
    [["run", "S2"], { cmd: "run", ids: ["S2"], modes: ["off", "on"], json: false, db: null }],
    [["run", "s3", "--mode", "ON"], { cmd: "run", ids: ["S3"], modes: ["on"], json: false, db: null }],
    [["run", "all", "--mode", "off", "--json"], { cmd: "run", ids: ["S1", "S2", "S3", "S4", "S5"], modes: ["off"], json: true, db: null }],
    [["run", "S1", "--db", "data/x.db"], { cmd: "run", ids: ["S1"], modes: ["off", "on"], json: false, db: "data/x.db" }],
  ])("%j", (argv, command) => {
    expect(parseArgs(argv)).toEqual({ ok: true, command });
  });

  it.each([
    [["frobnicate"], /Unknown command/],
    [["list", "extra"], /takes no arguments/],
    [["run"], /Missing scenario id/],
    [["run", "S9"], /Unknown scenario id/],
    [["run", "../../etc"], /Unknown scenario id/],
    [["run", "S1", "S2"], /Only one scenario id/],
    [["run", "S1", "--mode"], /--mode requires a value/],
    [["run", "S1", "--mode", "maybe"], /--mode must be on, off or both/],
    [["run", "S1", "--db"], /--db requires a value/],
    [["run", "S1", "--db", "--json"], /--db requires a value/],
    [["run", "S1", "--verbose"], /Unknown option/],
  ])("rejects %j", (argv, message) => {
    const r = parseArgs(argv);
    expect(r.ok).toBe(false);
    expect(!r.ok && r.error).toMatch(message);
  });

  it("error messages do not echo the offending argument", () => {
    const r = parseArgs(["run", "S1", "--token=FAKE-DEMO-SECRET"]);
    expect(!r.ok && r.error).not.toContain("FAKE-DEMO");
  });
});

describe("CLI commands", () => {
  it("help and list exit 0; list names every scenario and says the agent is not an LLM", () => {
    expect(cli()).toMatchObject({ code: 0, out: USAGE });
    const list = cli("list");
    expect(list.code).toBe(0);
    expect(list.out).toBe(formatList());
    for (const id of ["S1", "S2", "S3", "S4", "S5"]) expect(list.out).toContain(`  ${id}  [`);
    expect(list.out).toMatch(/not an LLM/);
  });

  it("invalid arguments exit 2 with a clean message and usage on stderr, nothing on stdout", () => {
    const r = cli("run", "S9");
    expect(r.code).toBe(2);
    expect(r.out).toBe("");
    expect(r.err).toMatch(/^Error: Unknown scenario id/);
    expect(r.err).toContain("Usage:");
  });

  it("run S2 (both modes) prints a judge-friendly report with all required sections", () => {
    const r = cli("run", "S2");
    expect(r.code).toBe(0);
    for (const section of ["RESULT", "AGENT STEPS", "POLICY DECISIONS", "APPROVALS (SCRIPTED operator", "AUDIT TRAIL", "SANDBOX EVIDENCE", "SUMMARY"]) {
      expect(r.out).toContain(section);
    }
    expect(r.out).toContain("Shield OFF");
    expect(r.out).toContain("Shield ON");
    expect(r.out).toMatch(/deterministic simulated agent — NOT an LLM/);
    expect(r.out).toMatch(/Attack {10}: SUCCEEDED/);
    expect(r.out).toMatch(/Attack {10}: BLOCKED/);
    expect(r.out).toMatch(/read_file +DENY +P2/);
    expect(r.out).toMatch(/send_email +DENY +P4/);
    expect(r.out).toMatch(/SCRIPTED APPROVE by operator:alice → ALLOW A1\+APPROVED → executed/);
    expect(r.out).toMatch(/S2 +OFF +COMPLETED +SUCCEEDED +MET/);
    expect(r.out).toMatch(/S2 +ON +COMPLETED +BLOCKED \/ NO EFFECT +MET/);
  });

  it("prints each run's sandbox directory, which exists on disk", () => {
    const r = cli("run", "S4", "--mode", "on");
    const dirs = [...r.out.matchAll(/Sandbox directory: (.+)$/gm)].map((m) => m[1]!.trim());
    expect(dirs).toHaveLength(1);
    expect(dirs[0]!.startsWith(rt.dir)).toBe(true);
    expect(existsSync(path.join(dirs[0]!, "files", "projects", "roadmap.md"))).toBe(true);
  });

  it("run all (both modes): every expectation met; output never contains secrets, bodies, document text or raw traces", () => {
    const r = cli("run", "all");
    expect(r.code).toBe(0);
    expect(r.err).toBe("");
    expect(r.out.match(/ MET$/gm)).toHaveLength(10);
    expect(r.out).not.toMatch(/NOT MET/);
    for (const f of FORBIDDEN) expect(r.out).not.toContain(f);
    expect(r.out).not.toMatch(/"request"|"args"|\{"value"|\{"ref"/);
  });

  it("--json prints the sanitised reports as parseable JSON with the same guarantees", () => {
    const r = cli("run", "all", "--json");
    expect(r.code).toBe(0);
    const reports = JSON.parse(r.out) as { scenario: { id: string }; mode: string; expectationsMet: boolean; sandboxDir: string }[];
    expect(reports.map((x) => `${x.scenario.id}:${x.mode}`)).toEqual(["S1", "S2", "S3", "S4", "S5"].flatMap((id) => [`${id}:off`, `${id}:on`]));
    expect(reports.every((x) => x.expectationsMet && typeof x.sandboxDir === "string")).toBe(true);
    for (const f of FORBIDDEN) expect(r.out).not.toContain(f);
  });

  it("--db persists the runs and audit trail to a SQLite file", () => {
    const file = path.join(rt.dir, "cli.db");
    expect(cli("run", "S3", "--mode", "on", "--db", file).code).toBe(0);
    const db = openDatabase(file);
    try {
      const stores = createStores(db);
      const runs = db.prepare("SELECT id, scenario_id, shield_mode, status FROM runs").all() as { id: string; scenario_id: string; shield_mode: string; status: string }[];
      expect(runs).toEqual([{ id: expect.stringMatching(/^run-/), scenario_id: "S3", shield_mode: "on", status: "completed" }]);
      expect(stores.audit.listEvents(runs[0]!.id).some((e) => e.ruleId === "P2")).toBe(true);
    } finally {
      db.close(); // Windows cannot delete open database files during cleanup
    }
  });

  it("an unopenable database path fails cleanly with exit 1", () => {
    const r = cli("run", "S1", "--db", rt.dir); // a directory, not a database file (missing parents are created on purpose)
    expect(r.code).toBe(1);
    expect(r.err).toBe("Error: could not open the database file");
  });
});
