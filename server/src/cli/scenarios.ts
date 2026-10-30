import { pathToFileURL } from "node:url";
import { createStores } from "../audit/store.js";
import { openDatabase } from "../db/sqlite.js";
import { SCENARIO_IDS, SCENARIOS, type ScenarioId } from "../scenarios/catalog.js";
import { runScenario, type ScenarioReport } from "../scenarios/runner.js";
import type { Verdict } from "../scenarios/verdict.js";

// Scenario CLI (M4). Thin presentation layer over runScenario(): no policy or execution logic lives here.
// It prints only the sanitised ScenarioReport (never agent traces, email bodies, document contents or secrets).
//
//   npm run scenarios -- list
//   npm run scenarios -- run <S1..S5|all> [--mode on|off|both] [--json] [--db <file>]

export const USAGE = `AgentShield scenario runner (PARALLAX 2026 PS-01)

Usage:
  npm run scenarios -- list
  npm run scenarios -- run <S1|S2|S3|S4|S5|all> [--mode on|off|both] [--json] [--db <file>]

Options:
  --mode on|off|both   Shield mode(s) to run (default: both, OFF first)
  --json               Print the sanitised reports as JSON
  --db <file>          Persist runs and audit events to a SQLite file (default: in-memory)

The agent is a deterministic, rule-based simulation (NOT an LLM). Approvals are made by a SCRIPTED operator.
All actions happen inside a per-run sandbox copy of synthetic fixtures; no real network or email is used.`;

export type CliCommand =
  | { cmd: "help" }
  | { cmd: "list" }
  | { cmd: "run"; ids: ScenarioId[]; modes: ("on" | "off")[]; json: boolean; db: string | null };

export type ParseResult = { ok: true; command: CliCommand } | { ok: false; error: string };

const isScenarioId = (s: string): s is ScenarioId => (SCENARIO_IDS as readonly string[]).includes(s);

export function parseArgs(argv: readonly string[]): ParseResult {
  const [cmd, ...rest] = argv;
  if (cmd === undefined || cmd === "help" || cmd === "--help" || cmd === "-h") return { ok: true, command: { cmd: "help" } };
  if (cmd === "list") {
    return rest.length === 0 ? { ok: true, command: { cmd: "list" } } : { ok: false, error: "'list' takes no arguments" };
  }
  if (cmd !== "run") return { ok: false, error: `Unknown command. Use 'list' or 'run'.` };

  let target: string | null = null;
  let mode: string = "both";
  let json = false;
  let db: string | null = null;
  for (let i = 0; i < rest.length; i++) {
    const a = rest[i]!;
    if (a === "--json") json = true;
    else if (a === "--mode" || a === "--db") {
      const v = rest[++i];
      if (v === undefined || v.startsWith("--")) return { ok: false, error: `${a} requires a value` };
      if (a === "--mode") mode = v.toLowerCase();
      else db = v;
    } else if (a.startsWith("--")) return { ok: false, error: "Unknown option" };
    else if (target === null) target = a;
    else return { ok: false, error: "Only one scenario id (or 'all') may be given" };
  }
  if (target === null) return { ok: false, error: "Missing scenario id (S1..S5 or 'all')" };
  const upper = target.toUpperCase();
  const ids = upper === "ALL" ? [...SCENARIO_IDS] : isScenarioId(upper) ? [upper] : null;
  if (!ids) return { ok: false, error: `Unknown scenario id. Valid ids: ${SCENARIO_IDS.join(", ")}, all` };
  const modes = mode === "both" ? (["off", "on"] as const) : mode === "on" || mode === "off" ? ([mode] as const) : null;
  if (!modes) return { ok: false, error: "--mode must be on, off or both" };
  return { ok: true, command: { cmd: "run", ids, modes: [...modes], json, db } };
}

export function formatList(): string {
  const lines = ["Available scenarios (deterministic simulated agent, not an LLM):", ""];
  for (const id of SCENARIO_IDS) {
    const s = SCENARIOS[id];
    const exp = (m: "on" | "off") => `legit=${fmtExpect(s.expect[m].legitimateCompleted)} attack=${fmtExpect(s.expect[m].attackSucceeded)}`;
    lines.push(`  ${id}  [${s.category}] ${s.title}`);
    lines.push(`      user ${s.userId} · agent ${s.agentId}`);
    lines.push(`      expected  OFF: ${exp("off")}  |  ON: ${exp("on")}`);
  }
  return lines.join("\n");
}

const fmtExpect = (v: boolean | null) => (v === null ? "n/a" : v ? "yes" : "no");
const pad = (s: string, n: number) => (s.length >= n ? s : s + " ".repeat(n - s.length));

function legitLabel(v: Verdict): string {
  return !v.applicable ? "n/a" : v.result ? "COMPLETED" : "NOT COMPLETED";
}
function attackLabel(v: Verdict): string {
  return !v.applicable ? "n/a" : v.result ? "SUCCEEDED" : "BLOCKED / NO EFFECT";
}

export function formatReport(r: ScenarioReport): string {
  const rule = "=".repeat(100);
  const out: string[] = [];
  out.push(rule);
  out.push(`${r.scenario.id} · ${r.scenario.title}`);
  out.push(`Shield ${r.mode.toUpperCase()} · policy ${r.policyId} · run ${r.runId}`);
  out.push(`User ${r.scenario.userId} · Agent ${r.scenario.agentId} (deterministic simulated agent — NOT an LLM)`);
  out.push(`Task: "${r.scenario.goal}"`);
  out.push(r.scenario.description);
  out.push(rule);

  out.push("RESULT");
  out.push(`  Legitimate task : ${legitLabel(r.legitimate)} — ${r.legitimate.evidence}`);
  out.push(`  Attack          : ${attackLabel(r.attack)} — ${r.attack.evidence}`);
  out.push(
    `  Expectations    : ${r.expectationsMet ? "MET" : "NOT MET"} (expected legit=${fmtExpect(r.expected.legitimateCompleted)}, attack=${fmtExpect(r.expected.attackSucceeded)})`,
  );
  out.push(`  Agent finished  : ${r.final.state}${r.final.haltReason ? ` — ${r.final.haltReason}` : ""}`);

  out.push("", "AGENT STEPS (sanitised: tool, origin and gateway result only — no arguments)");
  for (const s of r.steps) {
    out.push(
      `  ${pad(String(s.step), 3)}${pad(s.call, 8)}${pad(s.origin, 9)}${pad(s.tool, 24)}${pad(s.status, 18)}${pad(s.ruleId ?? "-", 14)}${s.source ? `from ${s.source}` : ""}`,
    );
  }

  out.push("", "POLICY DECISIONS (from the redacted audit log)");
  for (const d of r.decisions) {
    out.push(`  #${pad(String(d.seq), 4)}${pad(d.kind, 12)}${pad(d.tool ?? "-", 14)}${pad(d.decision ?? "-", 18)}${pad(d.ruleId ?? "-", 14)}risk ${d.risk ?? "-"}`);
    for (const reason of d.reasons) out.push(`        · ${reason}`);
  }

  out.push("", "APPROVALS (SCRIPTED operator — not a live human decision)");
  if (r.approvals.length === 0) out.push("  (none requested)");
  for (const a of r.approvals) {
    const re = a.reDecision ? `${a.reDecision.decision} ${a.reDecision.ruleId}` : "no re-decision";
    out.push(`  ${a.approvalId}  ${a.tool ?? "-"}: ${a.scripted ? "SCRIPTED" : "HUMAN"} ${a.action.toUpperCase()} by ${a.operator} → ${re} → ${a.executed ? "executed" : "not executed"}`);
    if (a.rationale) out.push(`        rationale: ${a.rationale}`);
  }

  out.push("", "AUDIT TRAIL (seq · kind · tool · decision/rule · outcome)");
  for (const e of r.audit) {
    out.push(`  ${pad(String(e.seq), 4)}${pad(e.kind, 20)}${pad(e.tool ?? "-", 16)}${pad([e.decision, e.ruleId].filter(Boolean).join(" ") || "-", 26)}${e.outcome ?? ""}`);
  }

  out.push("", "SANDBOX EVIDENCE (end state on disk; email bodies are never printed)");
  if (r.sandbox.outbox.length === 0) out.push("  Outbox: (empty)");
  for (const m of r.sandbox.outbox) {
    out.push(`  Outbox ${m.id} → ${m.to}  subject "${m.subject}"  (${m.bodyChars} chars, sha256 ${m.bodySha256.slice(0, 12)}…${m.isGeneratedSummary ? ", generated summary" : ""})`);
  }
  out.push(`  Files present: ${r.sandbox.filesPresent.join(", ") || "(none)"}`);
  out.push(`  Sandbox directory: ${r.sandboxDir}`);
  out.push("", `NOTE: ${r.operatorNote}`);
  return out.join("\n");
}

export function formatComparison(reports: readonly ScenarioReport[]): string {
  const lines = ["", "SUMMARY", `  ${pad("Scenario", 10)}${pad("Shield", 8)}${pad("Legitimate", 16)}${pad("Attack", 22)}Expectations`];
  for (const r of reports) {
    lines.push(`  ${pad(r.scenario.id, 10)}${pad(r.mode.toUpperCase(), 8)}${pad(legitLabel(r.legitimate), 16)}${pad(attackLabel(r.attack), 22)}${r.expectationsMet ? "MET" : "NOT MET"}`);
  }
  return lines.join("\n");
}

export interface CliIo {
  out: (s: string) => void;
  err: (s: string) => void;
  /** Override the sandbox runtime directory (tests). */
  runtimeDir?: string;
}

/** Returns the process exit code: 0 ok, 1 expectations not met or run error, 2 usage error. */
export function main(argv: readonly string[], io: CliIo): number {
  const parsed = parseArgs(argv);
  if (!parsed.ok) {
    io.err(`Error: ${parsed.error}\n\n${USAGE}`);
    return 2;
  }
  const c = parsed.command;
  if (c.cmd === "help") {
    io.out(USAGE);
    return 0;
  }
  if (c.cmd === "list") {
    io.out(formatList());
    return 0;
  }

  let db;
  try {
    db = openDatabase(c.db ?? ":memory:");
  } catch {
    io.err("Error: could not open the database file");
    return 1;
  }
  try {
    const stores = createStores(db);
    const reports: ScenarioReport[] = [];
    for (const id of c.ids) {
      for (const mode of c.modes) {
        const report = runScenario(id, mode, { stores, ...(io.runtimeDir ? { runtimeDir: io.runtimeDir } : {}) });
        reports.push(report);
        if (!c.json) io.out(formatReport(report));
      }
    }
    if (c.json) io.out(JSON.stringify(reports, null, 2));
    else if (reports.length > 1) io.out(formatComparison(reports));
    return reports.every((r) => r.expectationsMet) ? 0 : 1;
  } catch (e) {
    io.err(`Error: scenario run failed (${(e as Error).message})`);
    return 1;
  } finally {
    db.close();
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  process.exitCode = main(process.argv.slice(2), { out: (s) => console.log(s), err: (s) => console.error(s) });
}
