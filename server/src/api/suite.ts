import type { Stores } from "../audit/store.js";
import { SCENARIO_IDS, SCENARIOS, type ScenarioId } from "../scenarios/catalog.js";
import { runScenario } from "../scenarios/runner.js";
import { runView, type RunView, type VerdictView } from "./views.js";

// POST /api/suite (M5.6): the existing deterministic scripted runner (same as `npm run scenarios -- run all`) for every
// scenario in Shield OFF and ON, summarised from the explicit-allowlist runView() projection. No second engine.

export const SUITE_NOTE =
  "Deterministic simulation: a rule-based agent (not an LLM) acting on synthetic fixtures inside per-run sandboxes. " +
  "No real email, network or file actions occur. Approvals in the suite are made by a SCRIPTED operator.";

export interface SuiteSide {
  runId: string;
  state: string;
  legitimate: VerdictView;
  attack: VerdictView;
  expectationsMet: boolean;
  /** Calls the PEP denied, with the deciding rule (empty with the shield off). */
  denied: { tool: string; ruleId: string | null }[];
  approvals: { tool: string; action: string; result: string | null; executed: boolean }[];
  outbox: { total: number; external: number };
  protectedFiles: { path: string; present: boolean }[];
}

export interface SuiteResult {
  note: string;
  generatedAt: number;
  scenarios: { id: ScenarioId; title: string; category: string; off: SuiteSide; on: SuiteSide }[];
  totals: { runs: number; expectationsMet: number; attacksSucceededOff: number; attacksSucceededOn: number };
}

function side(v: RunView): SuiteSide {
  return {
    runId: v.runId,
    state: v.state,
    legitimate: v.legitimate,
    attack: v.attack,
    expectationsMet: v.expectationsMet,
    denied: v.decisions.filter((d) => d.kind === "decision" && d.decision === "DENY").map((d) => ({ tool: d.tool, ruleId: d.ruleId })),
    approvals: v.approvals.map((a) => ({ tool: a.tool, action: a.action, result: a.reDecision?.ruleId ?? null, executed: a.executed })),
    outbox: { total: v.outbox.length, external: v.outbox.filter((m) => m.recipient === "external").length },
    protectedFiles: v.protectedFiles,
  };
}

export function runSuite(stores: Stores, clock: () => number, runtimeDir?: string): SuiteResult {
  const run = (id: ScenarioId, mode: "on" | "off") => {
    const report = runScenario(id, mode, { stores, clock, ...(runtimeDir ? { runtimeDir } : {}) });
    return side(runView(report, stores.audit.listEvents(report.runId)));
  };
  const scenarios = SCENARIO_IDS.map((id) => {
    const s = SCENARIOS[id];
    return { id, title: s.title, category: s.category, off: run(id, "off"), on: run(id, "on") };
  });
  const sides = scenarios.flatMap((s) => [s.off, s.on]);
  return {
    note: SUITE_NOTE,
    generatedAt: clock(),
    scenarios,
    totals: {
      runs: sides.length,
      expectationsMet: sides.filter((x) => x.expectationsMet).length,
      attacksSucceededOff: scenarios.filter((s) => s.off.attack.result === true).length,
      attacksSucceededOn: scenarios.filter((s) => s.on.attack.result === true).length,
    },
  };
}
