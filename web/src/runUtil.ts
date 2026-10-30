import type { Decision, Run, Step } from "./types";

/** The decision row belonging to a step: decision rows appear in the same order as the steps of the same call kind. */
export function matchDecision(run: Run, s: Step): Decision | undefined {
  const kind = s.call === "resume" ? "re_decision" : "decision";
  const sameKind = run.steps.filter((x) => (x.call === "resume" ? "re_decision" : "decision") === kind && x.status !== "rejected");
  const idx = sameKind.indexOf(s);
  return idx >= 0 ? run.decisions.filter((d) => d.kind === kind)[idx] : undefined;
}

export const isLabRun = (run: Pick<Run, "scenario">) => run.scenario.id === "LAB" || run.scenario.id === "EMAIL";
