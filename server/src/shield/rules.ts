export type DecisionKind = "ALLOW" | "DENY" | "REQUIRE_APPROVAL";

// The rule catalogue implemented by the PEP. The enforce policy file must list exactly these IDs,
// so a policy that drops a rule fails to load (and therefore fails closed).
export const RULE_CATALOG = Object.freeze({
  F0: { decision: "DENY", overridable: false, summary: "Fail closed: invalid call, provenance, policy, approval or evaluator error" },
  P1: { decision: "DENY", overridable: false, summary: "Tool not permitted for this agent profile" },
  P2: { decision: "DENY", overridable: false, summary: "Resource out of scope or above effective clearance" },
  P3: { decision: "DENY", overridable: false, summary: "Confidential or secret data flowing to an external send" },
  P4: { decision: "DENY", overridable: false, summary: "High-impact target chosen by untrusted content" },
  A1: { decision: "REQUIRE_APPROVAL", overridable: true, summary: "High-impact action influenced by untrusted content" },
  A2: { decision: "REQUIRE_APPROVAL", overridable: true, summary: "High-impact action needs user confirmation" },
  A3: { decision: "REQUIRE_APPROVAL", overridable: true, summary: "Injection signals while untrusted data steers the call" },
  L1: { decision: "ALLOW", overridable: false, summary: "Low-impact read within scope" },
  DEFAULT: { decision: "DENY", overridable: false, summary: "No rule allowed the call" },
} as const satisfies Record<string, { decision: DecisionKind; overridable: boolean; summary: string }>);

export type RuleId = keyof typeof RULE_CATALOG;
export const RULE_IDS = Object.freeze(Object.keys(RULE_CATALOG) as RuleId[]);

const SEVERITY: Record<DecisionKind, number> = { ALLOW: 0, REQUIRE_APPROVAL: 1, DENY: 2 };

/** Monotone combinator used for escalation: never returns a less strict decision. */
export function stricter(a: DecisionKind, b: DecisionKind): DecisionKind {
  return SEVERITY[a] >= SEVERITY[b] ? a : b;
}

export function severity(d: DecisionKind): number {
  return SEVERITY[d];
}
