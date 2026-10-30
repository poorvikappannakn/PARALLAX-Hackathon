import { z } from "zod";

// Provenance labels. Integrity says whether a value may carry authority (who chose it);
// confidentiality says how sensitive it is. Labels only ever become more restrictive.

export const INTEGRITY = ["TRUSTED", "UNTRUSTED"] as const;
export const CONFIDENTIALITY = ["PUBLIC", "INTERNAL", "CONFIDENTIAL", "SECRET"] as const;

export type Integrity = (typeof INTEGRITY)[number];
export type Confidentiality = (typeof CONFIDENTIALITY)[number];

export interface Label {
  readonly integrity: Integrity;
  readonly confidentiality: Confidentiality;
  readonly sources: readonly string[];
}

export interface Labeled<T> {
  readonly value: T;
  readonly label: Label;
}

export const UNKNOWN_SOURCE = "unknown";

export const labelSchema = z
  .object({
    integrity: z.enum(INTEGRITY),
    confidentiality: z.enum(CONFIDENTIALITY),
    sources: z.array(z.string().min(1).max(200)).min(1).max(100),
  })
  .strict();

export function makeLabel(
  integrity: Integrity,
  confidentiality: Confidentiality,
  sources: readonly string[],
): Label {
  const unique = [...new Set(sources)].sort();
  return Object.freeze({
    integrity,
    confidentiality,
    sources: Object.freeze(unique.length > 0 ? unique : [UNKNOWN_SOURCE]),
  });
}

// Missing or unknown provenance is treated as the worst case: attacker-controlled and maximally sensitive.
export const WORST_CASE_LABEL: Label = makeLabel("UNTRUSTED", "SECRET", [UNKNOWN_SOURCE]);

export function confidentialityRank(c: Confidentiality): number {
  return CONFIDENTIALITY.indexOf(c);
}

export function maxConfidentiality(a: Confidentiality, b: Confidentiality): Confidentiality {
  return confidentialityRank(a) >= confidentialityRank(b) ? a : b;
}

export function minConfidentiality(a: Confidentiality, b: Confidentiality): Confidentiality {
  return confidentialityRank(a) <= confidentialityRank(b) ? a : b;
}

/** Strict parse: returns null for anything that is not a well-formed label. */
export function parseLabel(raw: unknown): Label | null {
  const r = labelSchema.safeParse(raw);
  return r.success ? makeLabel(r.data.integrity, r.data.confidentiality, r.data.sources) : null;
}

/** Lenient parse for propagation: malformed or missing labels become WORST_CASE_LABEL. */
export function labelOrWorstCase(raw: unknown): Label {
  return parseLabel(raw) ?? WORST_CASE_LABEL;
}

/**
 * Join (least upper bound): one untrusted input taints the result; the highest confidentiality wins;
 * sources are unioned. Joining nothing is treated as unknown provenance (fail closed).
 */
export function joinLabels(labels: readonly unknown[]): Label {
  if (labels.length === 0) return WORST_CASE_LABEL;
  const parsed = labels.map(labelOrWorstCase);
  const integrity: Integrity = parsed.some((l) => l.integrity === "UNTRUSTED") ? "UNTRUSTED" : "TRUSTED";
  const confidentiality = parsed.reduce<Confidentiality>(
    (acc, l) => maxConfidentiality(acc, l.confidentiality),
    "PUBLIC",
  );
  return makeLabel(integrity, confidentiality, parsed.flatMap((l) => l.sources));
}

export function labeled<T>(value: T, label: Label): Labeled<T> {
  return Object.freeze({ value, label });
}

// ---- Origins -------------------------------------------------------------

/** Data supplied by the user (task text, profile fields). */
export function fromUser<T>(value: T, source = "user:task", confidentiality: Confidentiality = "INTERNAL"): Labeled<T> {
  return labeled(value, makeLabel("TRUSTED", confidentiality, [source]));
}

/** Constants written into the agent's own code. */
export function agentLiteral<T>(value: T): Labeled<T> {
  return labeled(value, makeLabel("TRUSTED", "PUBLIC", ["agent:literal"]));
}

/** Content arriving from outside the trust boundary (web, email, documents, tool output). */
export function untrusted<T>(value: T, source: string, confidentiality: Confidentiality): Labeled<T> {
  return labeled(value, makeLabel("UNTRUSTED", confidentiality, [source]));
}

// ---- Propagation ---------------------------------------------------------

/** Copy: the label travels unchanged with the value. */
export function copy<T>(x: Labeled<T>): Labeled<T> {
  return labeled(x.value, labelOrWorstCase(x?.label));
}

/** Single-input transformation (substring, regex extract, formatting): label inherited. */
export function transform<T, U>(x: Labeled<T>, fn: (v: T) => U): Labeled<U> {
  return labeled(fn(x.value), labelOrWorstCase(x?.label));
}

/** Multi-input combination: label is the join of all inputs. */
export function combine<U>(inputs: readonly Labeled<unknown>[], fn: (values: unknown[]) => U): Labeled<U> {
  return labeled(
    fn(inputs.map((i) => i.value)),
    joinLabels(inputs.map((i) => i?.label)),
  );
}

/**
 * Generated content (summaries, model output). We cannot prove a generator ignored any part of
 * its context, so the result carries the join of the entire context it was produced from.
 */
export function generated<U>(context: readonly unknown[], value: U, generator = "agent:generated"): Labeled<U> {
  const ctx = joinLabels(context);
  return labeled(value, makeLabel(ctx.integrity, ctx.confidentiality, [...ctx.sources, generator]));
}

/** Control-taint: the run's context label after the agent has read `read`. */
export function extendContext(context: unknown, read: unknown): Label {
  return joinLabels([context, read]);
}
