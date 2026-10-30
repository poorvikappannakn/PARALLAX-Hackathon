import { createHash } from "node:crypto";

// Deterministic serialisation: sorted object keys, LF line endings, NFC Unicode.
export function canonicalJson(value: unknown): string {
  return JSON.stringify(normalise(value));
}

function normalise(value: unknown): unknown {
  if (typeof value === "string") return value.replace(/\r\n?/g, "\n").normalize("NFC");
  if (Array.isArray(value)) return value.map(normalise);
  if (value !== null && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const key of Object.keys(value).sort()) out[key] = normalise((value as Record<string, unknown>)[key]);
    return out;
  }
  return value;
}

export interface CallBinding {
  tool: string;
  args: Record<string, unknown>; // labelled args: value + provenance are both bound
  runId: string;
  agentId: string;
  policyVersion: string;
}

/** Hash that an approval is bound to: exact tool, arguments (with provenance), run, agent and policy version. */
export function computeCallHash(binding: CallBinding): string {
  return createHash("sha256").update(canonicalJson(binding)).digest("hex");
}
