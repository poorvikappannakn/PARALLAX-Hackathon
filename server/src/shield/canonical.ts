import { createHash } from "node:crypto";
import { parseLabel } from "./provenance.js";

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
  userId: string;
  policyVersion: string;
}

/** Hash that approvals and execution tickets are bound to: exact tool, arguments (with provenance), run, agent, user and policy version. */
export function computeCallHash(binding: CallBinding): string {
  return createHash("sha256").update(canonicalJson(binding)).digest("hex");
}

/**
 * Computes the binding hash directly from a tool call request. Labels are normalised through parseLabel so
 * equivalent labels hash identically. Returns null if any argument is not a well-labelled value.
 */
export function bindCallHash(
  call: { tool: string; args: Record<string, unknown>; runId: string; agentId: string; userId: string },
  policyVersion: string,
): string | null {
  const args: Record<string, unknown> = {};
  for (const name of Object.keys(call.args)) {
    const arg = call.args[name];
    if (!arg || typeof arg !== "object") return null;
    const label = parseLabel((arg as { label?: unknown }).label);
    if (!label) return null;
    args[name] = { value: (arg as { value?: unknown }).value, label };
  }
  return computeCallHash({ tool: call.tool, args, runId: call.runId, agentId: call.agentId, userId: call.userId, policyVersion });
}
