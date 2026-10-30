import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { parse as parseYaml } from "yaml";
import { z } from "zod";
import { RULE_CATALOG, RULE_IDS } from "../shield/rules.js";

export type ShieldMode = "on" | "off";

const policySchema = z
  .object({
    id: z.string().min(1).max(100),
    version: z.string().min(1).max(50),
    mode: z.enum(["enforce", "permissive"]),
    detector: z.object({ escalateThreshold: z.int().min(0).max(101) }).strict(),
    approval: z.object({ ttlSeconds: z.int().min(10).max(3600) }).strict(),
    rules: z.array(
      z
        .object({
          id: z.string(),
          decision: z.enum(["ALLOW", "DENY", "REQUIRE_APPROVAL"]),
          description: z.string().min(1),
        })
        .strict(),
    ),
  })
  .strict();

export type Policy = Readonly<z.infer<typeof policySchema> & { policyVersion: string }>;
export type PolicyLoadResult = { ok: true; policy: Policy } | { ok: false; error: string };

export function parsePolicy(text: string): PolicyLoadResult {
  let raw: unknown;
  try {
    raw = parseYaml(text);
  } catch (e) {
    return { ok: false, error: `Policy is not valid YAML: ${(e as Error).message}` };
  }
  const r = policySchema.safeParse(raw);
  if (!r.success) return { ok: false, error: `Policy failed validation: ${r.error.issues[0]?.message ?? "invalid"}` };
  const p = r.data;

  if (p.mode === "enforce") {
    if (p.detector.escalateThreshold > 100) {
      return { ok: false, error: "Enforce policy must not disable the injection detector (threshold > 100)" };
    }
    const listed = p.rules.map((rule) => rule.id).sort();
    const expected = [...RULE_IDS].sort();
    if (listed.length !== expected.length || listed.some((id, i) => id !== expected[i])) {
      return { ok: false, error: `Enforce policy must list exactly the rules ${expected.join(", ")}` };
    }
    for (const rule of p.rules) {
      const known = RULE_CATALOG[rule.id as keyof typeof RULE_CATALOG];
      if (known.decision !== rule.decision) {
        return { ok: false, error: `Rule ${rule.id} must have decision ${known.decision}` };
      }
    }
  } else if (p.rules.length !== 0) {
    return { ok: false, error: "Permissive policy must not declare rules" };
  }

  return { ok: true, policy: deepFreeze({ ...p, policyVersion: `${p.id}@${p.version}` }) };
}

// Loaded policy is immutable at runtime (e.g. the detector threshold cannot be lowered in memory).
function deepFreeze<T>(o: T): T {
  if (o && typeof o === "object") {
    for (const v of Object.values(o)) deepFreeze(v);
    Object.freeze(o);
  }
  return o;
}

const POLICY_FILES: Record<ShieldMode, URL> = {
  on: new URL("./policy.yaml", import.meta.url),
  off: new URL("./policy.permissive.yaml", import.meta.url),
};

export function loadPolicyFile(file: string | URL): PolicyLoadResult {
  try {
    return parsePolicy(readFileSync(typeof file === "string" ? file : fileURLToPath(file), "utf8"));
  } catch (e) {
    return { ok: false, error: `Policy could not be read: ${(e as Error).message}` };
  }
}

export function loadPolicy(mode: ShieldMode): PolicyLoadResult {
  return loadPolicyFile(POLICY_FILES[mode]);
}
