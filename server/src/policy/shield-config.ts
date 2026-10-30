import { TOOL_MANIFESTS } from "./manifests.js";
import { AGENT_PROFILES, USERS } from "./profiles.js";
import { loadPolicy, type Policy, type PolicyLoadResult, type ShieldMode } from "./loader.js";

// Shield ON and OFF share the same registries (same tools, profiles, users). The only difference is
// which policy file the PEP enforces. A policy that fails to load yields `policy: null` -> every call DENY.
export interface ShieldConfig {
  readonly mode: ShieldMode;
  readonly policy: Policy | null;
  readonly policyError: string | null;
  readonly tools: typeof TOOL_MANIFESTS;
  readonly profiles: typeof AGENT_PROFILES;
  readonly users: typeof USERS;
}

const EXPECTED_POLICY_MODE: Record<ShieldMode, Policy["mode"]> = { on: "enforce", off: "permissive" };

export function loadShieldConfig(mode: ShieldMode, load: (m: ShieldMode) => PolicyLoadResult = loadPolicy): ShieldConfig {
  let result = load(mode);
  // Tamper check: a policy file edited to "permissive" must not silently disable Shield ON.
  if (result.ok && result.policy.mode !== EXPECTED_POLICY_MODE[mode]) {
    result = { ok: false, error: `Shield ${mode} requires a ${EXPECTED_POLICY_MODE[mode]} policy, got ${result.policy.mode}` };
  }
  return Object.freeze({
    mode,
    policy: result.ok ? result.policy : null,
    policyError: result.ok ? null : result.error,
    tools: TOOL_MANIFESTS,
    profiles: AGENT_PROFILES,
    users: USERS,
  });
}
