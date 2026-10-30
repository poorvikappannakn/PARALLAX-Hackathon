import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { loadPolicyFile, parsePolicy } from "../src/policy/loader.js";
import { TOOL_MANIFESTS } from "../src/policy/manifests.js";
import { AGENT_PROFILES, USERS } from "../src/policy/profiles.js";
import { loadShieldConfig } from "../src/policy/shield-config.js";
import { RULE_IDS } from "../src/shield/rules.js";

const enforceYaml = readFileSync(new URL("../src/policy/policy.yaml", import.meta.url), "utf8");

describe("policy loading", () => {
  it("loads the enforce and permissive policies", () => {
    const on = loadShieldConfig("on");
    const off = loadShieldConfig("off");
    expect(on.policy?.mode).toBe("enforce");
    expect(on.policy?.policyVersion).toBe("agentshield-enforce@1.0.0");
    expect(off.policy?.mode).toBe("permissive");
    expect(on.policyError).toBeNull();
  });

  it("enforce policy lists every rule in the catalogue", () => {
    const r = parsePolicy(enforceYaml);
    expect(r.ok && r.policy.rules.map((x) => x.id).sort()).toEqual([...RULE_IDS].sort());
  });

  it("an enforce policy that drops a DENY rule fails to load", () => {
    const tampered = enforceYaml.split("\n").filter((l) => !l.includes("id: P4,")).join("\n");
    const r = parsePolicy(tampered);
    expect(r.ok).toBe(false);
  });

  it("an enforce policy that downgrades a DENY rule to ALLOW fails to load", () => {
    const tampered = enforceYaml.replace("{ id: P3,      decision: DENY", "{ id: P3,      decision: ALLOW");
    expect(parsePolicy(tampered).ok).toBe(false);
  });

  it.each([
    ["invalid YAML", "id: [unclosed"],
    ["empty document", ""],
    ["unknown mode", enforceYaml.replace("mode: enforce", "mode: yolo")],
    ["unknown field", enforceYaml + "\nbypass: true\n"],
    ["permissive with rules", enforceYaml.replace("mode: enforce", "mode: permissive")],
  ])("rejects %s", (_n, text) => {
    expect(parsePolicy(text).ok).toBe(false);
  });

  it("a missing policy file fails to load (and the config carries no policy)", () => {
    const r = loadPolicyFile("does-not-exist.yaml");
    expect(r.ok).toBe(false);
    const cfg = loadShieldConfig("on", () => r);
    expect(cfg.policy).toBeNull();
    expect(cfg.policyError).toMatch(/could not be read/);
  });

  it("an enforce policy may not disable the detector", () => {
    expect(parsePolicy(enforceYaml.replace("escalateThreshold: 50", "escalateThreshold: 101")).ok).toBe(false);
  });

  it("Shield ON refuses a policy file swapped to permissive mode (fails closed)", () => {
    const permissive = loadPolicyFile(new URL("../src/policy/policy.permissive.yaml", import.meta.url));
    const cfg = loadShieldConfig("on", () => permissive);
    expect(cfg.policy).toBeNull();
    expect(cfg.policyError).toMatch(/requires a enforce policy/);
  });

  it("loaded policies are deeply immutable", () => {
    const p = loadShieldConfig("on").policy!;
    expect(Object.isFrozen(p.detector)).toBe(true);
    expect(Object.isFrozen(p.rules)).toBe(true);
    expect(() => {
      (p.detector as { escalateThreshold: number }).escalateThreshold = 101;
    }).toThrow();
  });
});

describe("shield ON/OFF share everything except policy", () => {
  it("uses the same tool, profile and user registries", () => {
    const on = loadShieldConfig("on");
    const off = loadShieldConfig("off");
    expect(on.tools).toBe(off.tools);
    expect(on.profiles).toBe(off.profiles);
    expect(on.users).toBe(off.users);
    expect(on.policy?.id).not.toBe(off.policy?.id);
  });
});

describe("manifests and profiles", () => {
  it("every high-impact tool declares a target argument", () => {
    for (const m of Object.values(TOOL_MANIFESTS)) {
      if (m.impact === "HIGH") expect(Object.values(m.args).some((a) => a.role === "target")).toBe(true);
    }
  });

  it("read tools are low impact; send and destructive tools are high impact", () => {
    for (const m of Object.values(TOOL_MANIFESTS)) expect(m.impact).toBe(m.effect === "READ" ? "LOW" : "HIGH");
  });

  it("registries are immutable at runtime", () => {
    expect(Object.isFrozen(TOOL_MANIFESTS)).toBe(true);
    expect(Object.isFrozen(TOOL_MANIFESTS.send_email!.args)).toBe(true);
    expect(Object.isFrozen(AGENT_PROFILES["agent:research-assistant"]!.allowedTools)).toBe(true);
    expect(Object.isFrozen(USERS)).toBe(true);
  });

  it("profiles reference only known tools", () => {
    for (const p of Object.values(AGENT_PROFILES)) for (const t of p.allowedTools) expect(TOOL_MANIFESTS).toHaveProperty(t);
  });

  it("all identities use reserved .test domains", () => {
    for (const u of Object.values(USERS)) expect(u.email.endsWith(".test")).toBe(true);
    for (const p of Object.values(AGENT_PROFILES)) for (const h of p.urlAllowlist) expect(h.endsWith(".test")).toBe(true);
  });
});
