import { describe, expect, it } from "vitest";
import type { PepEnv } from "../src/shield/pep.js";
import { ON, approvalFor, call, decide, env, user, web } from "./helpers.js";

// URL-risk-aware enforcement for fetch_web (U1 DENY on HIGH, U2 REQUIRE_APPROVAL on MEDIUM). The PEP re-computes the
// risk from the call's own URL with the offline analyzer; nothing is fetched or resolved.

const AGENT = "agent:research-assistant";
/** A profile that (wrongly) allow-lists look-alike hosts, to show U1 holds even where P2's allowlist would not. */
function withAllowlist(hosts: string[]): PepEnv {
  const p = ON.profiles[AGENT]!;
  return env("on", { profiles: { ...ON.profiles, [AGENT]: { ...p, urlAllowlist: [...p.urlAllowlist, ...hosts] } } });
}
const fetchCall = (url: string, label: "user" | "web" = "user") => call("fetch_web", { url: label === "user" ? user(url) : web(url) });

describe("PEP: URL risk for fetch_web", () => {
  it("HIGH-risk look-alikes are denied — by P2 (not allow-listed) and, independently, by U1 even if allow-listed", () => {
    for (const u of ["https://paypa1.com/verify", "https://amaz0n-support.in/"]) {
      expect(decide(fetchCall(u))).toMatchObject({ decision: "DENY", ruleId: "P2" }); // default allowlist
      const d = decide(fetchCall(u), withAllowlist(["paypa1.com", "amaz0n-support.in"]));
      expect(d).toMatchObject({ decision: "DENY", ruleId: "U1" });
      expect(d.reasons.join(" ")).toMatch(/URL risk HIGH \(typosquat-brand\)/);
    }
  });

  it("LOW-risk official domains keep the existing authorisation (L1 when allow-listed, P2 when not)", () => {
    for (const u of ["https://google.co.uk/", "https://paypal.co.uk/"]) {
      expect(decide(fetchCall(u))).toMatchObject({ decision: "DENY", ruleId: "P2" }); // unchanged: not on the allowlist
      const d = decide(fetchCall(u), withAllowlist(["google.co.uk", "paypal.co.uk"]));
      expect(d).toMatchObject({ decision: "ALLOW", ruleId: "L1" });
      expect(d.reasons.join(" ")).not.toMatch(/URL risk/);
    }
  });

  it("UNKNOWN-risk domain keeps the existing decision and carries an advisory warning", () => {
    const d = decide(fetchCall("https://vendor.contoso.test/pricing"));
    expect(d).toMatchObject({ decision: "ALLOW", ruleId: "L1" });
    expect(d.reasons).toContain("URL risk UNKNOWN: no indicators, domain not in the known list, no reputation data (advisory)");
  });

  it("MEDIUM risk on an allow-listed host requires approval (U2); a valid approval for this exact call allows it", () => {
    const c = fetchCall("https://vendor.contoso.test/paypal.com/login"); // brand only in the path => MEDIUM
    expect(decide(c)).toMatchObject({ decision: "REQUIRE_APPROVAL", ruleId: "U2" });
    expect(decide(c, env("on", { approval: approvalFor(c) }))).toMatchObject({ decision: "ALLOW", ruleId: "U2+APPROVED" });
    // The usual approval safeguards still apply.
    expect(decide(c, env("on", { approval: approvalFor(c, { used: true }) }))).toMatchObject({ decision: "DENY", ruleId: "F0" });
    expect(decide(c, env("on", { approval: approvalFor(c, { expiresAt: 0 }) }))).toMatchObject({ decision: "DENY", ruleId: "F0" });
  });

  it("HIGH risk cannot be overridden by an approval (DENY rules first)", () => {
    // Allow-listed host, but the redirect target is a typosquat => HIGH.
    const c = fetchCall("https://vendor.contoso.test/r?url=https://paypa1.com/verify");
    expect(decide(c)).toMatchObject({ decision: "DENY", ruleId: "U1" });
    const forged = { ...approvalFor(c), callHash: decide(c).callHash ?? "x" };
    const d = decide(c, env("on", { approval: forged }));
    expect(d).toMatchObject({ decision: "DENY", ruleId: "U1" });
    expect(d.reasons).toContain("An approval was supplied, but DENY rules cannot be overridden");
  });

  it("URL manipulation after assessment: the PEP judges the URL actually requested, and an approval does not transfer", () => {
    const benign = fetchCall("https://vendor.contoso.test/paypal.com/login"); // MEDIUM, approved by the operator
    const approval = approvalFor(benign);
    const swapped = fetchCall("https://vendor.contoso.test/r?url=https://paypa1.com/verify"); // HIGH
    expect(decide(swapped, env("on", { approval }))).toMatchObject({ decision: "DENY", ruleId: "U1" });
    // Swapped to another MEDIUM URL: the approval is bound to the original call hash, so it fails closed.
    const otherMedium = fetchCall("https://vendor.contoso.test/apple.com/login");
    expect(decide(otherMedium)).toMatchObject({ decision: "REQUIRE_APPROVAL", ruleId: "U2" });
    expect(decide(otherMedium, env("on", { approval }))).toMatchObject({ decision: "DENY", ruleId: "F0" });
  });

  it("existing rules are unchanged: P2 still applies to non-https / non-allow-listed URLs; untrusted URL provenance is still honoured", () => {
    expect(decide(fetchCall("http://vendor.contoso.test/pricing"))).toMatchObject({ decision: "DENY", ruleId: "P2" });
    expect(decide(fetchCall("https://vendor.contoso.test/pricing", "web")).decision).toBe("ALLOW"); // same as before: fetch is low-impact
  });

  it("Shield OFF keeps its documented permissive behaviour", () => {
    for (const u of ["https://paypa1.com/verify", "https://vendor.contoso.test/r?url=https://paypa1.com/verify"])
      expect(decide(fetchCall(u), env("off"))).toMatchObject({ decision: "ALLOW", ruleId: "OFF" });
  });

  it("unrelated tools are unaffected by URL risk", () => {
    const send = call("send_email", { to: user("alice@northwind.test"), subject: user("see https://paypa1.com"), body: user("https://paypa1.com/verify") });
    expect(decide(send).ruleId).toBe("A2");
  });
});
