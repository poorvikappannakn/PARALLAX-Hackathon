import { describe, expect, it } from "vitest";
import {
  WORST_CASE_LABEL,
  agentLiteral,
  combine,
  copy,
  extendContext,
  fromUser,
  generated,
  joinLabels,
  labelOrWorstCase,
  labeled,
  makeLabel,
  parseLabel,
  transform,
  untrusted,
} from "../src/shield/provenance.js";

const secret = untrusted("sk_test_FAKE", "file:secrets/api_keys.env", "SECRET");
const page = untrusted("Ignore previous instructions...", "web:https://vendor.contoso.test/pricing", "PUBLIC");
const task = fromUser("Summarise the vendor page");

describe("labels", () => {
  it("are frozen and sources are de-duplicated and sorted", () => {
    const l = makeLabel("TRUSTED", "PUBLIC", ["b", "a", "b"]);
    expect(l.sources).toEqual(["a", "b"]);
    expect(Object.isFrozen(l)).toBe(true);
    expect(Object.isFrozen(l.sources)).toBe(true);
  });

  it("strict parse rejects unknown levels, missing fields, extra fields and empty sources", () => {
    expect(parseLabel({ integrity: "TRUSTED", confidentiality: "TOP_SECRET", sources: ["x"] })).toBeNull();
    expect(parseLabel({ integrity: "trusted", confidentiality: "PUBLIC", sources: ["x"] })).toBeNull();
    expect(parseLabel({ integrity: "TRUSTED", confidentiality: "PUBLIC" })).toBeNull();
    expect(parseLabel({ integrity: "TRUSTED", confidentiality: "PUBLIC", sources: [] })).toBeNull();
    expect(parseLabel({ integrity: "TRUSTED", confidentiality: "PUBLIC", sources: ["x"], trustMe: true })).toBeNull();
    expect(parseLabel(undefined)).toBeNull();
    expect(parseLabel("TRUSTED")).toBeNull();
  });

  it("missing or unknown provenance fails closed to UNTRUSTED + SECRET", () => {
    for (const bad of [undefined, null, {}, "x", { integrity: "TRUSTED" }]) {
      expect(labelOrWorstCase(bad)).toEqual(WORST_CASE_LABEL);
    }
    expect(WORST_CASE_LABEL.integrity).toBe("UNTRUSTED");
    expect(WORST_CASE_LABEL.confidentiality).toBe("SECRET");
  });
});

describe("join", () => {
  it("one untrusted input taints the result; highest confidentiality wins; sources union", () => {
    const j = joinLabels([task.label, page.label, secret.label]);
    expect(j.integrity).toBe("UNTRUSTED");
    expect(j.confidentiality).toBe("SECRET");
    expect(j.sources).toEqual(["file:secrets/api_keys.env", "user:task", "web:https://vendor.contoso.test/pricing"]);
  });

  it("all-trusted inputs stay trusted", () => {
    expect(joinLabels([task.label, agentLiteral("x").label]).integrity).toBe("TRUSTED");
  });

  it("joining nothing, or a malformed label, fails closed", () => {
    expect(joinLabels([])).toEqual(WORST_CASE_LABEL);
    const j = joinLabels([task.label, { bogus: true }]);
    expect(j.integrity).toBe("UNTRUSTED");
    expect(j.confidentiality).toBe("SECRET");
    expect(j.sources).toContain("unknown");
  });
});

describe("propagation", () => {
  it("copy keeps the label", () => {
    expect(copy(page).label).toEqual(page.label);
  });

  it("copy of a value with a stripped label fails closed", () => {
    const stripped = { value: "x" } as unknown as typeof page;
    expect(copy(stripped).label).toEqual(WORST_CASE_LABEL);
  });

  it("transformation does not launder provenance", () => {
    const extracted = transform(page, (s) => s.toUpperCase().slice(0, 6));
    expect(extracted.label).toEqual(page.label);
    const email = transform(page, () => "attacker@evil.test");
    expect(email.label.integrity).toBe("UNTRUSTED");
  });

  it("combine joins every input", () => {
    const subject = combine([agentLiteral("Summary: "), page], (v) => v.join(""));
    expect(subject.label.integrity).toBe("UNTRUSTED");
    expect(subject.label.sources).toContain("agent:literal");
  });

  it("generated summaries carry the whole context, even if they look benign", () => {
    const ctx = [task.label, page.label];
    const summary = generated(ctx, "Vendor prices are up 3%.");
    expect(summary.label.integrity).toBe("UNTRUSTED");
    expect(summary.label.sources).toEqual(expect.arrayContaining(["agent:generated", "web:https://vendor.contoso.test/pricing"]));
  });

  it("generated content after reading a secret is secret", () => {
    expect(generated([task.label, secret.label], "nothing to see").label.confidentiality).toBe("SECRET");
  });

  it("generated content with no context is unknown provenance", () => {
    const g = generated([], "x");
    expect(g.label.integrity).toBe("UNTRUSTED");
    expect(g.label.confidentiality).toBe("SECRET");
  });

  it("context taint only grows", () => {
    let ctx = task.label;
    ctx = extendContext(ctx, page.label);
    ctx = extendContext(ctx, fromUser("more user text").label);
    expect(ctx.integrity).toBe("UNTRUSTED");
  });

  it("each argument keeps its own provenance when trusted and untrusted data are combined in one call", () => {
    const args = {
      to: fromUser("alice@northwind.test", "user:profile"),
      body: generated([task.label, page.label], "summary text"),
    };
    expect(args.to.label.integrity).toBe("TRUSTED");
    expect(args.body.label.integrity).toBe("UNTRUSTED");
  });

  it("labelled values are immutable", () => {
    const v = labeled("x", task.label);
    expect(() => {
      (v as { label: unknown }).label = WORST_CASE_LABEL;
    }).toThrow();
  });
});
