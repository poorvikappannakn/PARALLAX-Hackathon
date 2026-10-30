import { describe, expect, it } from "vitest";
import { classifyPath, emailContentLabel, fileContentLabel, webContentLabel } from "../src/policy/classification.js";
import { isWithinScopes, normalizeSandboxPath } from "../src/shield/paths.js";

describe("normalizeSandboxPath", () => {
  it("accepts plain relative paths and normalises separators and case", () => {
    expect(normalizeSandboxPath("reports/q3-report.txt")).toBe("reports/q3-report.txt");
    expect(normalizeSandboxPath("Reports\\Q3-Report.TXT")).toBe("reports/q3-report.txt");
    expect(normalizeSandboxPath("./reports//q3.txt")).toBe("reports/q3.txt");
  });

  it.each([
    ["parent traversal", "../secrets/api_keys.env"],
    ["nested traversal", "reports/../../etc/passwd"],
    ["backslash traversal", "reports\\..\\..\\Windows\\win.ini"],
    ["absolute posix", "/etc/passwd"],
    ["drive letter", "C:\\Windows\\win.ini"],
    ["drive-relative", "C:secrets.txt"],
    ["UNC", "\\\\attacker\\share\\x"],
    ["alternate data stream", "reports/q3.txt:hidden"],
    ["NUL byte", "reports/q3.txt\u0000.png"],
    ["trailing dot alias", "secrets./api_keys.env"],
    ["trailing space alias", "secrets /api_keys.env"],
    ["device name", "reports/CON"],
    ["device name with ext", "reports/nul.txt"],
    ["short name", "SECRE~1/api_keys.env"],
    ["empty", ""],
    ["only dots", "./."],
    ["too long", "a/".repeat(200)],
    ["not a string", 42],
  ])("rejects %s", (_name, input) => {
    expect(normalizeSandboxPath(input)).toBeNull();
  });

  it("scope check is prefix-based on directories", () => {
    expect(isWithinScopes("reports/q3.txt", ["reports/"])).toBe(true);
    expect(isWithinScopes("reports-old/q3.txt", ["reports/"])).toBe(false);
    expect(isWithinScopes("secrets/k.env", ["reports/", "hr/"])).toBe(false);
  });
});

describe("data classification", () => {
  it("classifies by longest prefix", () => {
    expect(classifyPath("public/brochure.txt")).toBe("PUBLIC");
    expect(classifyPath("reports/q3.txt")).toBe("INTERNAL");
    expect(classifyPath("hr/salaries.csv")).toBe("CONFIDENTIAL");
    expect(classifyPath("secrets/api_keys.env")).toBe("SECRET");
  });

  it("unclassified paths fail closed to SECRET", () => {
    expect(classifyPath("misc/notes.txt")).toBe("SECRET");
  });

  it("content read from the environment is always UNTRUSTED", () => {
    expect(fileContentLabel("reports/q3.txt")).toMatchObject({ integrity: "UNTRUSTED", confidentiality: "INTERNAL" });
    expect(webContentLabel("https://vendor.contoso.test/p")).toMatchObject({ integrity: "UNTRUSTED", confidentiality: "PUBLIC" });
    expect(emailContentLabel("msg-3")).toMatchObject({ integrity: "UNTRUSTED", sources: ["inbox:msg-3"] });
  });
});
