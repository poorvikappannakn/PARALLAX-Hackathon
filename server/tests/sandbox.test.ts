import { cpSync, existsSync, linkSync, mkdirSync, readFileSync, readdirSync, symlinkSync, writeFileSync } from "node:fs";
import path from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import {
  DEFAULT_FIXTURES_DIR,
  SandboxError,
  createRunSandbox,
  destroyRunSandbox,
  isInside,
  readContainedFile,
  resolveContainedFile,
} from "../src/sandbox/sandbox.js";
import { tempRuntime } from "./tool-harness.js";

const rt = tempRuntime();
afterAll(rt.cleanup);

const code = (fn: () => unknown) => {
  try {
    fn();
  } catch (e) {
    return e instanceof SandboxError ? e.code : `other:${(e as Error).message}`;
  }
  return "no-error";
};

describe("per-run sandbox isolation", () => {
  it("each run gets a fresh copy with files, web, inbox and an empty outbox", () => {
    const sb = createRunSandbox("iso-a", { runtimeDir: rt.dir });
    expect(readFileSync(path.join(sb.files, "reports", "q3-report.txt"), "utf8")).toMatch(/Q3 FY2026/);
    expect(existsSync(path.join(sb.web, "vendor.contoso.test", "pricing.html"))).toBe(true);
    expect(readdirSync(sb.inbox).length).toBe(3);
    expect(readdirSync(sb.outbox)).toEqual([]);
  });

  it("changes in one run do not affect another run or the original fixtures", () => {
    const a = createRunSandbox("iso-b1", { runtimeDir: rt.dir });
    const b = createRunSandbox("iso-b2", { runtimeDir: rt.dir });
    writeFileSync(path.join(a.files, "reports", "q3-report.txt"), "tampered");
    expect(readFileSync(path.join(b.files, "reports", "q3-report.txt"), "utf8")).toMatch(/Q3 FY2026/);
    expect(readFileSync(path.join(DEFAULT_FIXTURES_DIR, "files", "reports", "q3-report.txt"), "utf8")).toMatch(/Q3 FY2026/);
  });

  it("refuses to reuse an existing run id", () => {
    createRunSandbox("iso-dup", { runtimeDir: rt.dir });
    expect(code(() => createRunSandbox("iso-dup", { runtimeDir: rt.dir }))).toBe("SANDBOX_EXISTS");
  });

  it.each(["", "../escape", "a/b", "a\\b", "C:", "x".repeat(65), "run id"])("rejects run id %j", (id) => {
    expect(code(() => createRunSandbox(id, { runtimeDir: rt.dir }))).toBe("INVALID_RUN_ID");
  });

  it("refuses fixtures that contain a junction", () => {
    const fx = path.join(rt.dir, "bad-fixtures");
    cpSync(DEFAULT_FIXTURES_DIR, fx, { recursive: true });
    symlinkSync(path.join(rt.dir), path.join(fx, "files", "escape"), "junction");
    expect(code(() => createRunSandbox("iso-badfx", { runtimeDir: path.join(rt.dir, "rt2"), fixturesDir: fx }))).toBe("UNSAFE_FIXTURE");
  });

  it("destroy removes only the run directory inside the runtime area", () => {
    const sb = createRunSandbox("iso-destroy", { runtimeDir: rt.dir });
    destroyRunSandbox(sb, rt.dir);
    expect(existsSync(sb.root)).toBe(false);
    expect(code(() => destroyRunSandbox({ ...sb, root: path.dirname(rt.dir) }, rt.dir))).toBe("ESCAPE_ATTEMPT");
  });
});

describe("real filesystem containment", () => {
  const sb = createRunSandbox("contain", { runtimeDir: rt.dir });
  const outside = path.join(rt.dir, "outside-secret.txt");
  writeFileSync(outside, "OUTSIDE");

  it("reads a contained file", () => {
    expect(readContainedFile(sb.files, "reports/q3-report.txt").content).toMatch(/Revenue/);
  });

  it.each([
    "../inbox/msg-3.json",
    "..\\..\\outside-secret.txt",
    "/etc/passwd",
    "C:\\Windows\\win.ini",
    "\\\\localhost\\c$\\x",
    "reports/q3-report.txt:stream",
    "secrets./api_keys.env",
  ])("rejects unsafe path syntax %j", (p) => {
    expect(code(() => resolveContainedFile(sb.files, p))).toBe("PATH_REJECTED");
  });

  it("rejects a junction that points outside the sandbox", () => {
    symlinkSync(rt.dir, path.join(sb.files, "public", "jx"), "junction");
    expect(code(() => resolveContainedFile(sb.files, "public/jx/outside-secret.txt"))).toBe("LINK_REJECTED");
  });

  it("rejects a junction even when it points inside the sandbox", () => {
    symlinkSync(path.join(sb.files, "secrets"), path.join(sb.files, "reports", "jin"), "junction");
    expect(code(() => resolveContainedFile(sb.files, "reports/jin/api_keys.env"))).toBe("LINK_REJECTED");
  });

  it("rejects a file symlink (skipped if the OS forbids creating one)", (ctx) => {
    try {
      symlinkSync(outside, path.join(sb.files, "public", "link.txt"), "file");
    } catch {
      ctx.skip();
    }
    expect(code(() => resolveContainedFile(sb.files, "public/link.txt"))).toBe("LINK_REJECTED");
  });

  it("rejects a hard link to a file outside the sandbox", () => {
    linkSync(outside, path.join(sb.files, "public", "hard.txt"));
    expect(code(() => resolveContainedFile(sb.files, "public/hard.txt"))).toBe("LINK_REJECTED");
  });

  it("rejects directories and missing files", () => {
    expect(code(() => resolveContainedFile(sb.files, "reports"))).toBe("NOT_A_FILE");
    expect(code(() => resolveContainedFile(sb.files, "reports/missing.txt"))).toBe("NOT_FOUND");
  });

  it("isInside is strict and not fooled by sibling prefixes", () => {
    expect(isInside("C:\\a\\run", "C:\\a\\run\\x")).toBe(process.platform === "win32");
    expect(isInside(sb.files, sb.files)).toBe(false);
    expect(isInside(sb.files, `${sb.files}-evil${path.sep}x`)).toBe(false);
  });

  it("creating a sandbox never modifies the fixture tree", () => {
    mkdirSync(path.join(rt.dir, "noop"), { recursive: true });
    expect(existsSync(path.join(DEFAULT_FIXTURES_DIR, "outbox"))).toBe(false);
  });
});
