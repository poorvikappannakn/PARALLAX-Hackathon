import {
  closeSync,
  cpSync,
  existsSync,
  fstatSync,
  lstatSync,
  mkdirSync,
  openSync,
  readdirSync,
  readFileSync,
  realpathSync,
  rmSync,
} from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { normalizeSandboxPath } from "../shield/paths.js";

// Per-run sandbox: every run gets a fresh copy of the synthetic fixtures. Tools may only touch files inside
// their run's directories, verified with real filesystem resolution (lstat on every component + realpath).

export const DEFAULT_FIXTURES_DIR = fileURLToPath(new URL("../../fixtures/northwind", import.meta.url));
export const DEFAULT_RUNTIME_DIR = fileURLToPath(new URL("../../runtime/runs", import.meta.url));

const RUN_ID = /^[A-Za-z0-9-]{1,64}$/;
const MAX_FILE_BYTES = 1_000_000;

export type SandboxErrorCode =
  | "INVALID_RUN_ID"
  | "SANDBOX_EXISTS"
  | "UNSAFE_FIXTURE"
  | "PATH_REJECTED"
  | "ESCAPE_ATTEMPT"
  | "LINK_REJECTED"
  | "NOT_FOUND"
  | "NOT_A_FILE"
  | "FILE_TOO_LARGE"
  | "FILE_CHANGED";

export class SandboxError extends Error {
  readonly code: SandboxErrorCode;
  constructor(code: SandboxErrorCode, message: string) {
    super(message);
    this.code = code;
  }
}

export interface RunSandbox {
  readonly runId: string;
  readonly root: string;
  readonly files: string; // agent-visible documents (read_file / delete_file)
  readonly web: string; // local pages for fetch_web
  readonly inbox: string; // synthetic inbox for read_inbox
  readonly outbox: string; // fake outbox for send_email
}

export interface SandboxOptions {
  fixturesDir?: string;
  runtimeDir?: string;
}

/** True if `target` is strictly inside `base` (both absolute). Case-insensitive on Windows via path.relative. */
export function isInside(base: string, target: string): boolean {
  const rel = path.relative(base, target);
  if (rel === "" || path.isAbsolute(rel)) return false;
  return rel.split(path.sep)[0] !== "..";
}

/** Rejects symlinks/junctions and anything that is not a plain file or directory. */
function assertPlainTree(dir: string): void {
  for (const entry of readdirSync(dir)) {
    const p = path.join(dir, entry);
    const st = lstatSync(p);
    if (st.isSymbolicLink()) throw new SandboxError("UNSAFE_FIXTURE", `Link found in sandbox tree: ${entry}`);
    if (st.isDirectory()) assertPlainTree(p);
    else if (!st.isFile() || st.nlink > 1) throw new SandboxError("UNSAFE_FIXTURE", `Unexpected filesystem object: ${entry}`);
  }
}

export function createRunSandbox(runId: string, opts: SandboxOptions = {}): RunSandbox {
  if (typeof runId !== "string" || !RUN_ID.test(runId)) throw new SandboxError("INVALID_RUN_ID", "Invalid run id");
  const fixtures = realpathSync.native(opts.fixturesDir ?? DEFAULT_FIXTURES_DIR);
  assertPlainTree(fixtures);

  const runtimeDir = opts.runtimeDir ?? DEFAULT_RUNTIME_DIR;
  mkdirSync(runtimeDir, { recursive: true });
  const runtime = realpathSync.native(runtimeDir);
  const root = path.join(runtime, runId);
  if (existsSync(root)) throw new SandboxError("SANDBOX_EXISTS", `Sandbox for run ${runId} already exists`);

  cpSync(fixtures, root, { recursive: true, errorOnExist: true, force: false });
  for (const sub of ["files", "web", "inbox", "outbox"]) mkdirSync(path.join(root, sub), { recursive: true });
  assertPlainTree(root);

  return Object.freeze({
    runId,
    root,
    files: path.join(root, "files"),
    web: path.join(root, "web"),
    inbox: path.join(root, "inbox"),
    outbox: path.join(root, "outbox"),
  });
}

/** Removes a run sandbox, only if it really lives inside the runtime directory. */
export function destroyRunSandbox(sandbox: RunSandbox, runtimeDir: string = DEFAULT_RUNTIME_DIR): void {
  const runtime = realpathSync.native(runtimeDir);
  if (!isInside(runtime, sandbox.root) || path.dirname(sandbox.root) !== runtime) {
    throw new SandboxError("ESCAPE_ATTEMPT", "Refusing to remove a directory outside the runtime area");
  }
  rmSync(sandbox.root, { recursive: true, force: true });
}

/**
 * Resolves a sandbox-relative path to an existing regular file strictly inside `baseDir`.
 * Rejects: unsafe path syntax, any symlink/junction component, realpath escapes, non-files and hard links.
 */
export function resolveContainedFile(baseDir: string, relPath: unknown): { real: string; normalized: string } {
  const normalized = normalizeSandboxPath(relPath);
  if (!normalized) throw new SandboxError("PATH_REJECTED", "Path is not a safe sandbox-relative path");
  const base = realpathSync.native(baseDir);

  let current = base;
  for (const segment of normalized.split("/")) {
    current = path.join(current, segment);
    if (!isInside(base, current)) throw new SandboxError("ESCAPE_ATTEMPT", "Path escapes the sandbox");
    let st;
    try {
      st = lstatSync(current);
    } catch {
      throw new SandboxError("NOT_FOUND", `No such file: ${normalized}`);
    }
    if (st.isSymbolicLink()) throw new SandboxError("LINK_REJECTED", "Symbolic links and junctions are not allowed");
  }

  const real = realpathSync.native(current);
  if (!isInside(base, real)) throw new SandboxError("ESCAPE_ATTEMPT", "Path resolves outside the sandbox");
  const st = lstatSync(real);
  if (!st.isFile()) throw new SandboxError("NOT_A_FILE", `${normalized} is not a regular file`);
  if (st.nlink > 1) throw new SandboxError("LINK_REJECTED", "Hard-linked files are not allowed");
  return { real, normalized };
}

/** Reads a contained file, verifying the opened handle is the file that was checked (narrows TOCTOU). */
export function readContainedFile(baseDir: string, relPath: unknown): { normalized: string; content: string } {
  const { real, normalized } = resolveContainedFile(baseDir, relPath);
  const checked = lstatSync(real);
  const fd = openSync(real, "r");
  try {
    const opened = fstatSync(fd);
    if (opened.ino !== checked.ino || opened.dev !== checked.dev || !opened.isFile()) {
      throw new SandboxError("FILE_CHANGED", "File changed during access");
    }
    if (opened.size > MAX_FILE_BYTES) throw new SandboxError("FILE_TOO_LARGE", "File too large");
    return { normalized, content: readFileSync(fd, "utf8") };
  } finally {
    closeSync(fd);
  }
}

/** Resolves a directory that must be a real, link-free directory inside the sandbox root. */
export function containedDir(sandbox: RunSandbox, dir: string): string {
  const root = realpathSync.native(sandbox.root);
  const st = lstatSync(dir);
  if (st.isSymbolicLink() || !st.isDirectory()) throw new SandboxError("LINK_REJECTED", "Sandbox directory is not a plain directory");
  const real = realpathSync.native(dir);
  if (!isInside(root, real)) throw new SandboxError("ESCAPE_ATTEMPT", "Sandbox directory escapes the run root");
  return real;
}
