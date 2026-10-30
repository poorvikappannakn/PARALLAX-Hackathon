import { randomUUID } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { createRunSandbox } from "../src/sandbox/sandbox.js";
import { evaluate, type Decision, type ToolCallRequest } from "../src/shield/pep.js";
import type { Labeled } from "../src/shield/provenance.js";
import { createTicketAuthority } from "../src/shield/tickets.js";
import { createToolExecutor, type ToolResult } from "../src/tools/index.js";
import { call, env } from "./helpers.js";

// Test-only harness wiring PEP -> ticket -> executor. This is NOT the gateway (M3): no audit, no approvals.

export function tempRuntime(): { dir: string; cleanup: () => void } {
  const dir = mkdtempSync(path.join(tmpdir(), "agentshield-test-"));
  return { dir, cleanup: () => rmSync(dir, { recursive: true, force: true }) };
}

export function harness(mode: "on" | "off", runtimeDir: string, clock: () => number = Date.now) {
  const { issuer, redeemer } = createTicketAuthority({ clock });
  const executor = createToolExecutor(redeemer);
  const runId = `run-${randomUUID()}`;
  const sandbox = createRunSandbox(runId, { runtimeDir });
  const mk = (tool: string, args: Record<string, unknown>, over: Partial<ToolCallRequest> = {}) =>
    call(tool, args as Record<string, Labeled<unknown>>, { runId, ...over });

  function run(tool: string, args: Record<string, unknown>, over: Partial<ToolCallRequest> = {}): { decision: Decision; result: ToolResult | null } {
    const c = mk(tool, args, over);
    const decision = evaluate(c, env(mode));
    if (decision.decision !== "ALLOW") return { decision, result: null };
    return { decision, result: executor.execute(c, issuer.issue(decision, c), sandbox) };
  }

  return { issuer, redeemer, executor, sandbox, runId, run, mk };
}
