import { TOOL_MANIFESTS } from "../policy/manifests.js";
import { SandboxError, type RunSandbox } from "../sandbox/sandbox.js";
import { validateArgs } from "../shield/arg-schema.js";
import type { ToolCallRequest } from "../shield/pep.js";
import type { Labeled } from "../shield/provenance.js";
import type { TicketRedeemer } from "../shield/tickets.js";
import { TOOL_IMPLS } from "./impl.js";

// The tool executor: the single entry point to tool implementations. It holds only a ticket *redeemer*
// (it cannot issue tickets) and runs a tool only after redeeming a valid, single-use ticket for this exact call.
// Sandbox containment and argument validation apply in every shield mode.

export type ToolErrorCode =
  | "TICKET_REJECTED"
  | "SANDBOX_MISMATCH"
  | "UNKNOWN_TOOL"
  | "INVALID_ARGS"
  | SandboxError["code"]
  | "TOOL_ERROR";

export type ToolResult =
  | { ok: true; tool: string; output: Labeled<unknown> }
  | { ok: false; tool: string; code: ToolErrorCode; message: string };

export interface ToolExecutor {
  execute(call: ToolCallRequest, ticket: unknown, sandbox: RunSandbox): ToolResult;
}

const has = (o: object, k: string) => Object.prototype.hasOwnProperty.call(o, k);

export function createToolExecutor(redeemer: TicketRedeemer): ToolExecutor {
  return Object.freeze({
    execute(call: ToolCallRequest, ticket: unknown, sandbox: RunSandbox): ToolResult {
      const tool = String(call?.tool);
      const fail = (code: ToolErrorCode, message: string): ToolResult => ({ ok: false, tool, code, message });

      const redeemed = redeemer.redeem(ticket, call);
      if (!redeemed.ok) return fail("TICKET_REJECTED", `${redeemed.code}: ${redeemed.message}`);
      if (sandbox.runId !== call.runId) return fail("SANDBOX_MISMATCH", "Sandbox does not belong to this run");
      if (!has(TOOL_MANIFESTS, tool) || !has(TOOL_IMPLS, tool)) return fail("UNKNOWN_TOOL", `Unknown tool ${tool}`);

      const args = validateArgs(TOOL_MANIFESTS[tool]!, call.args);
      if (!args.ok) return fail("INVALID_ARGS", args.reason);

      try {
        return { ok: true, tool, output: TOOL_IMPLS[tool]!(args.values, args.labels, sandbox) };
      } catch (e) {
        if (e instanceof SandboxError) return fail(e.code, e.message);
        return fail("TOOL_ERROR", "Tool failed");
      }
    },
  });
}
