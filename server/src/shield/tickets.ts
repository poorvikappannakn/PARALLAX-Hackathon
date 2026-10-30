import { randomUUID } from "node:crypto";
import { bindCallHash } from "./canonical.js";
import { isPepDecision, type Decision, type ToolCallRequest } from "./pep.js";

// Execution tickets: the only way a tool may run. A ticket is issued for a PEP-produced ALLOW decision,
// bound to that decision's call hash (tool, labelled args, run, agent, user, policy version), expires quickly,
// and is consumed on first redemption. The authority is split into an issuer (held by the gateway) and a
// redeemer (held by the tool executor), so tools can never mint their own tickets.

export interface ExecutionTicket {
  readonly id: string;
  readonly tool: string;
  readonly runId: string;
  readonly agentId: string;
  readonly callHash: string;
  readonly policyVersion: string;
  readonly expiresAt: number;
}

export type TicketErrorCode =
  | "NOT_PEP_DECISION"
  | "NOT_ALLOWED"
  | "CALL_MISMATCH"
  | "FORGED"
  | "REUSED"
  | "EXPIRED"
  | "MODIFIED";

export class TicketError extends Error {
  readonly code: TicketErrorCode;
  constructor(code: TicketErrorCode, message: string) {
    super(message);
    this.code = code;
  }
}

export interface TicketIssuer {
  issue(decision: Decision, call: ToolCallRequest): ExecutionTicket;
}

export type RedeemResult = { ok: true } | { ok: false; code: TicketErrorCode; message: string };

export interface TicketRedeemer {
  redeem(ticket: unknown, call: ToolCallRequest): RedeemResult;
}

export interface TicketAuthorityOptions {
  clock?: () => number;
  ttlMs?: number;
}

export function createTicketAuthority(opts: TicketAuthorityOptions = {}): { issuer: TicketIssuer; redeemer: TicketRedeemer } {
  const clock = opts.clock ?? Date.now;
  const ttlMs = opts.ttlMs ?? 30_000;
  const genuine = new WeakSet<object>(); // ticket objects minted by this authority
  const live = new Map<string, ExecutionTicket>(); // unconsumed tickets

  const issuer: TicketIssuer = {
    issue(decision, call) {
      if (!isPepDecision(decision)) throw new TicketError("NOT_PEP_DECISION", "Decision was not produced by the PEP");
      if (decision.decision !== "ALLOW") throw new TicketError("NOT_ALLOWED", `Cannot issue a ticket for ${decision.decision}`);
      if (!decision.callHash || !decision.policyVersion) throw new TicketError("NOT_ALLOWED", "Decision has no call binding");
      if (bindCallHash(call, decision.policyVersion) !== decision.callHash) {
        throw new TicketError("CALL_MISMATCH", "Call does not match the decision it claims");
      }
      const now = clock();
      for (const [id, t] of live) if (t.expiresAt <= now) live.delete(id);
      const ticket: ExecutionTicket = Object.freeze({
        id: randomUUID(),
        tool: call.tool,
        runId: call.runId,
        agentId: call.agentId,
        callHash: decision.callHash,
        policyVersion: decision.policyVersion,
        expiresAt: now + ttlMs,
      });
      genuine.add(ticket);
      live.set(ticket.id, ticket);
      return ticket;
    },
  };

  const redeemer: TicketRedeemer = {
    redeem(ticket, call) {
      if (typeof ticket !== "object" || ticket === null || !genuine.has(ticket)) {
        return { ok: false, code: "FORGED", message: "Ticket was not issued by this authority" };
      }
      const t = ticket as ExecutionTicket;
      if (!live.has(t.id)) return { ok: false, code: "REUSED", message: "Ticket has already been used" };
      live.delete(t.id); // consume before any further check: a failed redemption still burns the ticket
      if (clock() >= t.expiresAt) return { ok: false, code: "EXPIRED", message: "Ticket has expired" };
      if (t.tool !== call.tool || t.runId !== call.runId || t.agentId !== call.agentId) {
        return { ok: false, code: "MODIFIED", message: "Ticket does not match this tool, run or agent" };
      }
      if (bindCallHash(call, t.policyVersion) !== t.callHash) {
        return { ok: false, code: "MODIFIED", message: "Call arguments or provenance differ from the authorised call" };
      }
      return { ok: true };
    },
  };

  return { issuer: Object.freeze(issuer), redeemer: Object.freeze(redeemer) };
}
