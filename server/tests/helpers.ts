import { loadShieldConfig } from "../src/policy/shield-config.js";
import { evaluate, type ApprovalEvidence, type PepEnv, type ToolCallRequest } from "../src/shield/pep.js";
import { agentLiteral, fromUser, makeLabel, untrusted, type Label, type Labeled } from "../src/shield/provenance.js";

export const NOW = 1_800_000_000_000;
export const ON = loadShieldConfig("on");
export const OFF = loadShieldConfig("off");

export const TRUSTED_CTX: Label = makeLabel("TRUSTED", "INTERNAL", ["user:task"]);
export const TAINTED_CTX: Label = makeLabel("UNTRUSTED", "PUBLIC", ["user:task", "web:https://vendor.contoso.test/pricing"]);

export const user = <T>(v: T, src = "user:task") => fromUser(v, src);
export const web = <T>(v: T) => untrusted(v, "web:https://vendor.contoso.test/pricing", "PUBLIC");
export const mail = <T>(v: T) => untrusted(v, "inbox:msg-3", "INTERNAL");
export const literal = agentLiteral;

export function call(
  tool: string,
  args: Record<string, Labeled<unknown> | unknown>,
  over: Partial<ToolCallRequest> = {},
): ToolCallRequest {
  return {
    runId: "run-1",
    agentId: "agent:research-assistant",
    userId: "user:alice",
    tool,
    args,
    contextLabel: TRUSTED_CTX,
    ...over,
  };
}

export function env(mode: "on" | "off" = "on", over: Partial<PepEnv> = {}): PepEnv {
  const cfg = mode === "on" ? ON : OFF;
  return { policy: cfg.policy, tools: cfg.tools, profiles: cfg.profiles, users: cfg.users, now: NOW, ...over };
}

export const decide = (c: unknown, e: PepEnv = env()) => evaluate(c, e);

export function approvalFor(c: ToolCallRequest, over: Partial<ApprovalEvidence> = {}): ApprovalEvidence {
  const pending = decide(c);
  return {
    id: "appr-1",
    status: "approved",
    callHash: pending.callHash ?? "missing",
    requesterId: c.agentId,
    approverId: "operator:alice",
    expiresAt: NOW + 60_000,
    used: false,
    ...over,
  };
}

/** A legitimate email: recipient from the user's profile, body produced by the agent from trusted data. */
export function legitEmail(over: Partial<ToolCallRequest> = {}): ToolCallRequest {
  return call(
    "send_email",
    {
      to: user("alice@northwind.test", "user:profile"),
      subject: literal("Q3 summary"),
      body: user("Revenue grew 12%."),
    },
    over,
  );
}
