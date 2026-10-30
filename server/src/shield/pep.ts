import { z } from "zod";
import type { ArgSpec, ToolManifest } from "../policy/manifests.js";
import type { AgentProfile, UserPrincipal } from "../policy/profiles.js";
import type { Policy } from "../policy/loader.js";
import { classifyPath } from "../policy/classification.js";
import { computeCallHash } from "./canonical.js";
import { scanTexts, type DetectorResult } from "./detector.js";
import { isWithinScopes, normalizeSandboxPath } from "./paths.js";
import {
  confidentialityRank,
  maxConfidentiality,
  minConfidentiality,
  parseLabel,
  type Label,
} from "./provenance.js";
import { stricter, type DecisionKind, type RuleId } from "./rules.js";

// Policy Enforcement Point. A pure, deterministic function: no I/O, no clock reads (`now` is passed in).
// Order: structural fail-closed checks (F0) -> DENY rules (P1-P4, never overridable) ->
// approval rules (A1/A2) or allow (L1) -> detector escalation (A3, stricter only) -> approval evidence.

// TRUST ASSUMPTION: the PEP trusts runId/agentId/userId, argument labels and contextLabel as given.
// The gateway (M3) must set identities from the run, own the context label (joined from tool outputs it
// returned), and never accept labels or identities chosen by agent/model output. See SYSTEM_ARCHITECTURE §6a.
export interface ToolCallRequest {
  runId: string;
  agentId: string;
  userId: string;
  tool: string;
  /** Each argument is a Labeled value: { value, label }. Provenance is tracked per argument. */
  args: Record<string, unknown>;
  /** Run context label (control taint): join of everything the agent has read so far. */
  contextLabel: unknown;
}

/** Facts about a stored approval, supplied by the gateway (M3). The PEP only checks them. */
export interface ApprovalEvidence {
  readonly id: string;
  readonly status: "pending" | "approved" | "rejected" | "expired";
  readonly callHash: string;
  readonly requesterId: string;
  readonly approverId: string | null;
  readonly expiresAt: number; // epoch ms
  readonly used: boolean;
}

export interface PepEnv {
  readonly policy: Policy | null;
  readonly tools: Readonly<Record<string, ToolManifest>>;
  readonly profiles: Readonly<Record<string, AgentProfile>>;
  readonly users: Readonly<Record<string, UserPrincipal>>;
  readonly now: number;
  readonly approval?: ApprovalEvidence;
  /** Untrusted content the agent read in this run, for the injection detector only. */
  readonly untrustedContent?: readonly string[];
}

export interface Decision {
  readonly decision: DecisionKind;
  readonly ruleId: RuleId | `${"A1" | "A2" | "A3"}+APPROVED` | "OFF";
  readonly matchedRules: readonly string[];
  readonly reasons: readonly string[];
  readonly risk: number;
  readonly argProvenance: Readonly<Record<string, Label>>;
  readonly contextLabel: Label | null;
  readonly detector: DetectorResult;
  readonly callHash: string | null;
  readonly policyVersion: string | null;
  readonly policyMode: "enforce" | "permissive" | null;
  readonly approvalId: string | null;
}

const callSchema = z
  .object({
    runId: z.string().min(1).max(100),
    agentId: z.string().min(1).max(100),
    userId: z.string().min(1).max(100),
    tool: z.string().min(1).max(100),
    args: z.record(z.string(), z.unknown()),
    contextLabel: z.unknown(),
  })
  .strict();

const labeledArgSchema = z.object({ value: z.unknown(), label: z.unknown() }).strict();

function valueSchema(spec: ArgSpec): z.ZodType {
  switch (spec.kind) {
    case "sandbox_path":
      return z.string().min(1).max(256);
    case "url":
      return z.string().min(1).max(2048);
    case "email":
      return z.email().max(254);
    case "text":
      return z.string().max(spec.maxLength ?? 1000);
    case "count":
      return z.int().min(1).max(50);
  }
}

const EMPTY_DETECTOR: DetectorResult = Object.freeze({ score: 0, hits: Object.freeze([]) });

const has = (o: object, k: string) => Object.prototype.hasOwnProperty.call(o, k);

function failClosed(reason: string, partial: Partial<Decision> = {}): Decision {
  return Object.freeze({
    argProvenance: {},
    contextLabel: null,
    detector: EMPTY_DETECTOR,
    callHash: null,
    policyVersion: null,
    policyMode: null,
    approvalId: null,
    ...partial,
    decision: "DENY",
    ruleId: "F0",
    matchedRules: ["F0"],
    reasons: [reason],
    risk: 100,
  });
}

export function evaluate(call: unknown, env: PepEnv): Decision {
  try {
    return evaluateUnchecked(call, env);
  } catch (e) {
    return failClosed(`Policy evaluator error: ${(e as Error)?.message ?? "unknown"}`);
  }
}

function evaluateUnchecked(rawCall: unknown, env: PepEnv): Decision {
  // ---- F0: structural fail-closed checks --------------------------------------------------
  const policy = env.policy;
  if (!policy) return failClosed("No valid policy is loaded");
  const meta = { policyVersion: policy.policyVersion, policyMode: policy.mode };

  const parsed = callSchema.safeParse(rawCall);
  if (!parsed.success) return failClosed("Malformed tool call request", meta);
  const call = parsed.data;

  if (!has(env.tools, call.tool)) return failClosed(`Unknown tool "${call.tool}"`, meta);
  const manifest = env.tools[call.tool]!;
  if (!has(env.profiles, call.agentId)) return failClosed(`Unknown agent "${call.agentId}"`, meta);
  const profile = env.profiles[call.agentId]!;
  if (!has(env.users, call.userId)) return failClosed(`Unknown user "${call.userId}"`, meta);
  const user = env.users[call.userId]!;

  const argProvenance: Record<string, Label> = {};
  const values: Record<string, unknown> = {};
  for (const name of Object.keys(call.args)) {
    if (!has(manifest.args, name)) return failClosed(`Unexpected argument "${name}" for ${call.tool}`, meta);
  }
  for (const [name, spec] of Object.entries(manifest.args)) {
    if (!has(call.args, name)) {
      if (spec.required) return failClosed(`Missing required argument "${name}"`, meta);
      continue;
    }
    const arg = labeledArgSchema.safeParse(call.args[name]);
    if (!arg.success) return failClosed(`Argument "${name}" is not a labelled value`, meta);
    const label = parseLabel(arg.data.label);
    if (!label) return failClosed(`Argument "${name}" has missing or malformed provenance`, meta);
    if (!valueSchema(spec).safeParse(arg.data.value).success) {
      return failClosed(`Argument "${name}" failed validation for kind ${spec.kind}`, meta);
    }
    argProvenance[name] = label;
    values[name] = arg.data.value;
  }

  const contextLabel = parseLabel(call.contextLabel);
  if (!contextLabel) return failClosed("Run context has missing or malformed provenance", { ...meta, argProvenance });

  const callHash = computeCallHash({
    tool: call.tool,
    args: Object.fromEntries(Object.keys(values).map((k) => [k, { value: values[k], label: argProvenance[k] }])),
    runId: call.runId,
    agentId: call.agentId,
    policyVersion: policy.policyVersion,
  });

  const untrustedArgText = Object.keys(values)
    .filter((k) => argProvenance[k]!.integrity === "UNTRUSTED" && typeof values[k] === "string")
    .map((k) => values[k] as string);
  const detector = scanTexts([...untrustedArgText, ...(env.untrustedContent ?? [])]);

  const base = { ...meta, argProvenance, contextLabel, detector, callHash, approvalId: env.approval?.id ?? null };

  // ---- Shield OFF: enforcement disabled, everything structurally valid is allowed ---------
  if (policy.mode === "permissive") {
    return Object.freeze({
      ...base,
      decision: "ALLOW",
      ruleId: "OFF",
      matchedRules: ["OFF"],
      reasons: ["Shield OFF: permissive policy, no enforcement applied"],
      risk: detector.score,
    });
  }

  // ---- DENY rules (never overridable) ------------------------------------------------------
  const denies: { rule: RuleId; reason: string }[] = [];
  const effectiveClearance = minConfidentiality(user.clearance, profile.maxConfidentiality);

  if (!profile.allowedTools.includes(call.tool)) {
    denies.push({ rule: "P1", reason: `Agent profile ${profile.id} is not permitted to use ${call.tool}` });
  }

  for (const [name, spec] of Object.entries(manifest.args)) {
    if (!has(values, name)) continue;
    if (spec.kind === "sandbox_path") {
      const p = normalizeSandboxPath(values[name]);
      if (!p) {
        denies.push({ rule: "P2", reason: `Path "${String(values[name])}" is not a safe sandbox-relative path` });
      } else {
        if (!isWithinScopes(p, profile.fileScopes)) {
          denies.push({ rule: "P2", reason: `Path ${p} is outside the agent's file scopes (${profile.fileScopes.join(", ")})` });
        }
        const cls = classifyPath(p);
        if (confidentialityRank(cls) > confidentialityRank(effectiveClearance)) {
          denies.push({ rule: "P2", reason: `${p} is classified ${cls}, above effective clearance ${effectiveClearance} (user ${user.clearance}, agent ceiling ${profile.maxConfidentiality})` });
        }
      }
    }
    if (spec.kind === "url") {
      let url: URL | null = null;
      try {
        url = new URL(String(values[name]));
      } catch {
        url = null;
      }
      if (
        !url ||
        url.protocol !== "https:" ||
        url.username ||
        url.password ||
        url.port !== "" ||
        !profile.urlAllowlist.includes(url.hostname)
      ) {
        denies.push({ rule: "P2", reason: `URL "${String(values[name])}" is not an allow-listed https host for ${profile.id}` });
      }
    }
  }

  if (manifest.effect === "EXTERNAL_SEND") {
    for (const name of Object.keys(values)) {
      // Implicit flows: anything sent after reading sensitive data is treated as at least that sensitive.
      const conf = maxConfidentiality(argProvenance[name]!.confidentiality, contextLabel.confidentiality);
      if (confidentialityRank(conf) >= confidentialityRank("CONFIDENTIAL")) {
        denies.push({ rule: "P3", reason: `Argument "${name}" carries ${conf} data (sources: ${argProvenance[name]!.sources.join(", ")}; context: ${contextLabel.confidentiality}) into an external send` });
      }
    }
  }

  if (manifest.impact === "HIGH") {
    for (const [name, spec] of Object.entries(manifest.args)) {
      if (spec.role === "target" && has(values, name) && argProvenance[name]!.integrity === "UNTRUSTED") {
        denies.push({ rule: "P4", reason: `Target "${name}" was chosen by untrusted content (sources: ${argProvenance[name]!.sources.join(", ")})` });
      }
    }
  }

  if (denies.length > 0) {
    const reasons = denies.map((d) => `${d.rule}: ${d.reason}`);
    if (env.approval) reasons.push("An approval was supplied, but DENY rules cannot be overridden");
    return Object.freeze({
      ...base,
      decision: "DENY",
      ruleId: denies[0]!.rule,
      matchedRules: [...new Set(denies.map((d) => d.rule))],
      reasons,
      risk: Math.max(90, detector.score),
    });
  }

  // ---- Approval / allow rules --------------------------------------------------------------
  let decision: DecisionKind;
  let ruleId: RuleId;
  let risk: number;
  const reasons: string[] = [];

  if (manifest.impact === "HIGH") {
    const untrustedData = Object.entries(manifest.args)
      .filter(([n, s]) => s.role === "data" && has(values, n) && argProvenance[n]!.integrity === "UNTRUSTED")
      .map(([n]) => n);
    if (contextLabel.integrity === "UNTRUSTED" || untrustedData.length > 0) {
      decision = "REQUIRE_APPROVAL";
      ruleId = "A1";
      risk = 70;
      reasons.push(
        `A1: ${call.tool} is high-impact and is influenced by untrusted content` +
          (untrustedData.length ? ` (untrusted data in: ${untrustedData.join(", ")})` : " (run context is tainted)"),
      );
    } else {
      decision = "REQUIRE_APPROVAL";
      ruleId = "A2";
      risk = 40;
      reasons.push(`A2: ${call.tool} is high-impact and requires user confirmation`);
    }
  } else if (manifest.effect === "READ" && manifest.impact === "LOW") {
    decision = "ALLOW";
    ruleId = "L1";
    risk = 10;
    reasons.push(`L1: low-impact read within scope and clearance`);
  } else {
    return Object.freeze({ ...base, decision: "DENY", ruleId: "DEFAULT", matchedRules: ["DEFAULT"], reasons: ["DEFAULT: no rule allows this call"], risk: 90 });
  }

  // ---- A3: detector escalation (stricter only) ---------------------------------------------
  const matchedRules: string[] = [ruleId];
  const anyUntrustedArg = Object.values(argProvenance).some((l) => l.integrity === "UNTRUSTED");
  if (detector.score >= policy.detector.escalateThreshold && anyUntrustedArg) {
    const escalated = stricter(decision, "REQUIRE_APPROVAL");
    if (escalated !== decision) {
      decision = escalated;
      ruleId = "A3";
      reasons.push(`A3: injection signals (score ${detector.score}: ${detector.hits.map((h) => h.pattern).join(", ")}) while untrusted data steers this call`);
    }
    matchedRules.push("A3");
  }
  risk = Math.max(risk, detector.score);

  // ---- Approval evidence: may satisfy REQUIRE_APPROVAL, nothing else -----------------------
  if (decision === "REQUIRE_APPROVAL" && env.approval) {
    const problem = approvalProblem(env.approval, callHash, call.agentId, env.now, env.profiles);
    if (problem) return failClosed(`Invalid approval: ${problem}`, base);
    return Object.freeze({
      ...base,
      decision: "ALLOW",
      ruleId: `${ruleId as "A1" | "A2" | "A3"}+APPROVED`,
      matchedRules: [...matchedRules, "APPROVED"],
      reasons: [...reasons, `Approved by ${env.approval.approverId} (approval ${env.approval.id}); all DENY rules re-checked`],
      risk,
    });
  }

  return Object.freeze({ ...base, decision, ruleId, matchedRules, reasons, risk });
}

// Only human operator principals may approve; no agent (requester or any other) can approve actions.
const HUMAN_APPROVER = /^operator:[a-z0-9._-]{1,64}$/;

function approvalProblem(
  a: ApprovalEvidence,
  callHash: string,
  agentId: string,
  now: number,
  profiles: Readonly<Record<string, AgentProfile>>,
): string | null {
  if (a.status !== "approved") return `status is ${a.status}`;
  if (a.used) return "approval has already been used";
  if (!(now < a.expiresAt)) return "approval has expired";
  if (a.callHash !== callHash) return "approval is bound to a different call (tool, arguments, provenance, run, agent or policy version changed)";
  if (a.requesterId !== agentId) return "approval was requested by a different agent";
  if (!a.approverId) return "approval has no approver";
  if (a.approverId === a.requesterId || a.approverId === agentId) return "requester cannot approve its own action";
  if (has(profiles, a.approverId) || !HUMAN_APPROVER.test(a.approverId)) return "approver is not a human operator";
  return null;
}
