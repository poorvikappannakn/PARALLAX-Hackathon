import type { ApprovalRecord, Stores } from "../audit/store.js";
import { AGENT_PROFILES, OPERATORS } from "../policy/profiles.js";

// Operator-side approval decisions. Only registered human operators may decide; agents (any profile id) never can.
// The decision and its audit row are written in one transaction, so an unaudited approval cannot exist.

export type ApprovalDecisionResult =
  | { ok: true; approval: ApprovalRecord }
  | { ok: false; code: "NOT_FOUND" | "FORBIDDEN" | "CONFLICT" | "EXPIRED" | "AUDIT_FAILURE"; message: string };

const has = (o: object, k: string) => Object.prototype.hasOwnProperty.call(o, k);

export function decideApproval(
  stores: Stores,
  approvalId: string,
  approverId: string,
  verdict: "approve" | "reject",
  now: number,
): ApprovalDecisionResult {
  const approval = stores.approvals.get(approvalId);
  if (!approval) return { ok: false, code: "NOT_FOUND", message: "Approval not found" };
  if (!has(OPERATORS, approverId) || has(AGENT_PROFILES, approverId) || approverId === approval.requesterId) {
    return { ok: false, code: "FORBIDDEN", message: "Only a registered human operator, distinct from the requester, may decide" };
  }
  if (approval.status !== "pending" || approval.used) return { ok: false, code: "CONFLICT", message: `Approval is ${approval.status}` };
  if (now >= approval.expiresAt) return { ok: false, code: "EXPIRED", message: "Approval has expired" };

  const run = stores.audit.getRun(approval.runId);
  if (!run) return { ok: false, code: "NOT_FOUND", message: "Run not found" };

  try {
    stores.transaction(() => {
      if (!stores.approvals.setDecision(approvalId, verdict === "approve" ? "approved" : "rejected", approverId, now)) {
        throw new Error("conflict");
      }
      stores.audit.append(
        {
          runId: run.id,
          kind: "approval_decided",
          userId: run.userId,
          agentId: run.agentId,
          shieldMode: run.shieldMode,
          policyId: run.policyId,
          tool: approval.tool,
          callHash: approval.callHash,
          approvalId,
          decision: verdict === "approve" ? "APPROVED" : "REJECTED",
          detail: { approverId },
        },
        now,
      );
    });
  } catch (e) {
    if ((e as Error).message === "conflict") return { ok: false, code: "CONFLICT", message: "Approval was decided concurrently" };
    return { ok: false, code: "AUDIT_FAILURE", message: "Could not record the decision; approval left pending" };
  }
  return { ok: true, approval: stores.approvals.get(approvalId)! };
}
