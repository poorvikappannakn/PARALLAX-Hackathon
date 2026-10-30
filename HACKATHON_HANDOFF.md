# HACKATHON HANDOFF — AgentShield

_Last updated: 2026-10-30, M1 complete and independently reviewed._

## What we are building
PARALLAX PS-01 AgentShield: a provenance-aware, deterministic policy enforcement point (PEP) between a simulated agent and
5 sandboxed tools. Architecture: `docs/SYSTEM_ARCHITECTURE.md` (v2.1). Hard rules: `CLAUDE.md`.
Deadline: submissions close 31 Oct 16:00 IST; feature freeze 12:00.

## Approved safeguards (must hold)
1. Approvals are atomically consumed and bound to hash(tool, canonical args incl. provenance, runId, agentId, policyVersion);
   the PEP re-evaluates before execution; DENY rules are never overridable.
2. Audit fails closed: no execution without a decision row; outcome-write failure halts the run (`audit_failure`).
3. The gateway owns identities and the context label; nothing labels-related is taken from agent output (§6a).

## Milestones
| # | Milestone | Status |
|---|---|---|
| M0 | Foundation | COMPLETE (commits d3a5a6d, 4a3f0f4) |
| M1 | Security foundation | COMPLETE (uncommitted) |
| M2 | Sandbox fixtures + tools | NEXT — not started, awaiting authorisation |
| M3–M7 | Gateway/audit/approvals → agent/scenarios → API → dashboard → hardening | not started (see `docs/IMPLEMENTATION_PLAN.md`) |

## Current code (server/src)
| File | Purpose |
|---|---|
| `index.ts`, `db/sqlite.ts` | Fastify `/api/health` on 127.0.0.1:3000; SQLite opener (WAL, FKs). |
| `shield/provenance.ts` | `Label`/`Labeled<T>`, strict `parseLabel`, `WORST_CASE_LABEL` (UNTRUSTED+SECRET), `joinLabels` (empty/malformed ⇒ worst case), origins (`fromUser`, `agentLiteral`, `untrusted`), propagation (`copy`, `transform`, `combine`, `generated`, `extendContext`). Labels frozen. |
| `shield/canonical.ts` | `canonicalJson` (sorted keys, LF, NFC); `computeCallHash`. |
| `shield/paths.ts` | `normalizeSandboxPath` (rejects traversal, absolute, drive, UNC, ADS, NUL, trailing dot/space, device names, `~`), `isWithinScopes`. Logical only. |
| `shield/detector.ts` | Heuristic injection scorer (8 patterns, 0–100). Escalate-only. |
| `shield/rules.ts` | Rule catalogue F0, P1–P4, A1–A3, L1, DEFAULT; `stricter()`. |
| `shield/pep.ts` | Pure `evaluate(call, env)` → `Decision` (ruleId, matchedRules, reasons, risk, per-arg provenance, context label, detector, callHash, policy version). Checks `ApprovalEvidence`; approvers must be `operator:*`. |
| `policy/classification.ts` | Path-prefix classification (unclassified ⇒ SECRET); content labels for file/web/email (always UNTRUSTED). |
| `policy/manifests.ts` | 5 frozen tool manifests: effect, impact, per-argument kind and role (target/data/option). |
| `policy/profiles.ts` | Agents `agent:research-assistant`, `agent:ops-assistant`; users `user:alice` (INTERNAL), `user:hana` (CONFIDENTIAL). |
| `policy/policy.yaml`, `policy.permissive.yaml`, `loader.ts`, `shield-config.ts` | Shield ON/OFF. Enforce file must list exactly the catalogue, keep DENY decisions, keep detector enabled; ON refuses a permissive file; failure ⇒ `policy: null` ⇒ every call DENY. Policies deep-frozen. ON/OFF share the same registries. |

## Key M1 decisions
- A3 escalates ALLOW → REQUIRE_APPROVAL only when detector ≥ threshold **and** an argument is UNTRUSTED.
- P3 uses max(argument, run-context) confidentiality for every argument of an external send (implicit flows).
- All content read from the environment (files, web, email) is UNTRUSTED; files take confidentiality from classification.
- P2 effective clearance = min(user clearance, agent ceiling). URLs: https, exact allow-listed host, no credentials or port.
- Shield OFF still rejects structurally invalid calls (F0); all policy rules are skipped (`ruleId: OFF`).

## Verification (latest run)
`npm test`: 6 files, **137/137 pass** · server + web typecheck clean · ESLint clean · web production build OK.

## Open items carried into later milestones
- M2: real path containment (resolve + realpath + prefix) inside tools; reject CR/LF in email subject when writing the outbox.
- M3: gateway must own identities and context label (§6a); consume approvals only when `ruleId` ends in `+APPROVED`.
- Decision objects are shallow-frozen; gateway should treat them as read-only and copy before storing.

## Notes
- `node:sqlite` prints an ExperimentalWarning (expected). Use `npm.cmd`/`npx.cmd` in PowerShell.

## Failed approaches
- A test for "evaluator throws" first used a Proxy without a `getOwnPropertyDescriptor` trap, so `hasOwnProperty` bypassed it.
  The PEP still failed closed; the test was fixed to force a real exception.

## Next task
M2 (awaiting authorisation): synthetic sandbox fixtures (`server/sandbox/`), per-run sandbox copy, 5 tool implementations with
realpath containment and output labelling, single-use ALLOW-ticket enforcement.
