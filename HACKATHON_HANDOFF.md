# HACKATHON HANDOFF — AgentShield

_Last updated: 2026-10-30, M3 + M3 hardening (adversarial review F1–F6) complete (uncommitted)._

## What we are building
PARALLAX PS-01 AgentShield: a provenance-aware, deterministic policy enforcement point (PEP) between a simulated agent and
5 sandboxed tools. Architecture: `docs/SYSTEM_ARCHITECTURE.md` (v2.1). Hard rules: `CLAUDE.md`.
Deadline: submissions close 31 Oct 16:00 IST; feature freeze 12:00.

## Approved safeguards (all implemented and tested)
1. Approvals are atomically consumed and bound to hash(tool, canonical args incl. provenance, runId, agentId, userId, policyVersion);
   the PEP re-evaluates before execution; DENY rules are never overridable.
2. Audit fails closed: no ticket/execution without a decision row; outcome-write failure halts the run (`audit_failure`).
3. The gateway owns identities, labels and the grow-only context label; nothing is taken from agent output (§6a, §6c).
4. Tools run only with a single-use, call-bound execution ticket issued for a PEP-produced ALLOW decision (§6b); only
   `src/gateway/**` may import ticket issuance and the executor (ESLint, tested).
5. CONFIDENTIAL/SECRET values never appear in any audit field; detector excerpts are never stored (§6c hardening).

## Milestones
| # | Milestone | Status |
|---|---|---|
| M0 | Foundation | COMPLETE (commits d3a5a6d, 4a3f0f4) |
| M1 | Security foundation (provenance, policy, PEP) | COMPLETE (commits 82efe41, 257b22e, 5f75f86) |
| M2 | Sandbox, tools, execution tickets | COMPLETE (commits 21c7300 … 6f6a390) |
| M3 | ToolGateway, audit store, approval workflow + hardening (review F1–F6) | COMPLETE (uncommitted) |
| M4 | NaiveAgent + scenarios S1–S5 + attack regression suite | NEXT — not started, awaiting authorisation |
| M5–M7 | API → dashboard → hardening | not started (`docs/IMPLEMENTATION_PLAN.md`) |

## Current code (server/src)
| File | Purpose |
|---|---|
| `index.ts`, `db/sqlite.ts` | Fastify `/api/health` on 127.0.0.1:3000; SQLite opener. |
| `shield/provenance.ts` | Labels, strict parsing, worst-case default, join, origins, propagation. |
| `shield/arg-schema.ts` | Shared strict argument validation (PEP + executor). |
| `shield/canonical.ts` | `canonicalJson`, `computeCallHash`, `bindCallHash`. |
| `shield/paths.ts`, `shield/detector.ts`, `shield/rules.ts` | Path normalisation, injection scorer (escalate-only), rule catalogue. |
| `shield/pep.ts` | Pure `evaluate(call, env)`; brands decisions (`isPepDecision`); checks approval evidence. |
| `shield/tickets.ts` | Issuer/redeemer; single-use, 30 s, call-bound tickets. |
| `sandbox/sandbox.ts` | Per-run sandbox copy and realpath containment. |
| `tools/index.ts`, `tools/impl.ts` | Ticket-checking executor; 5 tools with labelled outputs. |
| `audit/store.ts` | **M3.** `createStores(db)` → `{audit, approvals, transaction}`; schema for runs, audit_events, approvals. |
| `gateway/gateway.ts` | **M3.** `startRun(deps, spec)` → `{run, sandbox, gateway}`; gateway `request`, `resume`, `refs`, `state`; audit redaction (`sensitiveValues`/`scrub`/`auditDetector`). |
| `gateway/approvals.ts` | **M3.** `decideApproval(stores, id, approverId, verdict, now)` — operator-only, transactional. |
| `policy/*` | Classification, manifests, profiles (+ `OPERATORS` registry, M3), YAML policies, loader, shield config. |

Fixtures: `server/fixtures/northwind/`. Run sandboxes: `server/runtime/runs/<runId>/` (git-ignored).

## How the gateway is used (for M4)
```ts
const stores = createStores(openDatabase("data/agentshield.db"));
const { run, gateway } = startRun({ config: loadShieldConfig("on"), stores }, {
  scenarioId: "S1", userId: "user:alice", agentId: "agent:research-assistant",
  task: { text: "Summarise the Q3 report and email it to me", params: { report: "reports/q3-report.txt" } },
});
gateway.request({ tool: "read_file", args: { path: { ref: "task.report" } } });          // -> { status: "ok", ref: "out-1", value }
gateway.request({ tool: "send_email", args: { to: { ref: "user.email" }, subject: { value: "Q3" }, body: { value: "..." } } });
// -> { status: "approval_required", approvalId }   then operator: decideApproval(stores, approvalId, "operator:alice", "approve", Date.now())
gateway.resume(approvalId);                                                                 // -> { status: "ok", ... }
```
Result statuses: `ok`, `denied`, `approval_required`, `approval_pending`, `tool_error`, `rejected`, `halted`.

## Key decisions
- M1: A3 needs detector ≥ threshold **and** an UNTRUSTED argument; P3 uses max(arg, context) confidentiality; all environment
  content is UNTRUSTED; P2 clearance = min(user, agent ceiling); Shield OFF still rejects structurally invalid calls.
- M2: tool outputs join content label with selecting args' labels; sandbox/URL/subject checks enforced in tools (hold with OFF).
- M3: agent args are `{ref}` (gateway-held label) or `{value}` (labelled `generated(context)`, never upgradable). Audit args redact
  CONFIDENTIAL/SECRET values; provenance kept. Approval decision + audit and approval consumption + audit are each one
  transaction. Pending calls are stored by the gateway, so the agent cannot change a call after approval was requested.
  Ticket-issue failure is treated as DENY F0 and audited.
- M3 hardening (adversarial review): F1 sensitive values scrubbed from every audit field, detector stored as pattern ids only,
  no value echo in sandbox errors / unknown-ref messages · F2/F3 ESLint import boundaries (agent: gateway types only; only
  gateway may import tickets + executor) verified by `tests/import-boundaries.test.ts` · F4 `resume` joins the current context
  into the stored call (hash unchanged, stricter only) · F5 accurate expired/audit-failure/consume-failure reasons · F6 any
  exception in `request`/`resume` halts the run; audit `seq` allocated atomically inside the INSERT.
- M3 review: replayed or unknown approval `resume` calls return `rejected` and are audited as `request_rejected` (approval id +
  fixed reason only); an audit-write failure there halts the run. Successful approvals execute exactly once (tested).
  Malformed approval ids (not `appr-<uuid v4>`, 41 chars) are audited with `approval_id` NULL. Unknown tool / unexpected
  argument names are recorded as placeholders, never verbatim (they are agent-controlled and unlabelled).

## Verification (latest run)
`npm test`: 11 files, **298 passed, 1 skipped** (file-symlink test: Windows `EPERM` without Developer Mode).
Server + web typecheck clean · ESLint clean · web production build OK.
Original adversarial probes P1–P4 re-run after hardening: no sensitive value in any audit record.
Mutation probes (reverted, M3): trusting agent `{value}` as user data fails 4 gateway tests; skipping the decision-write check
fails the fail-closed test.

## Remaining risks
- Audit is application-level append-only, not OS-level tamper-proof (hash chain is a stretch item).
- Pending calls and tickets are held in gateway memory: a server restart drops pending approvals (they expire safely).
- Coarse provenance for agent-generated values: any `{value}` carries the whole run context label (conservative; may require
  more approvals than strictly necessary, never fewer).
- Small TOCTOU window in `delete_file` between containment check and unlink (run-local; local attacker out of scope).
- Approver authentication (session/CSRF) is M5; `decideApproval` already enforces the operator registry. Any in-process caller
  of `decideApproval` can claim an operator id — ESLint keeps agent code away from it; M5 must bind it to the session.
- Import boundaries are enforced by ESLint (static), not at runtime; `npm run lint` must stay in the pre-commit checklist.
- Redaction is value-based: a CONFIDENTIAL value transformed beyond recognition (e.g. re-encoded) by the agent before reaching a
  reason string would not be matched. PEP reasons only echo path/URL values, which are covered including their normalised form.
- Audit `seq` atomicity relies on SQLite's single-writer model; multi-process deployment would need a dedicated writer.

## Notes
- `node:sqlite` ExperimentalWarning is expected. Use `npm.cmd`/`npx.cmd` in PowerShell.
- `files/secrets/api_keys.env` is a deliberately fake fixture and is intentionally tracked.
- On Windows, close SQLite handles before deleting temp directories (tests do).

## Failed approaches
- M1: "evaluator throws" test Proxy lacked a `getOwnPropertyDescriptor` trap (fixed in test).
- M2: a test passed the page object instead of `html` to `transform` (test bug).
- M3: a test left a file-backed SQLite handle open → intermittent `EPERM` on temp cleanup (fixed by closing handles).
- M3 review: the original redaction test only checked `FAKE-DEMO` and passed by luck (detector window). Replaced by serialized
  whole-audit assertions on reasons, details, rejected refs and detector fields.

## Next task
M4 (awaiting authorisation): deterministic NaiveAgent using only the gateway handle; scenarios S1–S5; attack regression suite
(shield OFF: attack succeeds; shield ON: blocked, legit task completes, audit rows present).
