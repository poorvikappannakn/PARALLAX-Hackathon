# HACKATHON HANDOFF — AgentShield

_Last updated: 2026-10-30, M2 complete (uncommitted)._

## What we are building
PARALLAX PS-01 AgentShield: a provenance-aware, deterministic policy enforcement point (PEP) between a simulated agent and
5 sandboxed tools. Architecture: `docs/SYSTEM_ARCHITECTURE.md` (v2.1). Hard rules: `CLAUDE.md`.
Deadline: submissions close 31 Oct 16:00 IST; feature freeze 12:00.

## Approved safeguards (must hold)
1. Approvals are atomically consumed and bound to hash(tool, canonical args incl. provenance, runId, agentId, userId, policyVersion);
   the PEP re-evaluates before execution; DENY rules are never overridable.
2. Audit fails closed: no execution without a decision row; outcome-write failure halts the run (`audit_failure`).
3. The gateway owns identities and the context label; nothing labels-related is taken from agent output (§6a).
4. Tools run only with a single-use, call-bound execution ticket issued for a PEP-produced ALLOW decision (§6b).

## Milestones
| # | Milestone | Status |
|---|---|---|
| M0 | Foundation | COMPLETE (commits d3a5a6d, 4a3f0f4) |
| M1 | Security foundation (provenance, policy, PEP) | COMPLETE (commits 82efe41, 257b22e, 5f75f86) |
| M2 | Sandbox, tools, execution tickets | COMPLETE (uncommitted) |
| M3 | Gateway + audit + approvals | NEXT — not started, awaiting authorisation |
| M4–M7 | Agent/scenarios → API → dashboard → hardening | not started (`docs/IMPLEMENTATION_PLAN.md`) |

## Current code (server/src)
| File | Purpose |
|---|---|
| `index.ts`, `db/sqlite.ts` | Fastify `/api/health` on 127.0.0.1:3000; SQLite opener. |
| `shield/provenance.ts` | Labels, strict parsing, worst-case default, join, origins, propagation (`copy/transform/combine/generated/extendContext`). |
| `shield/arg-schema.ts` | Shared strict argument validation (`validateArgs`) used by PEP and tool executor. |
| `shield/canonical.ts` | `canonicalJson`; `computeCallHash`; `bindCallHash(call, policyVersion)` (binds tool, labelled args, run, agent, user, policy). |
| `shield/paths.ts` | Logical path normalisation and scope check. |
| `shield/detector.ts` | Heuristic injection scorer (escalate-only). |
| `shield/rules.ts` | Rule catalogue and `stricter()`. |
| `shield/pep.ts` | Pure `evaluate(call, env)` → `Decision`; registers decisions for `isPepDecision`; checks approval evidence (approvers `operator:*`). |
| `shield/tickets.ts` | `createTicketAuthority({clock, ttlMs})` → `{issuer, redeemer}`; single-use, 30 s, call-bound tickets. |
| `sandbox/sandbox.ts` | `createRunSandbox`, `destroyRunSandbox`, `resolveContainedFile`, `readContainedFile`, `containedDir`, `isInside`. |
| `tools/index.ts` | `createToolExecutor(redeemer)` — the only entry point to tools. |
| `tools/impl.ts` | `read_file`, `fetch_web`, `read_inbox`, `send_email`, `delete_file` (labelled outputs). |
| `policy/*` | Classification, manifests, profiles, enforce/permissive YAML, loader, shield config. |

Fixtures: `server/fixtures/northwind/` (synthetic; see its README). Run sandboxes: `server/runtime/runs/<runId>/` (git-ignored).

## Key decisions
- M1: A3 needs detector ≥ threshold **and** an UNTRUSTED argument; P3 uses max(arg, context) confidentiality; all environment
  content is UNTRUSTED; P2 clearance = min(user, agent ceiling); Shield OFF still rejects structurally invalid calls.
- M2: tool outputs join the content label with the selecting arguments' labels; inbox messages labelled individually;
  receipts TRUSTED PUBLIC. Sandbox containment, URL restrictions (https, `.test`, no port/credentials, local fixtures) and
  single-line subjects are enforced in tools, independent of policy, so they hold with Shield OFF.
- M2 changes to M1 code: argument validation moved to `arg-schema.ts` (identical rules); call hash now also binds `userId`;
  `evaluate()` brands its decisions. All 137 M1 tests still pass unchanged.

## Verification (latest run)
`npm test`: 9 files, **213 passed, 1 skipped** (file-symlink test: Windows `EPERM` without Developer Mode; junction and
hard-link escapes are tested and rejected) · server + web typecheck clean · ESLint clean (boundary rules verified to fire) ·
web production build OK.

## M3 required security work (from M1/M2 reviews)
1. **[HIGH — provenance trust boundary]** The PEP and execution tickets trust the identities and labels they are given; a value
   relabelled TRUSTED is accepted (documented by test `tools.test.ts` › "a forged TRUSTED label…"). The M3 gateway MUST set
   `runId/agentId/userId` from the run record, maintain the run context label itself from tool outputs (grow-only), and never
   accept labels or identities from agent/model output (`SYSTEM_ARCHITECTURE.md` §6a, `CLAUDE.md` #11).
2. Write the decision audit row before issuing a ticket; halt the run if the outcome row fails (safeguard 2).
3. Consume approvals atomically and only when the re-evaluated decision `ruleId` ends in `+APPROVED` (safeguard 1).

## Accepted low risks
- Small TOCTOU window between `resolveContainedFile` and `unlink` in `delete_file` (run-local only; local attacker out of scope).
- Ticket store is in-memory (single-process demo).

## Notes
- `node:sqlite` ExperimentalWarning is expected. Use `npm.cmd`/`npx.cmd` in PowerShell.
- `files/secrets/api_keys.env` is a deliberately fake fixture and is intentionally tracked.

## Failed approaches
- M1: "evaluator throws" test Proxy lacked a `getOwnPropertyDescriptor` trap (fixed in test).
- M2: one test passed the page object instead of `html` to `transform` (test bug, fixed).

## Next task
M3 (awaiting authorisation): ToolGateway (identities + context label from run state), audit store with fail-closed writes,
approval store with atomic consumption and PEP re-evaluation, wiring PEP → audit → ticket → executor → audit.
