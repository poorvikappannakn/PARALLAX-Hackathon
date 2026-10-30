# HACKATHON HANDOFF — AgentShield

_Last updated: 2026-10-30, M4 complete (uncommitted at time of writing). M0–M3 committed and pushed._

## What we are building
PARALLAX PS-01 AgentShield: a provenance-aware, deterministic policy enforcement point (PEP) between a simulated agent and
5 sandboxed tools. Architecture: `docs/SYSTEM_ARCHITECTURE.md` (v2.1, §11 for M4). Hard rules: `CLAUDE.md`.
Deadline: submissions close 31 Oct 16:00 IST; feature freeze 12:00.

## Read this first (honesty constraints for the demo and judges)
- **The agent is a deterministic, rule-based simulation — NOT an LLM.** It uses a regex instruction parser and is gullible on
  purpose, standing in for a prompt-injected agent. Its "summaries" are first-lines extracts, labelled as such.
- **Approvals in M4 are SCRIPTED** (the scenario's predefined decision, recorded as `operator:alice`). They are not human
  decisions. Real human approval through an authenticated UI session is M5/M6.
- **Raw agent traces (`agent.trace()`) contain sensitive values** (e.g. the fake keys in S2 OFF) and must **never** be exposed
  through the API or UI. Expose only the sanitised `ScenarioReport`.
- **Public reports must not expose** secrets, document contents, email bodies or untrusted subject lines (enforced in
  `scenarios/verdict.ts` + `runner.ts`, tested for all 10 runs).
- **The `raw` task step is an internal test mechanism** (S5 malformed-request probes), not a public API capability.
- **The audit store is application-level append-only, not OS-level tamper-proof.**
- All data is synthetic (`.test` domains, `FAKE-DEMO` keys); everything happens in a per-run sandbox copy; no real network or email.

## Approved safeguards (implemented and tested)
1. Approvals are atomically consumed and bound to hash(tool, canonical args incl. provenance, runId, agentId, userId, policyVersion);
   the PEP re-evaluates before execution; DENY rules are never overridable.
2. Audit fails closed: no ticket/execution without a decision row; any audit-write failure halts the run.
3. The gateway owns identities, labels and the grow-only context label; nothing is taken from agent output.
4. Tools run only with a single-use, call-bound ticket for a PEP ALLOW; only `src/gateway/**` may import tickets + executor.
5. CONFIDENTIAL/SECRET values never appear in audit fields; unknown tool/argument names and malformed approval ids are not stored verbatim.

## Milestones
| # | Milestone | Status |
|---|---|---|
| M0 | Foundation | COMPLETE (committed) |
| M1 | Security foundation (provenance, policy, PEP) | COMPLETE (committed) |
| M2 | Sandbox, tools, execution tickets | COMPLETE (committed) |
| M3 | ToolGateway, audit store, approvals + hardening | COMPLETE (committed: 23f037b, b352c45, 9923829) |
| M4 | Parser, NaiveAgent, scenarios S1–S5, verdicts, regression suite, CLI | COMPLETE (uncommitted at time of writing) |
| M5 | API | **NOT STARTED** |
| M6 | Dashboard | **NOT STARTED** |
| M7 | Hardening, demo script, README, threat model | **NOT STARTED** |

## Current code (server/src)
| File | Purpose |
|---|---|
| `index.ts`, `db/sqlite.ts` | Fastify `/api/health` on 127.0.0.1:3000 (only route so far); SQLite opener (creates parent dirs). |
| `shield/*` | Provenance, argument schema, canonical hash, paths, detector, rules, pure PEP, tickets (M1–M2). |
| `sandbox/sandbox.ts`, `tools/*` | Per-run sandbox copy + containment; ticket-checking executor and 5 tools (M2). |
| `audit/store.ts` | Runs, append-only audit events, approvals (M3). |
| `gateway/gateway.ts`, `gateway/approvals.ts` | `startRun` → gateway `request`/`resume`/`refs`/`state`; `decideApproval` (M3). |
| `policy/*` | Classification, manifests, profiles, users, `OPERATORS`, YAML policies, loader, shield config (M1). |
| `agent/instructions.ts` | **M4.** `parseInstructions(text, source)` — regex parser, untrusted output, bounded. |
| `agent/naive-agent.ts` | **M4.** `createNaiveAgent(gateway, task, {maxSteps})` — `run()`, `resumeAfterApproval()`, `status()`, `trace()`. |
| `scenarios/catalog.ts` | **M4.** S1–S5 definitions, scripted operator scripts, checks, expected outcomes. |
| `scenarios/runner.ts` | **M4.** `runScenario(id, mode, {stores, runtimeDir?, clock?, maxSteps?, operatorOverride?})` → `ScenarioReport`. |
| `scenarios/verdict.ts` | **M4.** Sandbox snapshot, sanitised sandbox summary, legitimate/attack verdicts. |
| `cli/scenarios.ts` | **M4.** Scenario CLI (`npm run scenarios`). |

## How to run (verified against package scripts)
From the repository root (PowerShell: use `npm.cmd` if `npm` is blocked):
```
npm install
npm test                                              # full suite (root script -> server vitest)
npm run typecheck                                     # server + web
npm run lint                                          # server ESLint incl. import boundaries
npm run build -w web                                  # web production build
npm run scenarios -w server -- list                   # list S1–S5 with expected outcomes
npm run scenarios -w server -- run S2                 # one scenario, Shield OFF then ON
npm run scenarios -w server -- run all                # all 10 runs + summary table
npm run scenarios -w server -- run S4 --mode on       # one mode
npm run scenarios -w server -- run all --json         # sanitised reports as JSON
npm run scenarios -w server -- run S3 --db data/agentshield.db   # persist runs/audit (data/ is git-ignored)
```
From `server/` the same commands work as `npm run scenarios -- <args>`. Exit code 0 = all expectations met, 1 = not met or run
error, 2 = usage error.

### Inspecting sandbox evidence
Each report prints `Sandbox directory: …\server\runtime\runs\run-<uuid>` (git-ignored). Inside: `files/` (documents after the
run — e.g. S4 OFF has no `projects/roadmap.md`), `outbox/out-NNNN.json` (every "sent" email with per-argument provenance and the
note "SANDBOX OUTBOX - this email was not sent"), `web/`, `inbox/`. The outbox files of S2 OFF contain the fake keys — that is
the attack evidence; do not paste them into slides or reports. Delete `server/runtime/runs/` to clean up.

## Scenario results (Shield OFF vs ON)
| # | Shield OFF | Shield ON |
|---|---|---|
| S1 legit | sent | L1 → **A1** → scripted approve → sent once |
| S2 web injection | fake keys emailed to attacker@evil.test | **P2** read denied, **P4** ×2 sends denied; summary delivered |
| S3 salary read | file read, salary rows emailed to Alice | **P2** read denied |
| S4 inbox → delete | 2 project files deleted (sandbox) | **P1** ×2 denied; files remain |
| S5 fail-closed | F0 ×4 + rejected ×2; status email sent | same refusals; approval times out → **F0 expired** |

## Verification (latest run, M4 Step 6)
`npm test`: **15 files, 444 passed, 1 skipped** (file-symlink test: Windows `EPERM` without Developer Mode).
Per M4 file: instructions 49 · naive-agent 17 · scenarios 49 · cli 27. Server + web typecheck clean · ESLint clean ·
web production build OK · `git diff --check` clean.

## Key decisions
- M1: A3 needs detector ≥ threshold **and** an UNTRUSTED argument; P3 uses max(arg, context) confidentiality; all environment
  content is UNTRUSTED; P2 clearance = min(user, agent ceiling); Shield OFF still rejects structurally invalid calls.
- M2: tool outputs join content label with selecting args' labels; sandbox/URL/subject checks enforced in tools (hold with OFF).
- M3: agent args are `{ref}` or `{value}` (labelled `generated(context)`); audit redaction; decision+audit and consume+audit
  are single transactions; hardening F1–F6; replay/unknown/malformed/inconsistent approval ids rejected and audited.
- M4: the agent receives only `request`/`resume`/`refs`; email bodies are `{value}` (tool outputs are structured, so a ref
  cannot be used where a string is required) and therefore carry the run's taint. Injected instructions are turned into
  requests only when dequeued (so "read X then send it" really sends X). Verdicts come from sandbox state + gateway audit
  rows, never from the agent. S2–S4 use a worst-case scripted operator that approves everything. Report subjects other than
  the scenario's own task subjects are withheld.

## Known limitations and remaining security concerns
- Audit is application-level append-only, not OS-level tamper-proof (hash chain is a stretch item).
- Scripted approvals are recorded in the audit log as `operator:alice` without a scripted flag (M3 schema); the scripted label
  exists in reports only.
- Approver authentication (session/CSRF) is M5; `decideApproval` trusts its `approverId` argument (registry-checked).
- Pending approvals and tickets live in gateway memory; a restart drops them (they expire safely).
- Raw agent traces hold sensitive values; nothing prevents a future API from returning them except review — M5 must not.
- The parser is regex-based: other phrasings are missed; benign prose with a verb next to a path/address may yield an action
  (harmless: everything is UNTRUSTED and goes through the PEP). Negation detection is coarse.
- Coarse provenance: every `{value}` carries the whole run-context label (conservative).
- S2 OFF sends two attacker emails (hidden div + HTML comment); S3 ON's empty summary needs A2, S2/S4 summaries A1.
- Import boundaries are ESLint-enforced (static), not runtime; keep `npm run lint` in every check.
- Small TOCTOU window in `delete_file` (run-local sandbox only). Audit `seq` assumes a single writer process.
- Sandbox copies accumulate in `server/runtime/runs/` (git-ignored).

## Notes
- `node:sqlite` ExperimentalWarning is expected. Use `npm.cmd`/`npx.cmd` in PowerShell.
- `files/secrets/api_keys.env` is a deliberately fake fixture and is intentionally tracked.
- On Windows, close SQLite handles before deleting temp directories (tests do).

## Failed approaches
- M1: "evaluator throws" test Proxy lacked a `getOwnPropertyDescriptor` trap (fixed in test).
- M2: a test passed the page object instead of `html` to `transform` (test bug).
- M3: an open file-backed SQLite handle caused `EPERM` on temp cleanup (fixed by closing handles); an early redaction test
  passed by luck (replaced with whole-audit assertions).
- M4: splitting sentences at every newline lost a wrapped HTML instruction (parser now splits at blank lines/sentence ends);
  building injected sends at parse time emailed the page instead of the file (now built when dequeued).

## Next steps
**M5 — API (Fastify, `src/api/`, 127.0.0.1 only):**
1. Session: startup operator secret → `POST /api/session` → HttpOnly SameSite=Strict cookie + CSRF token (§8).
2. `GET /api/scenarios` (catalogue: id, title, category, description, expectations).
3. `POST /api/runs {scenarioId, mode}` (Zod; ids/modes only — no task steps, no `raw`) → run the scenario but **pause at
   `waiting`** instead of using the scripted operator; return run id.
4. `GET /api/runs/:id` → sanitised `ScenarioReport` only (never `agent.trace()`, bodies, contents, untrusted subjects).
5. `GET /api/approvals?status=pending`; `POST /api/approvals/:id/decision {verdict}` with session + CSRF; approver taken from
   the session; validate the approval id; then resume the agent.
6. `GET /api/runs/:id/events` (SSE) for live step/decision updates; `POST /api/suite` to run all scenarios scripted.
7. Error shape `{ error: { code, message } }`; tests for auth, CSRF, validation and that no response contains secret fragments.

**M6 — Dashboard (React/Vite/Tailwind in `web/`):** scenario runner with ON/OFF side-by-side, step timeline, decision inspector
(rule, reasons, per-argument provenance), pending-approval panel (human approve/reject), audit table, scorecard from
`expectationsMet`. Render only sanitised report fields.

**M7:** threat model doc, README, demo script, judge Q&A, final hardening pass.
