# HACKATHON HANDOFF — AgentShield

_Last updated: 2026-10-31, M7 complete (judge-ready). Committed: M0–M4 and the M5.1 session refactor (`runner.ts`, HEAD
43e6f25). Uncommitted at time of writing: `api/views.ts` + M5.1 tests, and all of M5.2–M7._

## Launch the demo
```powershell
npm install
# Terminal 1 (repository root). If 3000/5173 are busy, use e.g. 3200/5300 — set the SAME values in both terminals.
$env:AGENTSHIELD_API_PORT="3000"; $env:AGENTSHIELD_WEB_PORT="5173"; npm run dev:server   # prints the operator secret ONCE
# Terminal 2 (repository root)
$env:AGENTSHIELD_API_PORT="3000"; $env:AGENTSHIELD_WEB_PORT="5173"; npm run dev:web
```
Open `http://127.0.0.1:<web port>` and sign in with the secret. Script: `docs/DEMO_SCRIPT.md`. Q&A: `docs/JUDGE_QA.md`.
Note: on the dev machine 3000/5173 were occupied by unrelated processes (not ours) — the port variables exist for that.

## What we are building
PARALLAX PS-01 AgentShield: a provenance-aware, deterministic policy enforcement point (PEP) between a simulated agent and
5 sandboxed tools, with an authenticated local dashboard. Architecture: `docs/SYSTEM_ARCHITECTURE.md`. Hard rules: `CLAUDE.md`.
API: `docs/API_SPECIFICATION.md`. Threat model: `docs/THREAT_MODEL.md`.

## Honesty constraints (for the demo and judges)
- **The agent is a deterministic, rule-based simulation — NOT an LLM** (regex instruction parser, gullible on purpose;
  "summaries" are first-lines extracts, labelled as such).
- **Approvals in the CLI and the ON/OFF suite are SCRIPTED** (recorded in the audit log as `operator:alice`; labelled scripted
  in reports). Dashboard runs are approved by the signed-in human operator (`actor: "human"`).
- **Raw agent traces contain sensitive values** and are never exposed: the API/UI use explicit allowlist projections only
  (`server/src/api/views.ts`) — no traces, argument values, email bodies or subjects, file contents, hashes or paths.
- **The `raw` task step is an internal test mechanism** (S5 probes), not an API capability (clients send scenario id + mode only).
- **The audit store is application-level append-only, not OS-level tamper-proof.**
- All data is synthetic; everything runs in a per-run sandbox copy; no real network or email.

## Safeguards (implemented and tested)
1. Approvals are bound to hash(tool, canonical args incl. provenance, runId, agentId, userId, policyVersion), re-evaluated by
   the PEP (DENY first, never overridable) and consumed atomically once; expiry ⇒ F0.
2. Audit fails closed: no execution without a decision row; outcome-write failure halts the run (shown as **failed** in the UI).
3. The gateway owns identities, labels and the grow-only context label; nothing is taken from agent output.
4. Tools run only with a single-use, call-bound ticket for a PEP ALLOW; only `src/gateway/**` may import tickets + executor.
5. CONFIDENTIAL/SECRET values never appear in audit fields; unknown names and malformed approval ids are not stored verbatim.
6. API: operator session (HttpOnly, SameSite=Strict), per-session CSRF token, Host/Origin allowlists, JSON-only ≤ 1 KB,
   login rate limit, safe errors, loopback-only bind; the approver identity always comes from the session.

## Milestones
| # | Milestone | Status |
|---|---|---|
| M0–M3 | Foundation, PEP/provenance, sandbox/tools/tickets, gateway/audit/approvals + hardening | COMPLETE (committed) |
| M4 | Parser, NaiveAgent, scenarios S1–S5, verdicts, regression suite, CLI | COMPLETE (committed) |
| M5 | Sessions/views, auth+CSRF, runs+registry, human approval (same-run resume), SSE, suite, dashboard | COMPLETE |
| M6 | Dashboard | COMPLETE (delivered in M5.6) |
| M7 | Hardening review, S5 clarification, doc refresh, demo script, judge Q&A | COMPLETE |

## Code map (server/src)
| Area | Files |
|---|---|
| Policy core (M1–M2) | `shield/*` (provenance, PEP, tickets, detector, paths), `policy/*`, `sandbox/sandbox.ts`, `tools/*` |
| Gateway, audit, approvals (M3) | `gateway/gateway.ts`, `gateway/approvals.ts`, `audit/store.ts`, `db/sqlite.ts` |
| Agent and scenarios (M4) | `agent/instructions.ts`, `agent/naive-agent.ts` (optional per-call budget for live runs), `scenarios/{catalog,runner,verdict}.ts`, `cli/scenarios.ts` |
| API (M5) | `api/app.ts` (guards), `api/session.ts`, `api/errors.ts`, `api/routes.ts`, `api/views.ts` (allowlists), `api/runs.ts` (registry, human decisions, SSE), `api/suite.ts`; entry `index.ts` |
| Dashboard (M5.6) | `web/src/{App,RunPage,SuitePage}.tsx`, `api.ts`, `types.ts`, `ui.tsx`; `web/vite.config.ts` (proxy) |

## Commands (verified against package scripts)
```
npm test                                   # full suite
npm run typecheck                          # server + web
npm run lint                               # server ESLint incl. import boundaries
npm run build -w web                       # dashboard production build
npm run scenarios -w server -- list | run S2 | run all [--mode on|off] [--json] [--db data/x.db]
```
CLI exit codes: 0 all expectations met · 1 not met / run error · 2 usage error. Sandbox copies: `server/runtime/runs/` (git-ignored;
S2 OFF outbox files contain the fake keys — that is the attack evidence, do not paste it into slides).

## Scenario results (Shield OFF vs ON; identical in the CLI, the suite and the dashboard)
| # | Shield OFF | Shield ON |
|---|---|---|
| S1 legit | sent | L1 → **A1** → approve → same run resumes → sent once |
| S2 web injection | fake keys emailed to attacker@evil.test (2 emails) | **P2** read denied, **P4** ×2 sends denied; summary delivered after approval |
| S3 salary read | file read, salary rows emailed to Alice | **P2** read denied |
| S4 inbox → delete | 2 project files deleted (sandbox) | **P1** ×2 denied; files remain |
| S5 fail-closed | F0 ×4 + rejected ×2; status email sent (no approvals when OFF) | same refusals; unanswered approval → **F0 expired** (a human may instead approve the legitimate email — then "not matched", explained in the UI) |

## Verification (latest run, M7)
- `npm test`: **21 files, 585 passed, 1 skipped** (file-symlink test: Windows `EPERM` without Developer Mode).
  Per M5/M7 file: api-auth 56 · api-runs 32 · api-sse 14 · api-suite 2 · views 18 · scenario-session 8.
- Server + web typecheck, ESLint, web production build, `git diff --check`: clean. CLI exit codes 0/0/2 (`list`, `run all`, `run S9`).
- CLI output and all scripted scenario reports are **byte-identical** to the pre-M5 baseline (ids/timestamps normalised).
- Real-browser E2E (headless Chrome via DevTools Protocol, real API + Vite, fresh profile): sign-in → S5 note → S1 approval
  (same run completes) → S2 OFF (attack succeeded, live steps) → S2 ON (P2/P4, provenance, masked untrusted path) → approve →
  same run resumes → audit trail → suite (10 runs, 10/10, 3 vs 0); no console errors; no secrets/subjects/paths rendered.

## M7 changes
- **Fix (with regression test):** a gateway halt (fail-closed, e.g. audit write failure) was streamed/shown as `done`; it is now
  `failed` (`api/runs.ts`, test in `api-sse.test.ts`).
- **S5 clarification:** catalogue `expectationNote` (fixed text) exposed in the scenario and run views and shown in the UI;
  enforcement unchanged (test in `api-runs.test.ts`).
- Docs: README, API spec, architecture (§2, §6, §8, §11.6), threat model (API rows), plan, this handoff; new demo script and Q&A.

## Known limitations
- Simulated agent; regex parser misses other phrasings; coarse provenance for agent-generated values (conservative).
- In-memory sessions, live runs and pending approvals (lost on restart; approvals then expire). One fixed operator; anyone who
  can read the API console can sign in. Login limit is effectively global on loopback. No `Secure` cookie on plain HTTP.
- Audit is not OS-level tamper-proof (hash chain is future work). Suite approvals are scripted but recorded as `operator:alice`.
- Import boundaries are ESLint-enforced (static). Small TOCTOU window in `delete_file` (run sandbox only). Single-writer audit `seq`.
- Not tested: the 15 s heartbeat at its real interval (tested at 30 ms), Edge/Firefox, narrow mobile layouts.

## Notes and failed approaches
- `node:sqlite` ExperimentalWarning is expected. Use `npm.cmd`/`npx.cmd` in PowerShell. Close SQLite handles before deleting temp dirs.
- `files/secrets/api_keys.env` is a deliberately fake fixture and is intentionally tracked.
- M4: newline-splitting lost a wrapped HTML instruction; injected sends built at parse time emailed the page (both fixed).
- M5: SSE initially closed on the request's `close` event (fires once a GET is read) — now the response's. A test imported
  another test file and ran its tests twice — shared data moved to `tests/api-harness.ts`.
