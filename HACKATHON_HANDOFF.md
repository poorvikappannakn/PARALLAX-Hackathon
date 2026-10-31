# HACKATHON HANDOFF — AgentShield

_Last updated: 2026-10-31. Committed and pushed: everything up to `87aff7d` (labs, inspector, audit explorer). Uncommitted: the security-analysis layer (advisory content analysis) and URL-risk enforcement for `fetch_web` at the PEP (rules U1/U2, enforce policy 1.1.0) — see "Security analysis and URL-risk enforcement" below._

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

## Verification (M7 — historical)
- `npm test`: **21 files, 585 passed, 1 skipped** (file-symlink test: Windows `EPERM` without Developer Mode).
  Per M5/M7 file: api-auth 56 · api-runs 32 · api-sse 14 · api-suite 2 · views 18 · scenario-session 8.
- Server + web typecheck, ESLint, web production build, `git diff --check`: clean. CLI exit codes 0/0/2 (`list`, `run all`, `run S9`).
- CLI output and all scripted scenario reports are **byte-identical** to the pre-M5 baseline (ids/timestamps normalised).
- Real-browser E2E (headless Chrome via DevTools Protocol, real API + Vite, fresh profile): sign-in → S5 note → S1 approval
  (same run completes) → S2 OFF (attack succeeded, live steps) → S2 ON (P2/P4, provenance, masked untrusted path) → approve →
  same run resumes → audit trail → suite (10 runs, 10/10, 3 vs 0); no console errors; no secrets/subjects/paths rendered.

## Labs, inspector, audit explorer (post-M7)
- **Interactive Attack Lab / Email Security Lab** (`server/src/scenarios/{lab,email,inspector}.ts`, routes in `api/routes.ts`,
  UI `web/src/{AttackLab,EmailLab,LabResults,Inspector,AuditExplorer}.tsx`). A lab run is a normal session from a server-side
  definition (`createSessionFromDef`): same agent, user, tools, gateway, PEP, approvals, audit, SSE and capacity as S1–S5. The
  content is written into that run's own sandbox (web page on the allowlisted host, `public/` document, or the run's inbox)
  under a server-generated name; tools label it UNTRUSTED. "Compare" = two isolated runs with the same input.
- **Parser extension** (`agent/instructions.ts`): a fixed named-resource table used only when no explicit path is given
  ("API keys" → `secrets/api_keys.env`, "salary data" → `hr/salaries.csv`, "project documentation" → the two project
  files) and `analyzeInstructions()` for the inspector. `parseInstructions()` output for S1–S5 is unchanged (byte-identical
  CLI/report baseline).
- **Email parsing**: documented safe subset, no dependency — headers with folding; text/plain or text/html; text-only
  multipart/alternative|mixed, depth ≤ 2; 7bit/8bit/QP/base64; utf-8/us-ascii/latin1; attachments and anything else rejected.
- **Task interpretation**: "summarise/report/email me" → read + email summary; "read/review/check" → read only; else 422.
- **Verification (historical — at labs completion, commit `87aff7d`):** backend 23 files, 632 passed, 1 skipped; real-browser workflow A–H passed.

## Security analysis and URL-risk enforcement (post-labs, uncommitted)
- **Advisory content analysis** (`server/src/analysis/{instruction-threat,url-analyzer,assessment}.ts`): separate source trust /
  instruction threat / URL risk, evidence-based alerts, outgoing-email content check. Rule-based and offline. The instruction
  analysis and all content-level results are advisory — the PEP never reads them. Design: `docs/SECURITY_DESIGN.md`.
  Exposed via `/api/runs/:id/content` (`assessment`, `enforcement`, `outgoing`), `/api/approvals` (`outgoing`) and `/api/audit`
  (`threat`); UI: `web/src/Assessment.tsx` in the inspector, level badges in the Audit Explorer. Alerts state the real per-run
  outcome (Shield ON/OFF; executed / denied / awaiting approval).
- **URL-risk enforcement — `fetch_web` only** (`shield/pep.ts`, `shield/rules.ts`, `policy/policy.yaml` → version **1.1.0**): the PEP
  re-runs the offline URL analyzer on the URL of each `fetch_web` call (never a client-supplied or earlier result; nothing is
  fetched or resolved). **HIGH ⇒ U1 DENY** (a DENY rule, never sent for approval, cannot be approved); **MEDIUM ⇒ U2
  REQUIRE_APPROVAL** (normal approval safeguards); **LOW / UNKNOWN ⇒ existing behaviour** (UNKNOWN adds an advisory reason).
  P2's exact-host https allowlist still applies first, so e.g. `https://paypa1.com/verify` is denied by P2 (and by U1 if it were
  ever allow-listed). Shield OFF and other tools are unchanged.
- **Why a suspicious link in page content does not cause a `fetch_web`:** `fetch_web` only fetches the task's own page (S2's
  fixture or the lab page on the allow-listed `vendor.contoso.test`), which is UNKNOWN risk ⇒ L1 "Allowed". Links *inside* that
  content are never requested: the agent's instruction parser has no fetch/visit action. Their risk is shown as **URL risk**
  in the Security Assessment (advisory), separate from tool decisions.
- **Tests:** `server/tests/security-analysis.test.ts` (**42**: I1–I13, S5–S7, analyzer URL cases U1–U10 — not the PEP rules —,
  review regressions, analyzer-LOW-but-PEP-denies, mode-accurate alerts, outgoing check); `server/tests/pep-url-risk.test.ts`
  (**9**: look-alikes ⇒ P2/U1 DENY, official domains unchanged, UNKNOWN unchanged with warning, MEDIUM ⇒ U2 and approval
  safeguards, HIGH not overridable by approval, URL swap after approval, Shield OFF permissive, unrelated tools unaffected).
- **Verification (latest):** backend **25 files, 683 passed, 1 skipped**; typecheck, lint, web build clean. S1–S5 decisions
  unchanged; S2 ON's `fetch_web` decision carries the new advisory "URL risk UNKNOWN" reason. Browser workflow A–H last passed
  before the U1/U2 and "URL risk" label changes (re-run before the demo).

## M7 changes
- **Fix (with regression test):** a gateway halt (fail-closed, e.g. audit write failure) was streamed/shown as `done`; it is now
  `failed` (`api/runs.ts`, test in `api-sse.test.ts`).
- **S5 clarification:** catalogue `expectationNote` (fixed text) exposed in the scenario and run views and shown in the UI;
  enforcement unchanged (test in `api-runs.test.ts`).
- Docs: README, API spec, architecture (§2, §6, §8, §11.6), threat model (API rows), plan, this handoff; new demo script and Q&A.

## Known limitations
- Labs: the agent recognises only a small documented instruction vocabulary; uploads are UTF-8 text in JSON (non-UTF-8 `.eml`
  bytes may be decoded lossily by the browser); the email parser is a subset, not full MIME; a "Compare" uses two of the 10
  run slots; the inspector intentionally shows the untrusted INPUT text (rendered as inert React text, CSP default-src 'none').
- No frontend unit-test suite; the UI is verified by the real-browser end-to-end script.
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
