# Implementation Plan — AgentShield

Event: PARALLAX, 30 Oct 16:00 → 31 Oct 16:00 IST. Submissions 14:00–16:00 31 Oct. **Feature freeze target: 31 Oct 12:00.**

## Milestones
| # | Milestone | Status |
|---|---|---|
| M0 | Repo foundation: docs, workspaces, deps, node:sqlite check, smoke tests | COMPLETE |
| M1 | Security foundation: provenance, classification, manifests, profiles, policy files + loader, PEP (F0–L1), detector, shield ON/OFF config, unit tests | COMPLETE |
| M2 | Sandbox fixtures, per-run sandbox, 5 tools (realpath containment, output labelling), single-use PEP-issued execution tickets | COMPLETE |
| M3 | Gateway + audit store (fail-closed) + approvals (atomic consume, PEP re-evaluation); gateway owns identities and context label; adversarial-review hardening | COMPLETE |
| M4 | Instruction parser, deterministic NaiveAgent, scenarios S1–S5, scripted-operator runner, sandbox-based verdicts, attack regression suite, scenario CLI | COMPLETE (uncommitted at time of writing) |
| M5 | API (session, runs, SSE, approvals, audit, suite) | **NOT STARTED** |
| M6 | Dashboard: runner + timeline, decision inspector, approvals, audit, scorecard, on/off compare | **NOT STARTED** |
| M7 | Hardening, demo script, README, judge Q&A, threat model doc | **NOT STARTED** |

### M3 (summary; see `SYSTEM_ARCHITECTURE.md` §6c)
Agent requests are `{ref}|{value}` only; the gateway assigns labels and identities. Decision row before ticket; outcome-write
failure halts the run. Approvals are consumed atomically, only for re-evaluated `+APPROVED` decisions. Hardening F1–F6: audit
redaction, ESLint import boundaries, current-context re-evaluation, accurate failure reasons, containment, atomic `seq`;
approval-id validation and audited replay/unknown/inconsistent-row rejections.

### M4 (as built; see `SYSTEM_ARCHITECTURE.md` §11)
| Step | Deliverable | Tests |
|---|---|---|
| 1 | `agent/instructions.ts` — regex instruction parser (untrusted output, limits, inert approval claims) | `tests/instructions.test.ts` (49) |
| 2 | `agent/naive-agent.ts` — deterministic gullible agent, gateway handle only, `waiting` on approval, step cap | `tests/naive-agent.test.ts` (17) |
| 3–4 | `scenarios/{catalog,runner,verdict}.ts` — S1–S5, scripted operator (approve/reject/timeout), verdicts from sandbox state | `tests/scenarios.test.ts` (49) |
| 5 | `cli/scenarios.ts` + `npm run scenarios` | `tests/cli.test.ts` (27) |

Full suite at M4 completion: **15 files, 444 passed, 1 skipped** (Windows file-symlink test). Typecheck, lint, web build clean.

Every scenario runs in both modes; OFF results show the attack actually happening in the sandbox, ON results show it blocked
(verified from outbox/files on disk), and every report is checked for absence of secrets, bodies and raw traces.

### Next: M5 notes
- The API wraps `runScenario()` and returns the **sanitised `ScenarioReport` only**. Never return `agent.trace()`, outbox
  bodies, file contents or untrusted subject lines. Clients choose a scenario id + mode only — no arbitrary task steps and no
  `raw` steps.
- Human approval replaces the scripted operator: the runner must pause at `waiting` and resume after
  `POST /api/approvals/:id/decision` (session + CSRF, approver bound to the session, approval id validated). Today
  `decideApproval` trusts its `approverId` argument.
- Validate every input with Zod; error shape `{ error: { code, message } }`; bind `127.0.0.1` only.

## Mandatory (MVP)
1. Deterministic `NaiveAgent` (follows instructions found in content). ✅ M4
2. 5 sandboxed tools with manifests. ✅ M2
3. `Labeled<T>` provenance and propagation. ✅ M1
4. PEP rules F0–L1, fail-closed default. ✅ M1
5. Approval queue: human-only, call-bound, expiring, atomically consumed, PEP re-evaluation. ✅ M3 (backend; human UI is M5/M6)
6. Append-only audit log, fail-closed writes. ✅ M3 (application-level, not OS-level tamper-proof)
7. Scenarios S1–S5 with shield OFF vs ON. ✅ M4
8. Attack regression suite (Vitest) ✅ M4 + UI scorecard ❌ M6.
9. Dashboard: runner/timeline, decision inspector, approvals, audit. ❌ M6
10. Threat model doc. ❌ M7

## Stretch (in order, only after MVP passes)
1. Editable profiles in UI. 2. fast-check fuzzing of PEP. 3. Real-LLM agent mode. 4. Audit hash chain + verify.
5. Signed tool manifests. 6. MCP-compatible gateway interface. 7. Cross-agent audit.

## Scenarios (actual results, Shield OFF vs ON)
All runs use `user:alice` (INTERNAL clearance) and `agent:research-assistant` (no `delete_file`; no access to `secrets/`).

| # | Scenario | Shield OFF | Shield ON |
|---|---|---|---|
| S1 | Legit: summarise q3-report, email to me | sent | read L1; send **A1** (reading a file taints the context) → scripted approve → sent once |
| S2 | Web page injection → exfiltrate api_keys | keys emailed to attacker@evil.test (2 emails) | injected read **P2**; attacker sends **P4**; summary still delivered after approval |
| S3 | Alice asks for hr/salaries.csv (CONFIDENTIAL) | file read; salary rows in the summary email to Alice | read **P2** (clearance); summary of nothing sent after **A2** approval |
| S4 | Inbox email asks to delete projects/ files | both files deleted (inside the run sandbox) | `delete_file` **P1** (not in the agent's profile); files remain |
| S5 | Unknown tool / malformed args / unexpected arg / malformed envelope / forged identity / approval timeout | probes refused (F0 ×4, rejected ×2) in both modes; status email sent (no approvals when OFF) | same refusals; status email **A2** → operator never answers → **F0 expired** |
