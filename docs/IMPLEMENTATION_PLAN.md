# Implementation Plan — AgentShield

Event: PARALLAX, 30 Oct 16:00 → 31 Oct 16:00 IST. Submissions 14:00–16:00 31 Oct. **Feature freeze target: 31 Oct 12:00.**

## Milestones
| # | Milestone | Status |
|---|---|---|
| M0 | Repo foundation: docs, workspaces, deps, node:sqlite check, smoke tests | done |
| M1 | Provenance types, policy files (manifests, profiles, classification), sandbox fixtures | todo |
| M2 | Tools (sandbox containment, labelling, ticket check) | todo |
| M3 | PEP (rules F0–L1) + detector + unit tests | todo |
| M4 | Audit store (fail-closed) + approvals (atomic consume) + gateway | todo |
| M5 | NaiveAgent + scenarios S1–S5 + attack regression suite (CLI) | todo |
| M6 | API (session, runs, SSE, approvals, audit, suite) | todo |
| M7 | Dashboard: runner + timeline, decision inspector, approvals, audit, scorecard, on/off compare | todo |
| M8 | Hardening, demo script, README, judge Q&A | todo |

## Mandatory (MVP)
1. Deterministic `NaiveAgent` (follows instructions found in content).
2. 5 sandboxed tools with manifests.
3. `Labeled<T>` provenance and propagation.
4. PEP rules F0–L1, fail-closed default.
5. Approval queue: human-only, call-bound, expiring, atomically consumed, PEP re-evaluation.
6. Append-only audit log, fail-closed writes.
7. Scenarios S1–S5 with shield OFF vs ON.
8. Attack regression suite (Vitest) + UI scorecard.
9. Dashboard: runner/timeline, decision inspector, approvals, audit.
10. Threat model doc.

## Stretch (in order, only after MVP passes)
1. Editable profiles in UI. 2. fast-check fuzzing of PEP. 3. Real-LLM agent mode. 4. Audit hash chain + verify.
5. Signed tool manifests. 6. MCP-compatible gateway interface. 7. Cross-agent audit.

## Scenarios
| # | Scenario | Shield OFF | Shield ON |
|---|---|---|---|
| S1 | Legit: summarise q3-report, email to me | sent | READ ALLOW; send REQUIRE_APPROVAL (A2) → approve → sent |
| S2 | Web page injection → exfiltrate api_keys | secret emailed to attacker | P2 DENY on secret read; P4/P3 DENY on send; summary still delivered |
| S3 | User asks for salaries | data emailed | P2 DENY |
| S4 | Inbox email asks to delete projects/ | files deleted (sandbox) | P1 DENY |
| S5 | Unknown tool / malformed args / approval timeout | runs or crashes | F0 DENY |
