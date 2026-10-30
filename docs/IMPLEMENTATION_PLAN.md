# Implementation Plan — AgentShield

Event: PARALLAX, 30 Oct 16:00 → 31 Oct 16:00 IST. Submissions 14:00–16:00 31 Oct. **Feature freeze target: 31 Oct 12:00.**

## Milestones
| # | Milestone | Status |
|---|---|---|
| M0 | Repo foundation: docs, workspaces, deps, node:sqlite check, smoke tests | COMPLETE |
| M1 | Security foundation: provenance, classification, manifests, profiles, policy files + loader, PEP (F0–L1), detector, shield ON/OFF config, unit tests | COMPLETE |
| M2 | Sandbox fixtures, per-run sandbox, 5 tools (realpath containment, output labelling), single-use PEP-issued execution tickets | COMPLETE |
| M3 | Gateway + audit store (fail-closed) + approvals (atomic consume, PEP re-evaluation); gateway owns identities and context label | COMPLETE |
| M4 | NaiveAgent + scenarios S1–S5 + attack regression suite (CLI) | NEXT — not started |
| M5 | API (session, runs, SSE, approvals, audit, suite) | not started |
| M6 | Dashboard: runner + timeline, decision inspector, approvals, audit, scorecard, on/off compare | not started |
| M7 | Hardening, demo script, README, judge Q&A | not started |

### M3 security work (all resolved in M3, see `SYSTEM_ARCHITECTURE.md` §6c)
- **[HIGH] Provenance trust boundary — resolved:** agent requests are `{ref}|{value}` only; the gateway assigns all labels and
  identities and owns the grow-only context label.
- Decision audit row written before a ticket is issued; outcome-write failure halts the run — implemented and tested.
- Approvals consumed atomically, only for re-evaluated `+APPROVED` decisions — implemented and tested.

### M3 hardening (adversarial review) — COMPLETE
F1 audit redaction across all fields · F2 agent import restrictions · F3 gateway-only execution imports · F4 re-evaluation with
current context · F5 accurate failure reasons · F6 error containment and atomic audit sequencing. Regression tests in
`tests/gateway.test.ts` ("M3 hardening") and `tests/import-boundaries.test.ts`.

### M4 notes
- The agent must use only the gateway handle (`request`, `resume`, `refs`), injected by the runner; ESLint allows `src/agent/**`
  only type imports from `gateway/gateway` (see `tests/import-boundaries.test.ts`). The scenario runner should live outside
  `src/agent/` (e.g. `src/scenarios/`) but may not import tickets/executor — it calls `startRun` and `decideApproval`.

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
| S5 | Unknown tool / malformed args / approval timeout | unknown tool & malformed args are rejected structurally in both modes (nothing valid to run); approval timeout cannot occur (no approvals when OFF) | F0 DENY |
