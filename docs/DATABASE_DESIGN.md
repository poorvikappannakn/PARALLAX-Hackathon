# Database Design — AgentShield

Engine: Node 24 built-in `node:sqlite` (`DatabaseSync`). Implemented in `server/src/audit/store.ts` (`createStores(db)`).
Default file `data/agentshield.db` (git-ignored); tests use `:memory:` or temp files.

Policies, tool manifests, agent profiles, operators and data classification are **versioned files** in `server/src/policy/`, not tables.

**Integrity guarantee:** `audit_events` is *application-level* append-only — the code exposes no update or delete for it
(`AuditStore` has only `createRun`, `getRun`, `setRunStatus`, `append`, `listEvents`). This is **not** OS-level tamper-proofing:
anyone with write access to the database file can alter it. Hash chaining for tamper *detection* is a stretch item.

## Tables
### runs
`id` PK · `scenario_id` · `shield_mode` ('on'|'off') · `policy_id` (`<id>@<version>` or `none`) · `user_id` · `agent_id` ·
`status` (running, awaiting_approval, completed, halted, audit_failure, error) · `started_at` · `ended_at`.
`status` is informational and may be updated; audit rows are the source of truth.

### audit_events (append-only)
| Column | Notes |
|---|---|
| id | INTEGER PK AUTOINCREMENT |
| run_id, seq | FK → runs; `seq` monotonic per run; UNIQUE(run_id, seq) |
| ts | ISO-8601 |
| kind | run_started, request_rejected, decision, approval_requested, approval_decided, re_decision, outcome, run_halted |
| user_id, agent_id, shield_mode, policy_id | identity and policy evidence on every row (from server-side run state) |
| tool | |
| args_json | argument values; CONFIDENTIAL/SECRET values replaced with `[REDACTED <level>]` (the same values are also scrubbed from reasons and details) |
| provenance_json | per-argument labels (never redacted) |
| context_json | run context label at decision time |
| decision, rule_id, reasons_json, risk, detector_json | PEP decision evidence; `detector_json` = `{score, patterns:[{pattern, weight}]}` (no content excerpts) |
| call_hash | binding hash (tool, labelled args, run, agent, user, policy version) |
| approval_id | for approval-related rows |
| outcome | executed, failed, blocked |
| detail_json | kind-specific detail (e.g. output label, error code, approver id) |

Index: `(run_id, seq)`. `seq` is allocated inside the INSERT statement (`SELECT COALESCE(MAX(seq),0)+1 …`), so allocation and
insert are atomic; with the single-process demo there is one writer, and `UNIQUE(run_id, seq)` makes any conflicting writer fail.

### approvals
`id` PK (`appr-<uuid>`) · `run_id` FK · `audit_event_id` FK (the decision row) · `tool` · `call_hash` · `requester_id` (agent) ·
`status` (pending, approved, rejected) · `approver_id` · `created_at` · `decided_at` · `expires_at` (epoch ms) · `used` · `consumed_at`.
Index: `(status)`.

- Decide: `UPDATE ... SET status=?, approver_id=?, decided_at=? WHERE id=? AND status='pending' AND used=0` (must change 1 row),
  in the same transaction as the `approval_decided` audit row.
- Consume: `UPDATE ... SET used=1, consumed_at=? WHERE id=? AND used=0 AND status='approved' AND expires_at>? AND call_hash=?`
  (must change 1 row), in the same transaction as the `re_decision` audit row. Expiry is evaluated from `expires_at`.
- Replay / unknown id: a `resume` with no stored call in the run writes a `request_rejected` audit row (`approval_id` + fixed
  reason in `detail_json`, no argument values) and touches no approval row; if that audit write fails the run halts.
  Ids not matching the generated format (`appr-<lowercase uuid v4>`, exactly 41 chars) are audited as
  `request_rejected` "Malformed approval id" with `approval_id` NULL; the caller's input is never stored.

## Lifecycle
Delete `data/` to reset. Per-run sandbox copies live in `server/runtime/runs/<runId>/` (git-ignored).
