# Database Design — AgentShield

Engine: Node 24 built-in `node:sqlite` (`DatabaseSync`), file `data/agentshield.db` (git-ignored).
Fallback if `node:sqlite` misbehaves: `better-sqlite3`, or append-only JSONL.

Policies, tool manifests, agent profiles and data classification are **versioned files** in `server/src/policy/`, not tables.

## Tables
### runs
| Column | Type | Notes |
|---|---|---|
| id | TEXT PK | uuid |
| scenario_id | TEXT NOT NULL | S1–S5 |
| shield_mode | TEXT NOT NULL CHECK IN ('on','off') | |
| policy_id | TEXT NOT NULL | e.g. `policy.yaml@<version>` |
| user_id | TEXT NOT NULL | |
| agent_id | TEXT NOT NULL | |
| status | TEXT NOT NULL | running, awaiting_approval, completed, halted, audit_failure, error |
| started_at / ended_at | TEXT | ISO-8601 |

### audit_events (application-level append-only)
| Column | Type | Notes |
|---|---|---|
| id | INTEGER PK AUTOINCREMENT | |
| run_id | TEXT NOT NULL FK → runs.id | |
| seq | INTEGER NOT NULL | monotonic per run; UNIQUE(run_id, seq) |
| ts | TEXT NOT NULL | |
| kind | TEXT NOT NULL | decision, re_decision, outcome, run_event |
| tool | TEXT | |
| args_json | TEXT | redacted where confidential |
| provenance_json | TEXT | per-argument labels + context label |
| decision | TEXT | ALLOW, DENY, REQUIRE_APPROVAL |
| rule_id | TEXT | |
| reasons_json | TEXT | |
| risk | INTEGER | 0–100 |
| detector_json | TEXT | |
| call_hash | TEXT | |
| shield_mode / policy_id | TEXT | evidence for on/off comparison |
| outcome | TEXT | executed, blocked, failed |
| prev_hash / hash | TEXT NULL | **stretch** hash chain |

Index: `(run_id, seq)`. No UPDATE/DELETE statements exist for this table in application code.

### approvals
| Column | Type | Notes |
|---|---|---|
| id | TEXT PK | |
| run_id | TEXT NOT NULL FK | |
| audit_event_id | INTEGER NOT NULL FK | |
| call_hash | TEXT NOT NULL | sha256(tool, canonical args, runId, agentId, policyVersion) |
| requester_id | TEXT NOT NULL | agent principal |
| status | TEXT NOT NULL | pending, approved, rejected, expired |
| approver_id | TEXT | must differ from requester_id |
| created_at / decided_at / expires_at / consumed_at | TEXT | |
| used | INTEGER NOT NULL DEFAULT 0 | atomic consume: `UPDATE ... WHERE id=? AND used=0 AND status='approved' AND expires_at>?` → changes must be 1 |

Index: `(status)`.

## Lifecycle
Demo data is reset by deleting `data/`. Sandbox files are copied per run to `server/runtime/runs/<runId>/` (git-ignored) and may be cleaned at any time.
