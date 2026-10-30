# HACKATHON HANDOFF — AgentShield

_Last updated: 2026-10-30, after M0 (project foundation)._

## What we are building
PARALLAX PS-01 AgentShield. Provenance-aware deterministic PEP between a simulated agent and 5 sandboxed tools.
Approved architecture: `docs/SYSTEM_ARCHITECTURE.md` (v2.1) + `CLAUDE.md` hard constraints. Deadline: submissions close 31 Oct 16:00 IST; feature freeze 12:00.

## Approved safeguards (must hold)
1. Approval atomically consumed, bound to hash(tool, canonical args, runId, agentId, policyVersion); PEP re-evaluates before execution; DENY never overridable.
2. Audit fails closed: no execution without decision row; outcome-write failure halts run (`audit_failure`).

## State
| Milestone | Status |
|---|---|
| M0 Foundation | **done** |
| M1–M8 | not started (see `docs/IMPLEMENTATION_PLAN.md`) |

### Done in M0
- Docs: CLAUDE.md, README, docs/* (overview, architecture, threat model, DB, API, plan, decisions).
- npm workspaces: `server/` (Fastify 5, Zod 4, yaml, node:sqlite, Vitest 5, tsx, TS 6, ESLint 10) and `web/` (React 19, Vite 8, Tailwind 4).
- `server/src/index.ts`: `/api/health` on 127.0.0.1:3000. `server/src/db/sqlite.ts`: DB opener (WAL, FKs).
- `server/tests/environment.test.ts`: Node ≥24, transactions/rollback, single-use `UPDATE ... changes` semantics.
- ESLint `no-restricted-imports`: `src/agent/**` cannot import tools (verified it fires).
- `web/`: placeholder page calling `/api/health` via Vite proxy.

### Verified
`npm test` 3/3 pass · typecheck server+web clean · lint clean · web build OK · server health returns `{"ok":true,"node":"v24.11.0","sqlite":"3.50.4"}`.

## Known issues / notes
- `node:sqlite` prints ExperimentalWarning (expected; PowerShell shows it as NativeCommandError — harmless).
- Use `npm.cmd`/`npx.cmd` in PowerShell.
- Default DB path `data/agentshield.db` (git-ignored); override with `DB_FILE`.

## Failed approaches
None yet.

## Next task
M1: provenance types (`shield/provenance.ts`), policy files (tool manifests, agent profiles, data classification, `policy.yaml`, `policy.permissive.yaml`), synthetic sandbox fixtures (`server/sandbox/`). Await user instruction before starting.
