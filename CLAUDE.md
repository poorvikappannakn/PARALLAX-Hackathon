# CLAUDE.md — AgentShield permanent project instructions

AgentShield is our entry for **PARALLAX 2026, Problem Statement 01 (AgentShield — AI-agent / tool-use security)**.
It is a provenance-aware policy enforcement point (PEP) that sits between a simulated AI agent and its tools.

Read `HACKATHON_HANDOFF.md` first for the current state. Architecture lives in `docs/SYSTEM_ARCHITECTURE.md`.

## Hard constraints (never violate)
1. **Every tool execution goes through `ToolGateway` → `PEP.evaluate`.** No other code path may call a tool's `execute`.
   - `server/src/agent/**` must never import `server/src/tools/**` (enforced by ESLint `no-restricted-imports`).
   - Tools only execute with a PEP-issued, single-use ALLOW decision.
2. **DENY rules (F0, P1–P4) are never overridable**, including by human approval.
3. **Approval re-evaluation:** after approval the gateway calls the PEP again. An approval satisfies REQUIRE_APPROVAL only if it is
   `approved`, unexpired, unused, and bound to the exact canonical call hash = hash(tool, canonical args, runId, agentId, policyVersion).
   Consumption is atomic (`UPDATE ... WHERE used=0` must change exactly 1 row) and happens before execution.
4. **Audit fails closed.** A tool must not execute unless its decision audit row was written successfully.
   If the outcome row fails to write after a sandbox action, halt the run (status `audit_failure`) and report it; no further actions.
5. **Shield off changes only the policy** (`policy.permissive.yaml`). Same agent, tools, fixtures, sandbox, gateway and audit.
6. **Fail closed** on unknown tools, invalid args, missing/malformed labels, policy load errors, evaluator exceptions, approval timeout.
7. **No real side effects.** No real network calls, no real email, no shell tool, no filesystem access outside the per-run sandbox copy.
   `fetch_web` reads local fixture files; `send_email` writes to the sandbox outbox.
8. **All data synthetic.** `.test` domains, fake keys, fake people. Never add real personal data or real secrets.
9. **The agent never receives operator/approver credentials** or session cookies, and has no HTTP client.
10. Server binds to `127.0.0.1` only.

## Scope discipline
- Mandatory vs stretch features are fixed in `docs/IMPLEMENTATION_PLAN.md`. Do not build stretch items until all mandatory items pass.
- No external LLM key is required for the MVP. Real-LLM mode is stretch.

## Stack
TypeScript everywhere. npm workspaces: `server/` (Node 24, Fastify, Zod, `node:sqlite`, YAML, Vitest, tsx) and `web/` (React, Vite, Tailwind).
No Python. Avoid TS `enum` and parameter properties (keep code compatible with Node type stripping); use string-literal unions.

## Coding conventions
- ESM modules, `strict` TypeScript, no `any` in shield/ code.
- PEP (`shield/pep.ts`) is a **pure function**: no I/O, no clock reads (pass `now` in), deterministic.
- Every decision carries `ruleId`, human-readable `reasons[]`, per-argument provenance, and risk.
- Validate all external input with Zod. Error shape: `{ error: { code, message } }`.
- Small, readable modules; comment only non-obvious security reasoning.

## Testing rules
- `npm test` must pass before declaring any milestone done.
- Every policy rule has at least one positive and one negative test.
- Attack regression suite: each scenario runs shield OFF (attack must succeed) and shield ON (attack must be blocked, legit task must work, audit rows must exist).
- Never mark a feature complete without running it.

## Windows / environment notes
- PowerShell; if `npm` scripts are blocked use `npm.cmd`. Node 24.11 prints an ExperimentalWarning for `node:sqlite` — expected.
- Path containment must handle backslashes, case, drive letters, UNC, `..`, and symlinks/junctions (resolve + realpath + prefix check).
- Canonicalise line endings (LF) before hashing.

## Git rules
- **Claude never runs `git commit` or `git push`** and never rewrites history. Claude prepares grouped commands; the user runs them.
- Never stage `.env`, `*.db`, `data/`, `server/runtime/`, `node_modules/`.
- Conventional commits (`feat:`, `fix:`, `docs:`, `chore:`, `test:`).

## Handoff
Update `HACKATHON_HANDOFF.md` after every milestone and on "PREPARE CHATGPT HANDOFF".
