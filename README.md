# AgentShield — Secure the Agent, Not Just the Prompt

PARALLAX 2026 (BMSCE IEEE Computer Society) · Problem Statement 01 · Defensive Cybersecurity

AgentShield is a **provenance-aware policy enforcement point** that sits between a tool-using AI agent and its tools.
Every value the agent handles carries a trust label (where it came from, how sensitive it is). Every tool call is
decided **ALLOW / DENY / REQUIRE_APPROVAL** by a deterministic policy engine, with an inspectable reason and an audit record —
failing closed when policy or provenance is insufficient.

> Status: **M2 complete** — provenance model, deterministic policy engine, per-run sandbox, five sandboxed tools and
> single-use execution tickets are implemented and tested. Gateway, agent, API and dashboard are in progress — see `HACKATHON_HANDOFF.md`.

## Requirements
- Node.js 24+ (uses built-in `node:sqlite`), npm 11+. Windows PowerShell supported (use `npm.cmd` if script execution is blocked).
- No external API keys. No network access needed at runtime.

## Setup
```powershell
npm install
npm test             # server tests
npm run typecheck
npm run dev:server   # API on http://127.0.0.1:3000
npm run dev:web      # dashboard on http://127.0.0.1:5173
```

## Safety
All data is synthetic (`*.northwind.test`, fake keys). The agent's tools act only on a per-run sandbox copy;
there is no real network access, real email, or shell execution.

## Docs
- [Project overview](docs/PROJECT_OVERVIEW.md)
- [System architecture](docs/SYSTEM_ARCHITECTURE.md)
- [Threat model](docs/THREAT_MODEL.md)
- [Database design](docs/DATABASE_DESIGN.md)
- [API specification](docs/API_SPECIFICATION.md)
- [Implementation plan](docs/IMPLEMENTATION_PLAN.md)
- [Technical decisions](docs/TECHNICAL_DECISIONS.md)

## Attribution
Built during PARALLAX 2026 with AI-assisted development (Claude Code). Open-source dependencies are listed in `package.json` files.
