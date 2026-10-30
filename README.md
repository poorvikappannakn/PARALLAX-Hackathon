# AgentShield — Secure the Agent, Not Just the Prompt

PARALLAX 2026 (BMSCE IEEE Computer Society) · Problem Statement 01 · Defensive Cybersecurity

AgentShield is a **provenance-aware policy enforcement point** that sits between a tool-using AI agent and its tools.
Every value the agent handles carries a trust label (where it came from, how sensitive it is). Every tool call is
decided **ALLOW / DENY / REQUIRE_APPROVAL** by a deterministic policy engine, with an inspectable reason and an audit record —
failing closed when policy or provenance is insufficient.

> Status: **judge-ready** — policy engine, gateway, audit, approvals, deterministic simulated agent (not an LLM), five
> predefined scenarios, an **Interactive Attack Lab**, an **Email Security Lab**, an **Untrusted Content Inspector**, an
> **Audit Explorer**, authenticated API with live SSE, and human approval that resumes the same run. See `HACKATHON_HANDOFF.md`.

## What a judge can do
| Page | What it shows |
|---|---|
| Overview | Real counts (runs, allowed/denied actions, pending approvals, attacks blocked), the enforcement path, recent denials |
| Predefined Scenarios | S1–S5 with Shield OFF/ON, live execution, human approval, and the 10-run OFF-vs-ON suite |
| Interactive Attack Lab | Your own task + your own malicious web page/document (typed or `.txt`/`.html` upload ≤ 100 KB), run OFF and ON side by side |
| Email Security Lab | Three synthetic emails (legitimate, secret exfiltration, deletion) or an uploaded `.eml`/`.txt`/`.html` (safe parsing subset) |
| Untrusted Content Inspector | The exact injected sentences, their signals, the tool requests they produced and the PEP decision for each |
| Audit Explorer | Every audit event of the session's runs, filterable, with masked policy reasons |

Labs use the same agent, policy engine, gateway, sandbox and audit as S1–S5: the supplied content is written into each
run's own sandbox and labelled UNTRUSTED by the tools. The agent recognises a small documented set of instruction
patterns (read / send / delete, plus named resources such as "API keys"); everything else is shown as unsupported and
nothing runs for it.

## Requirements
- Node.js 24+ (uses built-in `node:sqlite`), npm 11+. Windows PowerShell supported (use `npm.cmd` if script execution is blocked).
- No external API keys. No network access needed at runtime.

## Run the demo
```powershell
npm install
npm run dev:server   # terminal 1: API on http://127.0.0.1:3000 — prints the operator secret once
npm run dev:web      # terminal 2: dashboard on http://127.0.0.1:5173 — sign in with that secret
```
If ports 3000/5173 are taken, set the same variables in **both** terminals, e.g.
`$env:AGENTSHIELD_API_PORT="3200"; $env:AGENTSHIELD_WEB_PORT="5300"` (the API's Host/Origin allowlists and the Vite proxy
both read them).

## Check
```powershell
npm test                                   # full test suite
npm run typecheck; npm run lint; npm run build -w web
npm run scenarios -w server -- run all     # CLI: all scenarios, Shield OFF vs ON
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
