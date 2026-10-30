# Technical Decisions — AgentShield

| # | Decision | Alternatives | Rationale |
|---|---|---|---|
| TD1 | Provenance-aware deterministic PEP (Option B) | ML/LLM injection classifier (A); full MCP proxy (C) | Deterministic, explainable, evasion-resistant; matches "secure the agent, not just the prompt". Classifier kept as escalate-only signal. |
| TD2 | Simulated deterministic agent | Real LLM agent | Brochure allows simulated; reproducible on stage; no API key or Wi-Fi dependency. LLM mode is stretch behind same interface. |
| TD3 | TypeScript end to end | Python backend | Shared types for decisions/audit; avoids Python 3.14 wheel risk. |
| TD4 | Fastify + Zod | Express | Built-in schema hooks, `inject()` for tests. |
| TD5 | `node:sqlite` | better-sqlite3, Postgres | Zero native build on Windows; verified on Node 24.11 (ExperimentalWarning only). Fallback documented. |
| TD6 | Policy as YAML files | DB-stored policy, OPA/Rego | Readable for judges, versioned in git, no extra runtime. |
| TD7 | Shield OFF = permissive policy, same pipeline | Bypass flag | Honest comparison; OFF runs still audited. |
| TD8 | Approval = extra PEP input, re-evaluated, atomically consumed, hash-bound (tool, args, runId, agentId, policyVersion) | Approval directly executes | DENY stays non-overridable; prevents replay/swap/TOCTOU. |
| TD9 | Audit fail-closed; app-level append-only; hash chain stretch | Immutable store | Honest MVP guarantee; tamper-evidence optional. |
| TD10 | Local operator secret → HttpOnly SameSite=Strict cookie + CSRF | Full user accounts/OAuth | Sufficient for local demo; clear separation from agent principal. |
| TD11 | SSE for live run updates | WebSockets | One-directional, simpler. |
| TD12 | Tailwind v4 (fallback v3) | CSS-in-JS | Fast to build; v3 fallback if native lightningcss fails on Windows. |
