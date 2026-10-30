# Project Overview — AgentShield

**Hackathon:** PARALLAX (BMSCE IEEE Computer Society), theme *Defensive Cybersecurity — Build. Break Safely. Prove the Fix.*
**Track:** Problem Statement 01 — AgentShield: *Secure the Agent, Not Just the Prompt* (AI-agent / MCP / tool-use security).

## Problem
AI agents read untrusted content (web pages, emails, files, tool output) and act through tools. Text in that content can redirect
the agent to leak secrets or misuse tools (indirect prompt injection). Filtering the user's prompt does not help: the attack never arrives there.

## Solution
A **provenance-aware policy enforcement point** between the agent and its tools. Every value carries a trust label
(where it came from, how sensitive it is). The PEP decides **ALLOW / DENY / REQUIRE_APPROVAL** per tool call from argument provenance,
tool impact, agent permissions and user clearance — deterministically, with an inspectable reason, failing closed.

## Signature features
1. **Provenance tracking** — the shield blocks by data flow ("the recipient came from a web page"), not by keywords.
2. **Prove-the-Fix lab** — every scenario runs with the shield OFF (attack succeeds) and ON (blocked), plus an automated attack regression suite and audit evidence.

## Users
Teams deploying tool-using agents/assistants (internal copilots, MCP-connected agents) who need enforceable boundaries and audit evidence.

See `SYSTEM_ARCHITECTURE.md`, `THREAT_MODEL.md`, `IMPLEMENTATION_PLAN.md`.
