# API Specification — AgentShield (as implemented, M5)

Base: `http://127.0.0.1:<AGENTSHIELD_API_PORT|3000>/api` (loopback only). JSON bodies only (≤ 1 KB).
Errors are always `{ "error": { "code": string, "message": string } }` with fixed messages (nothing user-supplied is echoed).
Auth: HttpOnly `as_session` cookie from `POST /session`; every state-changing request also needs `X-CSRF-Token`.
Every request passes the Host / Origin / JSON-only / session / CSRF guards described in `SYSTEM_ARCHITECTURE.md` §8.
All response bodies are explicit-allowlist projections (`server/src/api/views.ts`): no agent traces, argument values, email
bodies or subjects, document contents, secrets, hashes or filesystem paths.

| Method | Path | Auth | Request | Response |
|---|---|---|---|---|
| GET | `/health` | none | — | `{ ok, sqlite }` |
| POST | `/session` | none (rate-limited 10/min) | `{ secret }` (strict) | 201, sets cookie; `{ operator, csrfToken, expiresAt }` · 401 `INVALID_CREDENTIALS` · 429 `RATE_LIMITED` |
| GET | `/session` | session | — | `{ operator, csrfToken, expiresAt }` |
| DELETE | `/session` | session + CSRF | — | 204, session destroyed, cookie cleared |
| GET | `/scenarios` | session | — | `{ scenarios: ScenarioView[] }` (catalogue metadata + expected outcomes) |
| GET | `/runs` | session | — | `{ runs: RunSummary[] }` (interactive runs in memory, newest first) |
| POST | `/runs` | session + CSRF | `{ scenarioId: "S1".."S5", mode: "on"\|"off" }` (strict) | 201 `{ run: RunView }` · 429 `CAPACITY` (10 live/waiting runs) |
| GET | `/runs/:runId` | session | — | `{ run: RunView }` · 404 |
| GET | `/runs/:runId/events` | session | header `Last-Event-ID` (optional) | `text/event-stream` (below) · 404 · 429 `TOO_MANY_SUBSCRIBERS` |
| GET | `/approvals?status=pending` | session | — | `{ approvals: PendingApprovalView[] }` (approvals of live runs only) |
| POST | `/approvals/:approvalId/decision` | session + CSRF | `{ verdict: "approve"\|"reject" }` (strict) | 200 `{ run: RunView }` (the same run resumes) · 404 · 409 `CONFLICT` / `APPROVAL_EXPIRED` · 403 · 500 `AUDIT_FAILURE` |
| POST | `/suite` | session + CSRF | `{}` | `SuiteResult` (all scenarios × both modes, scripted operator) · 409 `SUITE_RUNNING` |
| GET | `/runs/:runId/content` | session | — | `{ content: RunContentView }` — task, deterministic plan, untrusted sources (bounded inert text preview + per-sentence analysis). Never task files, outbox bodies or secrets |
| ↳ | each `content.sources[i].assessment` | | | `{ sourceTrust, instructionThreat: {level, score, confidence, summary, uncertainty, counts, sentences[]}, urlRisk, urls[]: {hostname, unicodeHostname, registrableDomain, risk, score, confidence, indicators[], reputation:"unavailable"}, alert | null }` — advisory, never used by the PEP; plus per source `enforcement: {mode, executed[], denied[], pending[], statement}` from the run's real steps, and per run `outgoing[]` (content check of each attempted send: level + categories, never text). `/approvals` items carry `outgoing` the same way |
| GET | `/overview` | session | — | `{ overview: { runs, live, waiting, decisions: {allow, deny, approval}, attacksBlocked, attacksSucceeded } }` |
| GET | `/audit` | session | — | `{ events: AuditExplorerEvent[] }` (≤ 500, newest first; masked reasons; each with the run's advisory `threat: {instruction, url, alerts}`) |
| POST | `/lab/runs` | session + CSRF, body ≤ 320 KB | `{ task, sourceType: "web"\|"document", content (≤ 100 KB text), filename?, modes: ["off"\|"on", …] }` | 201 `{ runs: RunView[], plan }` · 422 `INVALID_CONTENT` / `TASK_NOT_RECOGNISED` · 429 |
| GET | `/email/samples` | session | — | `{ samples: EmailSample[] }` (3 synthetic emails) |
| POST | `/email/parse` | session + CSRF, body ≤ 320 KB | `{ filename (.eml/.txt/.html), content }` | `{ email }` · 422 `INVALID_EMAIL` (fixed reason) |
| POST | `/email/runs` | session + CSRF, body ≤ 320 KB | `{ task, modes, sampleId }` or `{ task, modes, upload: { filename, content } }` | 201 `{ runs, plan }` · 422 · 429 |

Lab requests never carry labels, identities, paths or permissions (strict schemas reject them); the server writes the
content into each run's own sandbox under a generated name and the existing tools label it UNTRUSTED.

The approver is always the authenticated session's operator (`operator:alice`); a client-supplied identity is rejected (400).
Decisions are persisted by `decideApproval()` (M3) and executed only through the run's own gateway after PEP re-evaluation.

## SSE (`/runs/:runId/events`)
Each event has a per-run, strictly increasing `id`. On connect: `snapshot` `{run}` (or, with a valid `Last-Event-ID` still in
the 500-event buffer, exactly the missed events). Then, as the run executes one gateway call at a time:
`step` (StepView), `decision` (DecisionView), `audit` (AuditEventView), `state` `{phase, state}`,
`approval_required` (PendingApprovalView), and finally `done` `{run}` or `failed` `{run}` — after which the server closes the
stream. Heartbeat comment `: ping` every 15 s; `retry: 3000`. Limits: 10 subscribers per run, 100 total; disconnected clients
are removed immediately.

Status codes used: 400 `BAD_REQUEST`, 401 `UNAUTHENTICATED`, 403 `FORBIDDEN_HOST` / `FORBIDDEN_ORIGIN` / `CSRF_FAILED` /
`FORBIDDEN`, 404 `NOT_FOUND`, 409, 413 `PAYLOAD_TOO_LARGE`, 415 `UNSUPPORTED_MEDIA_TYPE`, 429, 500 `INTERNAL`.
No route mutates or deletes `audit_events`.
