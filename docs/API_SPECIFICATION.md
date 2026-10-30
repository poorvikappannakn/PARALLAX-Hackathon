# API Specification — AgentShield

Base: `http://127.0.0.1:3000/api`. JSON. Errors: `{ "error": { "code": string, "message": string } }`.
Auth: session cookie from `POST /session`; state-changing routes also need header `X-CSRF-Token`.

| Method | Path | Auth | Request | Response |
|---|---|---|---|---|
| GET | `/health` | none | — | `{ ok, node, sqlite }` |
| POST | `/session` | none | `{ secret }` | sets cookie; `{ principal, csrfToken }` |
| GET | `/scenarios` | session | — | `[{ id, title, description, attackType }]` |
| POST | `/runs` | session + CSRF | `{ scenarioId, shield: "on"\|"off" }` | `{ runId }` |
| GET | `/runs/:id` | session | — | run + steps + decisions |
| GET | `/runs/:id/stream` | session | — | SSE: `step`, `decision`, `approval_required`, `outcome`, `run_end` |
| GET | `/audit?runId=` | session | — | `[AuditEvent]` |
| GET | `/approvals?status=pending` | session | — | `[Approval + provenance view]` |
| POST | `/approvals/:id/decision` | session + CSRF (approver role) | `{ decision: "approve"\|"reject" }` | `{ approval }`; 403 if approver == requester; 409 if not pending/expired |
| POST | `/suite/run` | session + CSRF | — | scorecard `[{ scenarioId, off: {attackSucceeded}, on: {blocked, legitCompleted}, auditRows }]` |
| GET | `/policy` | session | — | policy, manifests, profiles (read-only) |

Error codes: `VALIDATION_ERROR` 400, `UNAUTHENTICATED` 401, `FORBIDDEN` 403, `NOT_FOUND` 404, `CONFLICT` 409, `INTERNAL` 500.
No route mutates or deletes `audit_events`.
