# AgentShield — Likely Judge Questions

**How is this different from a prompt-injection filter?**
A filter classifies text and can be evaded by rephrasing. AgentShield never decides on what text *says*. It decides each tool
call from (a) the provenance labels of each argument — trusted/untrusted integrity, confidentiality, and source — and (b) the
tool's impact. An attacker who rephrases the injection still produces an UNTRUSTED recipient (P4) or a SECRET read above
clearance (P2). The heuristic injection detector exists but can only *escalate* a decision to approval (A3); security never
depends on it.

**Where do provenance labels come from? Can the agent fake them?**
The gateway assigns them. The agent may only send `{ref}` (a value the gateway already holds, with its label) or `{value}` (new
text, which the gateway labels with the join of everything read so far plus `agent:generated`, so it can never be more trusted
than its inputs). Requests carrying labels, identities or extra fields are rejected and audited. Tool outputs are labelled by
the tools (e.g. web/inbox content is UNTRUSTED; files carry their classification). Missing or malformed labels become
UNTRUSTED + SECRET (worst case).

**What does "fail closed" mean concretely?**
Unknown tool, invalid/unexpected arguments, malformed provenance, missing or invalid policy, evaluator exceptions, invalid or
expired approvals → DENY (F0). If the decision audit row cannot be written, nothing executes; if the outcome row cannot be
written, the run halts (`audit_failure`) and the UI shows it as failed. Structural F0 checks apply even with the shield off (S5).

**Can a human approval override a DENY? Can an approval be reused?**
No and no. DENY rules (F0, P1–P4) are evaluated first and are never sent for approval. An approval is bound to a SHA-256 hash of
the exact call — tool, canonical arguments with their provenance, run, agent, user and policy version — and the PEP re-evaluates
the stored call after the decision (DENY rules can still deny). Consumption is a single atomic `UPDATE … WHERE used = 0` in the
same transaction as its audit row; replays are rejected and audited. The approver must be a registered operator, taken from the
authenticated session; the agent has no approve tool and agent text like "pre-approved" is inert data.

**Why did S2 ON still need approval for the summary?**
Rule A1: email is high-impact and its body was derived from untrusted web content. The recipient is Alice's own address from
her profile (TRUSTED), so it is approvable — unlike the attacker's address, which came from the page (UNTRUSTED ⇒ P4 DENY).

**How do you know the attack really succeeded/failed?**
Verdicts are computed from the sandbox end state — outbox files on disk, files present — plus gateway-written audit rows, never
from the agent's own trace or claims. Tests also delete evidence to prove the verdict flips.

**Is the audit log tamper-proof?**
No — and we say so. It is append-only at the application level (no update/delete code paths or routes) and fails closed, but
anyone with write access to the SQLite file could edit it. Hash chaining (tamper *detection*) and an external WORM log are
listed as future work.

**Do you expose sensitive data in the dashboard?**
Every browser-facing response is an explicit allowlist projection: no agent traces, argument values, email bodies or
subjects, document contents, secrets, hashes or file-system paths. Attacker-chosen values echoed in policy reasons are masked
as `[untrusted value]`. Tests check every scenario's API responses, SSE streams and the rendered pages for the fake keys,
salary rows and injected subjects.

**How is the operator authenticated?**
A random 32-byte secret printed once by the API at startup → HttpOnly, SameSite=Strict session cookie (12 h) + per-session CSRF
token on every state-changing request; Host and Origin allowlists (DNS-rebinding/CSRF defence); JSON-only bodies ≤ 1 KB;
10 login attempts/min; loopback-only bind. It is a single local operator — not a multi-user identity system.

**Can I try my own attack?**
Yes — the Interactive Attack Lab (web page or document, typed or `.txt`/`.html` upload ≤ 100 KB) and the Email Security Lab
(three samples or an uploaded `.eml`/`.txt`/`.html`). The content is written into a fresh sandbox per run and read by the
same agent through the same policy engine. The agent recognises a small documented vocabulary: read/open/cat, send/email/
forward, delete/remove/erase with an explicit path or address, plus named resources ("API keys", "salary data", "project
documentation"). The inspector shows what was recognised and what was unsupported; unsupported instructions do nothing.
Tasks are interpreted the same way (summarise/report → read + email summary; read/review → read only; anything else refused).

**Does the email's sender or subject matter?**
No. Sender, recipient and subject are display data; the whole message is labelled UNTRUSTED by the inbox tool, and an email
cannot grant permissions, approve anything or change the user's task.

**Is the agent an LLM?**
No. It is a deterministic, deliberately gullible rule-based agent with a regex instruction parser, so the demo is reproducible
and needs no API key or network. The enforcement layer is agent-agnostic: it never trusts the agent's output, so an LLM agent
would go through the same gateway (planned, not built).

**What are the limitations?**
Simulated agent; regex parser misses other phrasings (which only makes the *attack* weaker, not the shield); coarse provenance
for agent-generated values (conservative: more approvals, never fewer); in-memory sessions/runs/pending approvals (lost on
restart, approvals then expire); one fixed operator; audit not OS-level tamper-proof; import boundaries enforced by ESLint
(static) rather than at runtime; a small TOCTOU window in `delete_file`, confined to the run's sandbox; suite approvals are
scripted (recorded as `operator:alice` in the audit log, labelled scripted in reports).

**Why does S5 Shield ON show "not matched" after I approved?**
S5's expected outcome assumes the operator never answers (the approval expires ⇒ F0). Approving the legitimate status email
is allowed — it is sent once — so the expectation honestly reads "not matched"; every malformed/forged probe is still refused.

**How was it tested?**
Vitest suite covering the PEP rules, provenance, sandbox, tickets, gateway and audit failure paths, approval replay/expiry,
all scenarios in both modes, the API (auth, CSRF, Host/Origin, validation, leakage), SSE (live, reconnection, cleanup), plus a
real-browser end-to-end run of this demo. Current counts are in `HACKATHON_HANDOFF.md`.
