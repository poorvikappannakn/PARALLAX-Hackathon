# AgentShield — Security Design: Detection, Alerts and Enforcement

AgentShield has three layers. They are deliberately independent of each other:

| Layer | Purpose | Authority |
|---|---|---|
| **Instruction threat analyzer** (`server/src/analysis/instruction-threat.ts`) | Explains which parts of untrusted content are information and which are instructions, and whether they attack the user's objective | **Advisory only** |
| **URL threat analyzer** (`server/src/analysis/url-analyzer.ts`) | Explains why a link in the content is or is not suspicious. **Exception:** the PEP re-runs it on the URL of every `fetch_web` call (rules U1/U2, below) | Advisory for content; **enforced for `fetch_web` URLs** |
| **PEP** (`server/src/shield/pep.ts`) via the gateway | Decides every tool call (ALLOW / DENY / REQUIRE_APPROVAL) from provenance, permissions and impact | **Final authority** |

The instruction analyzer and all content-level results never authorise or block anything, and the PEP never reads them.
An attacker who evades them still meets the same PEP decisions; a false positive produces at most an unnecessary alert.

**URL risk at the PEP (fetch_web only).** The PEP itself re-runs the offline URL analyzer on the `url` argument of each
`fetch_web` call — it never uses a risk level computed earlier, by the client or by the inspector. HIGH ⇒ **U1 DENY** (a DENY
rule: evaluated with P1–P4, never sent for approval, cannot be approved); MEDIUM ⇒ **U2 REQUIRE_APPROVAL** (normal approval
safeguards: call-hash binding, single use, expiry, re-evaluation); UNKNOWN ⇒ decision unchanged with an advisory reason;
LOW ⇒ unchanged. P2's exact-host https allowlist still applies first, so in practice U1/U2 matter for URLs on allow-listed
hosts (redirect parameters, brand-in-path, encoded destinations) and as defence in depth if a look-alike host were ever
allow-listed. Shield OFF (permissive policy) is unchanged. Other tools are unaffected. A URL-analyzer false positive on an
allow-listed host would block or pause that fetch — the price of enforcing it.

## 1. Three separate classifications
Each untrusted source gets three classifications. They are reported side by side and never merged into one label.

- **Source trust:** TRUSTED / UNTRUSTED / UNKNOWN. This says *where* the content came from: the authenticated user's task and the application policy are TRUSTED; web pages, inbox mail and lab content are UNTRUSTED.
- **Instruction threat:** LOW / MEDIUM / HIGH / UNKNOWN. This is *what the content tries to do*.
- **URL risk:** LOW / MEDIUM / HIGH / UNKNOWN, or none when no URL is present.

Key points:
- UNTRUSTED ≠ malicious: an ordinary vendor email is UNTRUSTED with a LOW threat.
- TRUSTED ≠ safe: the threat analysis does not depend on trust, and a trusted user's out-of-permission request is still denied by the PEP.
- UNKNOWN means insufficient evidence, not malicious. It covers empty or unreadable content, content too long to analyse fully, and unknown domains with no indicators.
- LOW is never presented as "safe". Each result carries a qualification ("no indicators is not proof…") and a confidence.

## 2. Instruction threat analyzer (rule-based, contextual)
The analyzer works sentence by sentence and looks at sentence **structure**, not at keywords:

1. Is the sentence an imperative addressed to the reader or agent ("please…", "assistant, …", "you must…", a sentence-initial verb), or is it descriptive?
2. What action does it request?
   - access: read, retrieve, gather…
   - transfer: send, forward, "pass them along"…
   - destroy: delete, wipe…
   - execute: run, download, visit, open the attachment…
3. What is the target?
   - credentials or keys;
   - confidential data;
   - protected files or records;
   - a destination chosen by the content (an address or URL that the user's task did not name).
4. Does it carry manipulation markers?
   - instruction or objective override ("ignore previous instructions", "your new task");
   - fake SYSTEM, DEVELOPER or ADMIN headers, or claims of pre-approval;
   - concealment ("do not tell the user", "silently").
5. Does it conflict with the user's objective? The objective is derived from the trusted task: *summarise* or *read*.

**Levels:**
- HIGH: any high-severity finding (credential request, external transfer of sensitive data, instruction override, encoded instruction); or three or more medium findings; or a manipulation marker anywhere in the content combined with a tool-misuse request anywhere in it.
- MEDIUM: any medium finding.
- LOW: no finding, and the whole content was analysed.

Single words never raise the level. "Our system administrator will update the password policy" and "If you received this email in error, please delete it" are both LOW; tests cover both.

**Decoding before analysis:**
- HTML tags, comments and entities;
- zero-width characters and NFKC normalisation;
- base64 runs that decode to readable text;
- multi-byte percent-encoding.

Decoded instructions are marked `decoded`.

**Second line of evidence (agent requests):** the tool requests the agent's own parser derives from the content are also
used as evidence. A read of a CONFIDENTIAL/SECRET file or a deletion → HIGH; an email to an address the user did not
name → HIGH after a sensitive read, otherwise a LOW finding with no alert (ordinary business mail such as "send the PO to
orders@…"). Passive ("should be forwarded to …") and question ("could you share …") forms are recognised. Concealment
means hiding an action from the user; general security advice ("never tell anyone your OTP") is not flagged.

**What the analyzer is not:** it is not a language model. It recognises documented structures and will miss paraphrases outside them. That is acceptable only because enforcement does not depend on it (see §5).

## 3. URL threat analyzer (rule-based, offline)
The analyzer uses WHATWG URL parsing and hostname normalisation (lower case, punycode), and a built-in approximation of the registrable domain.

It never fetches, resolves or visits anything: no DNS and no network. Shortened links are reported as "destination hidden, not resolved".

| Check | Indicator | Severity |
|---|---|---|
| `javascript:`, `data:`, `vbscript:`, `file:` | dangerous-scheme | high |
| userinfo before `@` (`paypal.com@evil.test`) | userinfo | high |
| numeric or hex host (`0x7f000001`) | encoded-destination | high |
| look-alike letters (Cyrillic/Greek) producing a brand name | homoglyph-brand, mixed-script, punycode | high |
| character substitution (`paypa1`, `micros0ft`) or edit distance 1–2 from a brand | typosquat-brand | high |
| brand in a subdomain of another registrable domain (`paypal.com.account-verify.test`) | brand-in-subdomain | high |
| brand combined with other words (`paypal-secure.test`), or the brand on a non-official domain | brand-in-hostname | medium |
| brand only in the path | brand-in-path | medium |
| IP host, explicit port, ≥ 5 labels, shortener, redirect parameter, nested encoding | various | medium |

**Risk level:**
- HIGH: any high-severity indicator.
- MEDIUM: any medium indicator.
- LOW: no indicator, and the domain is one of a small built-in list of official brand domains. Reported as "not a guarantee of safety".
- UNKNOWN: anything else. No arbitrary score is assigned to unknown domains.

The score is the sum of indicator weights and is null when there is no evidence. Reputation is always reported as
`unavailable`, because no malicious-domain dataset is bundled.

URL risk and instruction risk are independent: a legitimate URL can host malicious instructions, and a suspicious URL can
sit in harmless text. Tests cover both cases.

## 3a. Outgoing content check
Each `send_email` the agent attempts is analysed (subject + body, from the audit row's already-redacted arguments) for
instruction-like text copied from untrusted input — e.g. an injected line that the extract-style summary carried along. The
result (level + categories, never the text) is shown in the approval panel and the inspector. It is advisory: it does not
change the A1 decision. CONFIDENTIAL/SECRET bodies are redacted in audit and reported as "not analysed".

## 4. Alerts
An alert is created only when the instruction threat is MEDIUM or HIGH, or when a URL is MEDIUM or HIGH. Ordinary external
content raises no alert.

Each alert states:
- what was detected and where it came from (its provenance label);
- why it is suspicious, as one reason per finding or URL indicator;
- what the content tried to make the agent do, and the potential impact;
- **what actually happened in this run**, built only from the run's real step outcomes: the mode (Shield ON/OFF) and which
  requests from this source were EXECUTED, DENIED (with rule) or are awaiting approval. With the Shield OFF it says
  "no policy enforcement" and lists executed actions; it never claims a block that did not happen;
- content handling (data only; links never visited; attachments never opened or executed);
- whether the legitimate task can continue.

The actual PEP decisions for the resulting tool requests are shown next to the alert. They are real decisions from the run.

## 5. Safe processing and autonomy (enforced by the PEP)
- **Inspecting content as data** (reading the email or page, extracting text): ALLOW, rule L1. This happens automatically, with no approval.
- **Following instructions from content:** the demo agent is *deliberately gullible*. It attempts every instruction it recognises, so the demo proves that enforcement does not depend on the agent behaving well.
  - Each resulting request is decided by the PEP from argument provenance.
  - A secret read above clearance → P2 DENY.
  - A recipient chosen by untrusted content → P4 DENY.
  - A tool outside the agent's profile (delete) → P1 DENY.
  - DENY is never sent for approval and cannot be approved.
- **Continuing the legitimate task:** after the injected requests are denied, the user's own task continues in the same run. The summary to the user's own, trusted address is REQUIRE_APPROVAL (A1), because its body is derived from untrusted content; this is a policy choice.
- **Dangerous content:**
  - attachments are rejected by the email parser and never opened or executed;
  - the agent has no browse, execute or shell capability, so links and commands in content cannot be followed;
  - `fetch_web` only reads allowlisted local fixtures.
- **Unsafe content:** content that cannot be parsed safely (binary data, unsupported MIME, oversize) is refused as a whole, and no run starts.
- **Missing provenance** fails closed: F0, or worst-case labels (UNTRUSTED + SECRET).

## 6. Provenance granularity
- **Per value:** labels are attached to each value the gateway holds and to each tool argument.
- **Agent-generated values** (summaries, new text) inherit the join of everything read so far, plus `agent:generated`. This conservative source inheritance means a summary of an injected page stays UNTRUSTED and keeps the page as a source; a test checks that an injection preserved in a summary is still detected.
- **Not sentence-level:** taint is not tracked per sentence inside a document, so a clean sentence extracted from a tainted page is still tainted. This yields more approvals, never fewer.
- **No self-promotion:** content cannot promote itself to TRUSTED, because labels come only from the gateway and the tools.

## 6a. A1 approval for the summary (reviewed, unchanged)
The user's summary email is `send_email` (HIGH impact). Its body is agent-generated from untrusted content, so A1 applies;
with nothing untrusted read, A2 applies — every send needs approval by policy. The recipient is the user's own TRUSTED
address and P3/P4 already bound exfiltration, so a future policy could ALLOW (e.g. "L2") a send to the requesting user when
the body is within clearance and the outgoing check finds no embedded instructions. Not changed in this patch.

## 7. Limitations and future work
- Rule-based analyzers: paraphrases outside the documented structures are missed, and some benign imperatives may be flagged. Neither affects enforcement.
- No model-based classification; an optional LLM classifier is future work, and it would stay advisory.
- URL: no full Public Suffix List (a small private-suffix subset and country variants of listed brands only); redirect
  targets are analysed one level deep; bare-domain extraction covers common TLDs only; non-English instructions are not
  analysed by the phrase rules (the agent-request evidence still applies when the agent's parser recognises them).
- In "Compare" mode the lab inspector shows the ON run's enforcement; the OFF run's outcome is in the comparison table.
- The URL brand list is small and fixed. There is no Public Suffix List, no reputation feed, and confusables cover common Cyrillic/Greek and digit substitutions only.
- The demo agent is a deterministic simulation with a small instruction vocabulary.
- Per-sentence taint and instruction/data separation inside a single value are future work.
