// Contextual instruction-threat analysis of untrusted content. Advisory only: it informs the user and the inspector, it
// never authorises or blocks anything (the PEP decides every tool call from provenance and policy, independently).
//
// Rule-based and heuristic, not a language model. Each sentence is classified by STRUCTURE rather than by single words:
//   - is it addressed to the reader/agent as an imperative (vs. descriptive information)?
//   - what action does it ask for (access / transfer / destroy / execute) and on what target (credentials, confidential
//     data, protected resources, a link or attachment)?
//   - does it try to replace the user's objective, impersonate authority, or hide itself from the user?
// A word such as "password", "system" or "delete" on its own never raises the level; only combinations do.
// Encoded payloads (base64, percent/HTML entity encoding, zero-width characters) are decoded before analysis.

export type ThreatLevel = "LOW" | "MEDIUM" | "HIGH" | "UNKNOWN";
export type SourceTrust = "TRUSTED" | "UNTRUSTED" | "UNKNOWN";

export type SentenceRole = "information" | "instruction" | "objective-override" | "tool-misuse";

export type FindingCategory =
  | "instruction-override"
  | "fake-authority"
  | "concealment"
  | "credential-request"
  | "confidential-access"
  | "external-transfer"
  | "destructive-action"
  | "execution-request"
  | "objective-change"
  | "tool-invocation"
  | "encoded-instruction"
  | "out-of-scope-request"
  | "agent-tool-request";

export interface ThreatFinding {
  readonly category: FindingCategory;
  readonly severity: "high" | "medium" | "low";
  readonly reason: string;
}

export interface SentenceAssessment {
  /** Bounded sentence text (untrusted input, rendered as inert text). */
  readonly evidence: string;
  readonly role: SentenceRole;
  readonly level: ThreatLevel;
  readonly findings: readonly ThreatFinding[];
  readonly decoded: boolean;
  /** Whether the request conflicts with the user's stated objective. */
  readonly conflictsWithObjective: boolean;
}

export interface InstructionAssessment {
  readonly level: ThreatLevel;
  readonly sourceTrust: SourceTrust;
  /** Sum of finding weights (0–100), null when nothing was found. Never an authorisation signal. */
  readonly score: number | null;
  readonly confidence: "high" | "medium" | "low";
  readonly counts: { readonly information: number; readonly instruction: number; readonly suspicious: number };
  readonly sentences: readonly SentenceAssessment[];
  readonly summary: string;
  readonly uncertainty: string | null;
}

export interface UserObjective {
  /** What the user asked for, as interpreted by the task parser. */
  readonly intent: "summarise" | "read" | "other";
  /** Addresses the user's own task explicitly mentions (allowed destinations). */
  readonly allowedRecipients: readonly string[];
}

const MAX_CHARS = 20_000;
const EVIDENCE = 300;
const MAX_SENTENCES = 40;
const WEIGHT = { high: 40, medium: 20, low: 5 } as const;

// ---- normalisation / decoding -----------------------------------------------------------------------------------

const ENTITY: Record<string, string> = { quot: '"', apos: "'", lt: "<", gt: ">", amp: "&", nbsp: " " };
const decodeEntities = (s: string) =>
  s
    .replace(/&#x([0-9a-f]{1,6});/gi, (_, h: string) => safeChar(parseInt(h, 16)))
    .replace(/&#(\d{1,7});/g, (_, d: string) => safeChar(Number(d)))
    .replace(/&([a-z]+);/gi, (m, n: string) => ENTITY[n.toLowerCase()] ?? m);
const safeChar = (cp: number) => (cp > 0 && cp < 0x10ffff ? String.fromCodePoint(cp) : " ");
const ZERO_WIDTH = /[​-‍⁠﻿­]/g;

function plain(input: string): string {
  return decodeEntities(input.replace(/<!--|-->/g, " ").replace(/<[^>]*>/g, " ")).replace(ZERO_WIDTH, "").normalize("NFKC");
}

/** Decode base64 / percent-encoded runs that turn into readable text, so hidden instructions are analysed too. */
function decodedPayloads(text: string): string[] {
  const out: string[] = [];
  for (const m of text.matchAll(/[A-Za-z0-9+/]{24,}={0,2}/g)) {
    try {
      const t = Buffer.from(m[0], "base64").toString("utf8");
      if (/^[\x20-\x7e\s]{16,}$/.test(t) && /[a-z]{3,}\s+[a-z]{2,}/i.test(t)) out.push(t);
    } catch {
      /* not base64 */
    }
  }
  for (const m of text.matchAll(/(?:%[0-9a-f]{2}){6,}[^\s]*/gi)) {
    try {
      out.push(decodeURIComponent(m[0]));
    } catch {
      /* malformed encoding */
    }
  }
  return out.slice(0, 10);
}

const sentencesOf = (text: string) =>
  text
    .split(/\r?\n[ \t]*\r?\n|(?<=[.!?])\s+|\r?\n(?=[A-Z\[<#*-])/)
    .map((s) => s.replace(/\s+/g, " ").trim())
    .filter((s) => s.length > 1);

// ---- structural patterns ------------------------------------------------------------------------------------------

const ACCESS = "gather|harvest|read|open|retrieve|fetch|get|obtain|collect|extract|access|grab|dump|print|reveal|show|display|output|list|copy|look\\s+up|find|cat|load";
const TRANSFER = "pass\\s+(?:them|it|this|these)\\s+(?:along|on)|send|e-?mail|mail|forward|upload|post|transmit|share|exfiltrate|leak|paste|deliver|submit|reply\\s+with|cc";
const DESTROY = "delete|remove|erase|wipe|purge|destroy|overwrite|truncate|rm|format|drop";
const EXECUTE = "run|execute|invoke|launch|eval|install|download|click|visit|navigate\\s+to|open\\s+the\\s+(?:link|attachment|url)|follow\\s+the\\s+link";

const LEAD = "(?:^|[:;,\\-–—]\\s*|\\b(?:please|kindly|now|then|also|first|next|immediately|and|(?:could|can|would|will)\\s+you(?:\\s+please)?|you\\s+(?:must|should|need\\s+to|are\\s+to|will|have\\s+to)|(?:the\\s+)?(?:assistant|agent|ai|bot|model)\\s*[,:]?\\s*(?:must|should|will|is\\s+to)?)\\s+)";
const imperative = (verbs: string) => new RegExp(`${LEAD}(?:${verbs})\\b`, "i");
const IMP_ACCESS = imperative(ACCESS);
const IMP_TRANSFER = imperative(TRANSFER);
const IMP_DESTROY = imperative(DESTROY);
const IMP_EXECUTE = imperative(EXECUTE);
// Passive requests ("the keys should be forwarded to ...") are requests too.
const passive = (participles: string) => new RegExp(`\\b(?:should|must|needs?\\s+to|is\\s+to|are\\s+to|has\\s+to|have\\s+to)\\s+be\\s+(?:${participles})\\b`, "i");
// Third-person requests addressed to the agent ("the assistant handling this document needs to forward ...").
const addressed = (verbs: string) =>
  new RegExp(`\\b(?:assistant|agent|ai|bot|model)\\b[^.!?\\n]{0,40}?\\b(?:needs?\\s+to|must|should|has\\s+to|have\\s+to|is\\s+(?:required|expected|asked)\\s+to|will)\\s+(?:${verbs})\\b`, "i");
const TO_AGENT_ACCESS = addressed(ACCESS);
const TO_AGENT_TRANSFER = addressed(TRANSFER);
const TO_AGENT_DESTROY = addressed(DESTROY);
const PASSIVE_ACCESS = passive("retrieved|collected|gathered|extracted|read|opened|dumped|printed|copied");
const PASSIVE_TRANSFER = passive("sent|forwarded|e-?mailed|mailed|uploaded|shared|posted|transmitted|delivered|submitted");
const PASSIVE_DESTROY = passive("deleted|removed|erased|wiped|purged|destroyed|overwritten|truncated");

const CREDENTIAL = /\b(?:api[\s_-]?keys?|access[\s_-]?keys?|secret[\s_-]?keys?|private[\s_-]?keys?|ssh[\s_-]?keys?|tokens?|passwords?|passphrases?|credentials?|secrets?(?:\s+file)?|\.env\b|otp|2fa\s+codes?)\b/i;
const CONFIDENTIAL = /\b(?:salar(?:y|ies)|payroll|hr\s+(?:records?|files?|data)|confidential|customer\s+(?:data|records|list)|personal\s+data|bank\s+details|database|internal\s+(?:documents?|files?))\b/i;
const PROTECTED = /\b(?:files?|documents?|folders?|director(?:y|ies)|projects?|roadmap|backups?|logs?|audit|records?|everything|all\s+(?:data|files))\b/i;
const OWN_MESSAGE = /\b(?:this|the)\s+(?:e-?mail|message)\b[^.]{0,40}\b(?:in\s+error|by\s+mistake|not\s+the\s+intended)\b|\bif\s+you\s+(?:are|were)\s+not\s+the\s+intended\b/i;
const DESTINATION = /[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+|\bhttps?:\/\/\S+|\bto\s+(?:me|us|this\s+address|the\s+(?:following|address|server|endpoint))\b/i;

const OVERRIDE = /\b(?:ignore|disregard|forget|override|bypass|skip)\b[^.!?\n]{0,40}\b(?:previous|prior|above|earlier|all|any|your|the\s+user'?s?|original|existing)\b[^.!?\n]{0,30}\b(?:instructions?|rules|prompts?|guidelines|task|directions|polic(?:y|ies)|restrictions)\b|\bsystem\s+override\b|\b(?:new|updated|real)\s+(?:instructions|task|objective)\b|\binstead\s+of\s+(?:summari[sz]|reading|the\s+task)|\b(?:do\s+not|don'?t|stop)\s+(?:summari[sz]e|follow\s+the\s+user)/i;
const FAKE_AUTHORITY = /(?:^|\s|\[|<)(?:system|developer|admin(?:istrator)?|root|sysadmin)\s*(?:message|prompt|note|notice)?\s*[:\]>]|\byou\s+are\s+now\s+(?:authori[sz]ed|in\s+\w+\s+mode|an?\s)|\b(?:pre-?approved|already\s+approved|authori[sz]ed\s+by\s+(?:it|security|the\s+admin|management))\b|\b(?:message|instruction|order)\s+from\s+(?:the\s+)?(?:it|security|admin|ceo|developer)s?\b|\bas\s+your\s+(?:administrator|developer|operator)\b/i;
// Concealment = hiding an ACTION from the user. General security advice ("never tell anyone your OTP") is not.
const CONCEAL =
  /\b(?:do\s+not|don'?t|never)\s+(?:tell|inform|notify|mention|alert|reveal|disclose|report)(?:\s+(?:this|it))?\s+(?:to\s+)?the\s+(?:user|recipient|owner|operator)\b|\b(?:do\s+not|don'?t|never)\s+(?:tell|inform|notify|mention|alert|report)\s+(?:anyone|anybody|them)\s+(?:about|of)\s+(?:this|it|that|the\s+(?:request|transfer|action|change|email|message))\b|\bwithout\s+(?:telling|informing|notifying|alerting|asking)\s+(?:the\s+user|anyone|them)\b|\b(?:do\s+not|don'?t)\s+(?:log|record)\s+(?:this|it)\b|\b(?:silently|secretly|covertly)\b|\bkeep\s+(?:this|it)\s+(?:secret|hidden|between\s+us)\b/i;
const TOOL_NAME = /\b(?:read_file|send_email|delete_file|fetch_web|read_inbox|exec|shell|bash|powershell|curl|wget)\b/i;

// ---- assessment ---------------------------------------------------------------------------------------------------

function assessSentence(text: string, objective: UserObjective, decoded: boolean): SentenceAssessment {
  const f: ThreatFinding[] = [];
  const add = (category: FindingCategory, severity: ThreatFinding["severity"], reason: string) => {
    if (!f.some((x) => x.category === category)) f.push({ category, severity, reason });
  };

  const access = IMP_ACCESS.test(text) || PASSIVE_ACCESS.test(text) || TO_AGENT_ACCESS.test(text);
  const transfer = IMP_TRANSFER.test(text) || PASSIVE_TRANSFER.test(text) || TO_AGENT_TRANSFER.test(text);
  const destroy = (IMP_DESTROY.test(text) || PASSIVE_DESTROY.test(text) || TO_AGENT_DESTROY.test(text)) && !OWN_MESSAGE.test(text);
  const execute = IMP_EXECUTE.test(text);
  const credential = CREDENTIAL.test(text);
  const confidential = CONFIDENTIAL.test(text);
  const destination = DESTINATION.test(text);
  const external = [...text.matchAll(/[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+/g)].some((m) => !objective.allowedRecipients.includes(m[0].toLowerCase()));
  const override = OVERRIDE.test(text);
  const authority = FAKE_AUTHORITY.test(text);
  const conceal = CONCEAL.test(text);
  const toolName = TOOL_NAME.test(text) && (access || transfer || destroy || execute || /\b(?:call|use|invoke)\b/i.test(text));
  const imperativeAny = access || transfer || destroy || execute;

  if (override) add("instruction-override", "high", "Tries to override or replace the instructions the agent was given.");
  if (authority) add("fake-authority", "medium", "Claims system, developer or administrator authority, or pre-approval, from inside external content. Content cannot grant authority.");
  if (conceal) add("concealment", "medium", "Asks for the action to be hidden from the user.");
  if ((access || transfer) && credential) add("credential-request", "high", "Asks the agent to retrieve or disclose credentials, keys or passwords.");
  else if (access && confidential) add("confidential-access", "high", "Asks the agent to access confidential data unrelated to the user's request.");
  if (transfer && (destination || external) && (credential || confidential || /\b(?:contents?|data|files?|keys?|everything|it)\b/i.test(text)))
    add("external-transfer", credential || confidential ? "high" : "medium", "Asks the agent to send data to a destination chosen by the content, not by the user.");
  if (destroy && PROTECTED.test(text)) add("destructive-action", override || conceal || authority ? "high" : "medium", "Asks the agent to delete or modify files or records.");
  if (execute) add("execution-request", "medium", "Asks the agent to run, download, open or visit something. AgentShield never executes or visits content-supplied items.");
  if (toolName) add("tool-invocation", "medium", "Names agent tools or shell commands directly, attempting to steer tool use.");
  if (decoded && imperativeAny) add("encoded-instruction", "high", "An instruction was hidden in encoded text.");

  const outside = imperativeAny && (objective.intent === "summarise" || objective.intent === "read") && (transfer ? external || destination : destroy || execute || credential || confidential);
  if (outside && f.length > 0) add("objective-change", "medium", `Requests actions outside the user's objective (${objective.intent === "summarise" ? "summarise the content" : "read the content"}).`);
  if (outside && f.length === 0 && transfer) add("out-of-scope-request", "low", "Contains a request addressed to the reader that is outside the user's task; the agent does not act on it.");

  // Combination rules: individual weak indicators stay MEDIUM; HIGH requires a high-severity finding, or several
  // medium findings that together describe an attack (e.g. authority + concealment + destructive request).
  const highs = f.filter((x) => x.severity === "high").length;
  const mediums = f.filter((x) => x.severity === "medium").length;
  const level: ThreatLevel = highs > 0 || mediums >= 3 ? "HIGH" : mediums > 0 ? "MEDIUM" : "LOW";
  const role: SentenceRole = override || f.some((x) => x.category === "objective-change") ? "objective-override" : f.some((x) => ["credential-request", "confidential-access", "external-transfer", "destructive-action", "tool-invocation", "execution-request"].includes(x.category)) ? "tool-misuse" : imperativeAny || f.length > 0 ? "instruction" : "information";
  return Object.freeze({ evidence: text.length > EVIDENCE ? `${text.slice(0, EVIDENCE)}…` : text, role, level, findings: Object.freeze(f), decoded, conflictsWithObjective: outside });
}

/** A tool request the agent's own instruction parser derived from one sentence of the content. */
export interface AgentRequestEvidence {
  readonly evidence: string;
  readonly actions: readonly (
    | { readonly kind: "read_file"; readonly sensitive: boolean }
    | { readonly kind: "send_email"; readonly to: string }
    | { readonly kind: "delete_file" }
  )[];
}

/**
 * Second, independent line of evidence: what the agent would actually ATTEMPT because of this content. Wording the
 * phrase analysis misses ("I need the assistant to email X to Y") still produces a concrete tool request here.
 * A request to email an address the user did not name is MEDIUM on its own (ordinary mail says "send feedback to …");
 * combined with a sensitive read, or for a sensitive read or a deletion, it is HIGH.
 */
function agentRequestEvidence(records: readonly AgentRequestEvidence[], objective: UserObjective): SentenceAssessment[] {
  const sensitiveRead = records.some((r) => r.actions.some((a) => a.kind === "read_file" && a.sensitive));
  const out: SentenceAssessment[] = [];
  for (const r of records.slice(0, MAX_SENTENCES)) {
    const f: ThreatFinding[] = [];
    for (const a of r.actions) {
      if (a.kind === "read_file" && a.sensitive)
        f.push({ category: "agent-tool-request", severity: "high", reason: "The agent would turn this text into a read of a CONFIDENTIAL or SECRET file the user did not ask for." });
      else if (a.kind === "send_email" && !objective.allowedRecipients.includes(a.to.toLowerCase()))
        f.push({
          category: "agent-tool-request",
          // Alone this is ordinary business mail ("send the PO to orders@…"): recorded, but no alert. The run's
          // enforcement view still shows what the PEP did with the attempt.
          severity: sensitiveRead ? "high" : "low",
          reason: sensitiveRead
            ? "The agent would turn this text into an email to an address chosen by the content, after reading sensitive data."
            : "The agent would turn this text into an email to an address the user did not name (ordinary request; no sensitive data involved).",
        });
      else if (a.kind === "delete_file") f.push({ category: "agent-tool-request", severity: "high", reason: "The agent would turn this text into a file deletion the user did not ask for." });
    }
    if (f.length === 0) continue;
    const top = f.some((x) => x.severity === "high") ? f.find((x) => x.severity === "high")! : f[0]!;
    out.push(
      Object.freeze({
        evidence: r.evidence.length > EVIDENCE ? `${r.evidence.slice(0, EVIDENCE)}…` : r.evidence,
        role: "tool-misuse" as const,
        level: top.severity === "high" ? ("HIGH" as const) : top.severity === "medium" ? ("MEDIUM" as const) : ("LOW" as const),
        findings: Object.freeze([top]),
        decoded: false,
        conflictsWithObjective: objective.intent !== "other",
      }),
    );
  }
  return out;
}

/**
 * Assess untrusted content against the user's objective. `sourceTrust` is reported separately and never changes the
 * threat level: untrusted content with no findings is LOW, not malicious; trusted content is analysed the same way.
 */
export function assessInstructions(
  content: string | null | undefined,
  objective: UserObjective,
  sourceTrust: SourceTrust,
  agentRequests: readonly AgentRequestEvidence[] = [],
): InstructionAssessment {
  if (typeof content !== "string" || content.trim().length === 0) {
    return result("UNKNOWN", sourceTrust, [], "No analysable content.", "The content was empty or could not be read, so no conclusion is possible.");
  }
  const truncated = content.length > MAX_CHARS;
  const text = plain(truncated ? content.slice(0, MAX_CHARS) : content);
  const sentences = sentencesOf(text).map((s) => assessSentence(s, objective, false));
  for (const payload of decodedPayloads(text)) for (const s of sentencesOf(payload)) sentences.push(assessSentence(s, objective, true));
  sentences.push(...agentRequestEvidence(agentRequests, objective));

  const bounded = sentences.slice(0, MAX_SENTENCES);
  const levels = sentences.map((s) => s.level);
  // Content-level combination: a manipulation marker (override, fake authority, concealment) anywhere in the content
  // together with a tool-misuse request elsewhere in it describes one attack, even when split across sentences.
  const cats = new Set(sentences.flatMap((s) => s.findings.map((f) => f.category)));
  const manipulation = ["instruction-override", "fake-authority", "concealment"].some((c) => cats.has(c as FindingCategory));
  const misuse = ["credential-request", "confidential-access", "external-transfer", "destructive-action", "execution-request", "tool-invocation", "agent-tool-request"].some((c) => cats.has(c as FindingCategory));
  if (manipulation && misuse) levels.push("HIGH");
  let level: ThreatLevel = levels.includes("HIGH") ? "HIGH" : levels.includes("MEDIUM") ? "MEDIUM" : "LOW";
  let uncertainty: string | null = "No indicators is not proof that the content is harmless; the analyzer is rule-based.";
  if (truncated || sentences.length > MAX_SENTENCES) {
    uncertainty = "Only the first part of the content was analysed.";
    if (level === "LOW") level = "UNKNOWN";
  }
  const summary =
    level === "HIGH"
      ? "Strong indicators of embedded malicious instructions."
      : level === "MEDIUM"
        ? "Suspicious instructions detected; they are treated as data, not commands."
        : level === "LOW"
          ? "No meaningful suspicious indicators detected. The content is treated as information."
          : "Insufficient evidence to assess this content.";
  return result(level, sourceTrust, bounded, summary, uncertainty, sentences);
}

function result(level: ThreatLevel, sourceTrust: SourceTrust, shown: SentenceAssessment[], summary: string, uncertainty: string | null, all = shown): InstructionAssessment {
  const findings = all.flatMap((s) => s.findings);
  const score = findings.length ? Math.min(100, findings.reduce((n, x) => n + WEIGHT[x.severity], 0)) : null;
  const confidence = level === "HIGH" && findings.filter((x) => x.severity === "high").length >= 2 ? "high" : level === "UNKNOWN" ? "low" : "medium";
  return Object.freeze({
    level,
    sourceTrust,
    score,
    confidence,
    counts: Object.freeze({
      information: all.filter((s) => s.role === "information").length,
      instruction: all.filter((s) => s.role !== "information").length,
      suspicious: all.filter((s) => s.level === "HIGH" || s.level === "MEDIUM").length,
    }),
    sentences: Object.freeze(shown.filter((s) => s.role !== "information" || s.findings.length > 0)),
    summary,
    uncertainty,
  });
}

/** Derive the user's objective from the (trusted) task text. */
export function objectiveFromTask(task: string): UserObjective {
  const t = String(task).toLowerCase();
  const intent = /\b(?:summari[sz]e|summary|report|brief|overview)\b/.test(t) ? "summarise" : /\b(?:read|review|check|open|look\s+at)\b/.test(t) ? "read" : "other";
  const allowedRecipients = [...t.matchAll(/[a-z0-9._%+-]+@[a-z0-9-]+(?:\.[a-z0-9-]+)+/g)].map((m) => m[0]);
  return Object.freeze({ intent, allowedRecipients: Object.freeze(allowedRecipients) });
}
