// Instruction parser for the deliberately gullible NaiveAgent (M4).
//
// It extracts tool-action instructions (read_file, send_email, delete_file) from text the agent has read, so that the demo
// agent really does act on injected content. It is a deterministic, regex-based parser, NOT an AI model.
//
// Security posture:
//  - Everything returned is UNTRUSTED data. The parser has no notion of approval or authority: phrases such as
//    "pre-approved" or "authorised by IT" are counted for display only and never change the actions produced.
//  - Pure and deterministic: no I/O, no clock, no randomness. Same input => same output.
//  - Bounded: input length, number of actions and number of rejections are capped.
//  - Malformed or ambiguous instructions (no target, several recipients, directories/wildcards, absolute or ".." paths,
//    negated verbs) are rejected with a fixed reason; rejected text is never echoed.

export type InstructionKind = "read_file" | "send_email" | "delete_file";

export type ParsedAction =
  | { readonly kind: "read_file"; readonly path: string }
  | { readonly kind: "send_email"; readonly to: string; readonly subject: string | null }
  | { readonly kind: "delete_file"; readonly path: string };

export type UntrustedAction = ParsedAction & { readonly trust: "UNTRUSTED"; readonly source: string };

export type RejectionReason =
  | "missing target"
  | "missing recipient"
  | "ambiguous recipient"
  | "directory or wildcard target"
  | "unsafe path"
  | "negated instruction"
  | "action limit reached";

export interface ParseResult {
  readonly actions: readonly UntrustedAction[];
  readonly rejected: readonly { readonly kind: InstructionKind; readonly reason: RejectionReason }[];
  /** Number of injected approval/authority claims seen. Informational only: never authorises anything. */
  readonly approvalClaims: number;
  readonly truncated: boolean;
}

export const LIMITS = Object.freeze({
  maxInputChars: 20_000,
  maxActions: 8,
  maxRejections: 20,
  maxPathChars: 200,
  maxEmailChars: 254,
  maxSubjectChars: 200,
  maxSourceChars: 200,
});

const VERBS: readonly [RegExp, InstructionKind][] = [
  [/^(?:read_file|read|open|cat|load)$/i, "read_file"],
  [/^(?:send_email|send|e-?mail|mail|forward)$/i, "send_email"],
  [/^(?:delete_file|delete|remove|erase|wipe|rm)$/i, "delete_file"],
];
const VERB = /\b(read_file|send_email|delete_file|read|open|cat|load|send|e-?mail|mail|forward|delete|remove|erase|wipe|rm)\b/gi;

// Relative sandbox-style path: at least one "/" segment. Not preceded by path/URL characters, so "/etc/passwd" and
// "C:\x" never match (they are not relative sandbox paths).
const PATH = /(?<![\w/\\:.~-])[A-Za-z0-9_-][A-Za-z0-9_.-]*(?:\/[A-Za-z0-9_.*-]*)+/g;
const EMAIL = /(?<![\w.+-])[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+(?![\w@-])/g;
const SUBJECT = /\bsubject\s*[:=]?\s*["“']([^"”'\r\n]{1,200})["”']/i;
const NEGATION = /\b(?:do\s+not|don'?t|never|not)\s+(?:\w+\s+){0,2}$/i;
const APPROVAL_CLAIM = /\b(?:pre-?approved|already\s+approved|approved\s+by|authori[sz]ed\s+by|has\s+been\s+approved|no\s+approval\s+(?:is\s+)?(?:needed|required))\b/gi;

function verbKind(word: string): InstructionKind {
  for (const [re, kind] of VERBS) if (re.test(word)) return kind;
  throw new Error("unreachable: VERB and VERBS disagree");
}

/** Strip markup so hidden text (display:none, comments) is read like any other text — the agent is gullible by design. */
function toPlainText(input: string): string {
  return input
    .replace(/<!--|-->/g, " ")
    .replace(/<[^>]*>/g, " ")
    .replace(/&quot;/g, '"')
    .replace(/&#39;|&apos;/g, "'")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&amp;/g, "&")
    .replace(/\bhttps?:\/\/\S+/gi, " "); // URLs are not file paths
}

/**
 * Sentences: split at blank lines and at . ! ? followed by whitespace (so "api_keys.env" and "evil.test" stay intact).
 * Single line breaks are treated as spaces because markup and mail wrap instructions across lines.
 */
function sentences(text: string): string[] {
  return text
    .split(/\r?\n[ \t]*\r?\n|(?<=[.!?])\s+/)
    .map((s) => s.replace(/\s+/g, " "))
    .map((s) => s.trim())
    .filter(Boolean);
}

type PathCheck = { ok: true; path: string } | { ok: false; reason: RejectionReason };

function checkPath(raw: string): PathCheck {
  const path = raw.replace(/\.+$/, ""); // trailing sentence punctuation
  if (path.length === 0 || path.length > LIMITS.maxPathChars) return { ok: false, reason: "unsafe path" };
  if (path.split("/").some((seg) => seg === "." || seg === "..")) return { ok: false, reason: "unsafe path" };
  if (path.endsWith("/") || path.includes("*")) return { ok: false, reason: "directory or wildcard target" };
  return { ok: true, path };
}

const paths = (region: string) => [...region.matchAll(PATH)].map((m) => m[0]);
const emails = (region: string) => [...new Set([...region.matchAll(EMAIL)].map((m) => m[0].toLowerCase()))];

/**
 * Named resources the gullible agent resolves to concrete sandbox files when an instruction gives NO explicit path
 * ("read the confidential API keys" → secrets/api_keys.env). A small, fixed, documented table — not language
 * understanding. Explicit paths always take precedence, so existing parses are unchanged.
 */
export const RESOURCE_ALIASES: readonly { pattern: RegExp; kind: "read_file" | "delete_file"; paths: readonly string[]; label: string }[] = Object.freeze([
  { pattern: /\b(?:api[ -]?keys?(?: file)?|environment secrets|secret keys?|credentials? file|secrets? file)\b/i, kind: "read_file", paths: ["secrets/api_keys.env"], label: "API keys / secrets" },
  { pattern: /\b(?:salar(?:y|ies)(?: file| data)?|payroll)\b/i, kind: "read_file", paths: ["hr/salaries.csv"], label: "salary data" },
  { pattern: /\bproject (?:documentation|docs|files)\b/i, kind: "delete_file", paths: ["projects/roadmap.md", "projects/launch-plan.md"], label: "project documentation" },
]);

const aliasPaths = (kind: "read_file" | "delete_file", region: string) =>
  RESOURCE_ALIASES.filter((a) => a.kind === kind && a.pattern.test(region)).flatMap((a) => a.paths);

/** Inspector-only signals: phrases typical of injected instructions. They never cause or authorise anything. */
const SIGNALS: readonly { name: SignalName; pattern: RegExp }[] = [
  { name: "instruction override", pattern: /\b(?:ignore|disregard|forget)\b[^.!?\n]{0,30}\b(?:previous|prior|above|earlier|all)\b[^.!?\n]{0,20}\binstructions?\b|\bsystem override\b|\bnew instructions\b/i },
  { name: "concealment", pattern: /\b(?:do not|don'?t|never)\s+(?:tell|inform|disclose|mention|reveal|notify)\b/i },
  { name: "authority claim", pattern: /\byou are now authori[sz]ed\b|\b(?:pre-?approved|already approved|authori[sz]ed by)\b/i },
  { name: "urgency", pattern: /\b(?:urgent|immediately|right now|action required)\b/i },
];
export type SignalName = "instruction override" | "concealment" | "authority claim" | "urgency";

interface SentenceRecord {
  text: string;
  actions: ParsedAction[];
  rejections: { kind: InstructionKind; reason: RejectionReason }[];
}

/**
 * Parse tool-action instructions from untrusted text. `source` names where the text came from (e.g. "web:<url>",
 * "inbox:msg-3") and is attached to every action; it is truncated, never interpreted.
 */
export function parseInstructions(input: string, source: string): ParseResult {
  return parseCore(input, source).result;
}

function parseCore(input: string, source: string): { result: ParseResult; records: SentenceRecord[] } {
  const text = typeof input === "string" ? input : "";
  const truncated = text.length > LIMITS.maxInputChars;
  const plain = toPlainText(truncated ? text.slice(0, LIMITS.maxInputChars) : text);
  const src = String(source).slice(0, LIMITS.maxSourceChars);

  const actions: UntrustedAction[] = [];
  const seen = new Set<string>();
  const rejected: { kind: InstructionKind; reason: RejectionReason }[] = [];
  const records: SentenceRecord[] = [];
  let current: SentenceRecord | null = null;

  const reject = (kind: InstructionKind, reason: RejectionReason) => {
    current?.rejections.push({ kind, reason });
    if (rejected.length < LIMITS.maxRejections) rejected.push({ kind, reason });
  };
  const add = (a: ParsedAction) => {
    current?.actions.push(a);
    const key = JSON.stringify(a);
    if (seen.has(key)) return;
    if (actions.length >= LIMITS.maxActions) return reject(a.kind, "action limit reached");
    seen.add(key);
    actions.push(Object.freeze({ ...a, trust: "UNTRUSTED" as const, source: src }));
  };
  const addPaths = (kind: "read_file" | "delete_file", region: string): number => {
    let found = 0;
    for (const raw of paths(region)) {
      found++;
      const p = checkPath(raw);
      if (p.ok) add({ kind, path: p.path });
      else reject(kind, p.reason);
    }
    if (found === 0) {
      for (const p of aliasPaths(kind, region)) {
        found++;
        add({ kind, path: p });
      }
    }
    return found;
  };

  for (const sentence of sentences(plain)) {
    current = { text: sentence, actions: [], rejections: [] };
    records.push(current);
    // Group consecutive verbs of the same kind ("use delete_file to delete ...") into one instruction. Each group's
    // arguments are the text up to the next group's verb.
    const verbs = [...sentence.matchAll(VERB)].map((m) => ({ kind: verbKind(m[0]), start: m.index, end: m.index + m[0].length }));
    const groups: { kind: InstructionKind; start: number; end: number }[] = [];
    for (const v of verbs) {
      const last = groups.at(-1);
      if (last && last.kind === v.kind) last.end = v.end;
      else groups.push({ ...v });
    }

    groups.forEach((g, i) => {
      const region = sentence.slice(g.end, groups[i + 1]?.start ?? sentence.length);
      if (NEGATION.test(sentence.slice(0, g.start))) return reject(g.kind, "negated instruction");

      if (g.kind === "send_email") {
        // "email the contents of secrets/x.env to y" implies reading the file first.
        addPaths("read_file", region);
        const to = emails(region);
        if (to.length === 0) return reject(g.kind, "missing recipient");
        if (to.length > 1) return reject(g.kind, "ambiguous recipient");
        if (to[0]!.length > LIMITS.maxEmailChars) return reject(g.kind, "ambiguous recipient");
        const subject = SUBJECT.exec(region)?.[1]?.trim().slice(0, LIMITS.maxSubjectChars) ?? null;
        return add({ kind: "send_email", to: to[0]!, subject: subject || null });
      }
      if (addPaths(g.kind, region) === 0) reject(g.kind, "missing target");
    });
  }

  const result: ParseResult = Object.freeze({
    actions: Object.freeze(actions),
    rejected: Object.freeze(rejected.map((r) => Object.freeze(r))),
    approvalClaims: [...plain.matchAll(APPROVAL_CLAIM)].length,
    truncated,
  });
  return { result, records };
}

// ---- inspector analysis -------------------------------------------------------------------------------------------

export type InstructionCategory = "sensitive-data access" | "file read" | "external disclosure" | "destructive action";

export interface AnalyzedInstruction {
  /** The sentence of the untrusted content that produced this entry (bounded). */
  readonly evidence: string;
  readonly signals: readonly SignalName[];
  readonly recognized: readonly (ParsedAction & { readonly category: InstructionCategory })[];
  readonly unsupported: readonly { readonly kind: InstructionKind; readonly reason: RejectionReason }[];
}

export interface ContentAnalysis {
  readonly instructions: readonly AnalyzedInstruction[];
  readonly truncated: boolean;
}

const EVIDENCE_CHARS = 300;
const MAX_ANALYZED = 20;

function categorize(a: ParsedAction): InstructionCategory {
  if (a.kind === "delete_file") return "destructive action";
  if (a.kind === "send_email") return "external disclosure";
  return /^(?:secrets|hr)\//.test(a.path) ? "sensitive-data access" : "file read";
}

/**
 * For the Untrusted Content Inspector: which sentences of the content the agent would treat as instructions, what it
 * recognised (and would attempt), what it could not interpret, and suspicious-phrase signals. Pure; purely descriptive —
 * it never authorises anything, and the agent itself uses parseInstructions().
 */
export function analyzeInstructions(input: string, source: string): ContentAnalysis {
  const { result, records } = parseCore(input, source);
  const instructions = records
    .map((r) => ({
      evidence: r.text.length > EVIDENCE_CHARS ? `${r.text.slice(0, EVIDENCE_CHARS)}…` : r.text,
      signals: SIGNALS.filter((s) => s.pattern.test(r.text)).map((s) => s.name),
      recognized: r.actions.map((a) => Object.freeze({ ...a, category: categorize(a) })),
      unsupported: r.rejections,
    }))
    .filter((r) => r.recognized.length > 0 || r.unsupported.length > 0 || r.signals.length > 0)
    .slice(0, MAX_ANALYZED);
  return Object.freeze({ instructions: Object.freeze(instructions), truncated: result.truncated });
}

/** Plain-text rendering of untrusted content (markup removed, whitespace normalised) for safe, bounded previews. */
export function plainTextPreview(input: string, maxChars = 4000): { text: string; truncated: boolean } {
  const plain = toPlainText(typeof input === "string" ? input.slice(0, LIMITS.maxInputChars) : "")
    .split(/\r?\n/)
    .map((l) => l.replace(/[ \t]+/g, " ").trim())
    .filter((l, i, a) => l.length > 0 || (i > 0 && a[i - 1]!.length > 0))
    .join("\n")
    .trim();
  return plain.length > maxChars ? { text: `${plain.slice(0, maxChars)}…`, truncated: true } : { text: plain, truncated: false };
}
