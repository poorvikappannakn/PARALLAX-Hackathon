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
 * Parse tool-action instructions from untrusted text. `source` names where the text came from (e.g. "web:<url>",
 * "inbox:msg-3") and is attached to every action; it is truncated, never interpreted.
 */
export function parseInstructions(input: string, source: string): ParseResult {
  const text = typeof input === "string" ? input : "";
  const truncated = text.length > LIMITS.maxInputChars;
  const plain = toPlainText(truncated ? text.slice(0, LIMITS.maxInputChars) : text);
  const src = String(source).slice(0, LIMITS.maxSourceChars);

  const actions: UntrustedAction[] = [];
  const seen = new Set<string>();
  const rejected: { kind: InstructionKind; reason: RejectionReason }[] = [];

  const reject = (kind: InstructionKind, reason: RejectionReason) => {
    if (rejected.length < LIMITS.maxRejections) rejected.push({ kind, reason });
  };
  const add = (a: ParsedAction) => {
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
    return found;
  };

  for (const sentence of sentences(plain)) {
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

  return Object.freeze({
    actions: Object.freeze(actions),
    rejected: Object.freeze(rejected.map((r) => Object.freeze(r))),
    approvalClaims: [...plain.matchAll(APPROVAL_CLAIM)].length,
    truncated,
  });
}
