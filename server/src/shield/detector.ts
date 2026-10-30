// Heuristic prompt-injection signal. It is a secondary signal only: the PEP may use it to make a
// decision stricter, never to allow anything. Security does not depend on it catching attacks.

export interface DetectorHit {
  readonly pattern: string;
  readonly weight: number;
  readonly excerpt: string;
}

export interface DetectorResult {
  readonly score: number; // 0-100
  readonly hits: readonly DetectorHit[];
}

const PATTERNS: readonly { id: string; weight: number; re: RegExp }[] = [
  { id: "override-instructions", weight: 60, re: /\b(ignore|disregard|forget|override)\b[^.\n]{0,40}\b(previous|prior|above|earlier|all|your)\b[^.\n]{0,25}\b(instructions?|rules|prompts?|guidelines)\b/i },
  { id: "role-hijack", weight: 35, re: /\b(you are now|new instructions|system prompt|developer mode|act as an? )/i },
  { id: "conceal-from-user", weight: 30, re: /\b(do not|don't|never)\s+(tell|inform|mention|alert|notify)\b[^.\n]{0,25}\b(user|anyone|them)\b/i },
  { id: "tool-name", weight: 25, re: /\b(read_file|send_email|delete_file|fetch_web|read_inbox)\b/ },
  { id: "credential-target", weight: 20, re: /\b(api[_ -]?keys?|passwords?|secrets?|credentials?|access tokens?)\b/i },
  { id: "exfiltration-verb", weight: 20, re: /\b(send|email|forward|upload|post|exfiltrate)\b[^.\n]{0,60}\b(to|@)/i },
  { id: "mass-destruction", weight: 25, re: /\b(delete|wipe|erase|remove|purge)\b[^.\n]{0,30}\b(all|every|everything|entire)\b/i },
  { id: "hidden-markup", weight: 15, re: /<!--|display\s*:\s*none|font-size\s*:\s*0|[​-‍⁠]/i },
];

export function scanText(text: string): DetectorResult {
  const hits: DetectorHit[] = [];
  for (const p of PATTERNS) {
    const m = p.re.exec(text);
    if (m) {
      const start = Math.max(0, m.index - 20);
      hits.push({ pattern: p.id, weight: p.weight, excerpt: text.slice(start, m.index + m[0].length + 20).replace(/\s+/g, " ").trim() });
    }
  }
  return { score: Math.min(100, hits.reduce((s, h) => s + h.weight, 0)), hits };
}

/** Scans several texts; each pattern counts once overall. */
export function scanTexts(texts: readonly string[]): DetectorResult {
  const byPattern = new Map<string, DetectorHit>();
  for (const t of texts) for (const h of scanText(t).hits) if (!byPattern.has(h.pattern)) byPattern.set(h.pattern, h);
  const hits = [...byPattern.values()];
  return { score: Math.min(100, hits.reduce((s, h) => s + h.weight, 0)), hits };
}
