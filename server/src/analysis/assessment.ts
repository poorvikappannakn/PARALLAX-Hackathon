import { analyzeInstructions } from "../agent/instructions.js";
import { classifyPath } from "../policy/classification.js";
import { normalizeSandboxPath } from "../shield/paths.js";
import { assessInstructions, objectiveFromTask, type AgentRequestEvidence, type InstructionAssessment, type SourceTrust, type ThreatLevel } from "./instruction-threat.js";
import { analyzeUrl, extractUrls, type UrlAssessment } from "./url-analyzer.js";

// Security assessment of one untrusted source: source trust, instruction threat and URL threat are kept as SEPARATE
// classifications and are never merged into one label. An alert is raised only when evidence justifies it. Advisory
// only: the PEP decides every tool call independently and never reads these results. What AgentShield actually did
// (PEP decisions, executions) is NOT stated here — it depends on the run and is added by the run view (enforcement).

export interface SecurityAlert {
  readonly level: "MEDIUM" | "HIGH";
  readonly detected: string;
  readonly origin: string;
  readonly why: readonly string[];
  readonly attemptedActions: readonly string[];
  readonly potentialImpact: string;
  /** Handling that holds in every mode (inspection as data, no link visits, no attachment execution). */
  readonly contentHandling: string;
}

export interface SourceAssessment {
  readonly sourceTrust: SourceTrust;
  readonly instructions: InstructionAssessment;
  readonly urls: readonly UrlAssessment[];
  /** Highest URL risk, or null when the content contains no URL. */
  readonly urlRisk: ThreatLevel | null;
  readonly alert: SecurityAlert | null;
}

const RANK: Record<ThreatLevel, number> = { LOW: 0, UNKNOWN: 1, MEDIUM: 2, HIGH: 3 };
export const maxLevel = (levels: readonly ThreatLevel[]): ThreatLevel | null => (levels.length ? levels.reduce((a, b) => (RANK[b] > RANK[a] ? b : a)) : null);

const ATTEMPT: Record<string, string> = {
  "credential-request": "retrieve credentials or API keys",
  "confidential-access": "read confidential data",
  "external-transfer": "send data to a recipient chosen by the content",
  "destructive-action": "delete or modify files",
  "execution-request": "run, download, open or visit something",
  "tool-invocation": "invoke agent tools directly",
  "instruction-override": "replace the user's instructions",
  "objective-change": "change the user's objective",
  "agent-tool-request": "make the agent issue a tool request the user did not ask for",
};

const sensitivePath = (p: string) => {
  const n = normalizeSandboxPath(p);
  if (n === null) return true; // unclassifiable path: assume sensitive
  const c = classifyPath(n);
  return c === "CONFIDENTIAL" || c === "SECRET";
};

/** The tool requests the agent's own parser derives from the content, as evidence for the threat assessment. */
function agentRequests(content: string, origin: string): AgentRequestEvidence[] {
  return analyzeInstructions(content, origin).instructions
    .filter((i) => i.recognized.length > 0)
    .map((i) => ({
      evidence: i.evidence,
      actions: i.recognized.map((a) => (a.kind === "read_file" ? { kind: a.kind, sensitive: sensitivePath(a.path) } : a.kind === "send_email" ? { kind: a.kind, to: a.to } : { kind: a.kind })),
    }));
}

export function assessSource(opts: { task: string; origin: string; content: string; extraDomains?: readonly string[]; sourceTrust?: SourceTrust }): SourceAssessment {
  const sourceTrust = opts.sourceTrust ?? "UNTRUSTED";
  const instructions = assessInstructions(opts.content, objectiveFromTask(opts.task), sourceTrust, agentRequests(opts.content, opts.origin));
  const urls = [...new Set([...extractUrls(opts.content), ...(opts.extraDomains ?? [])])].slice(0, 20).map(analyzeUrl);
  const urlRisk = maxLevel(urls.map((u) => u.risk));
  return Object.freeze({ sourceTrust, instructions, urls: Object.freeze(urls), urlRisk, alert: buildAlert(opts.origin, instructions, urls) });
}

/** Advisory analysis of OUTGOING text (e.g. a generated summary about to be emailed): does it carry embedded instructions? */
export function assessOutgoing(text: string): InstructionAssessment {
  return assessInstructions(text, { intent: "other", allowedRecipients: [] }, "UNTRUSTED");
}

function buildAlert(origin: string, ins: InstructionAssessment, urls: readonly UrlAssessment[]): SecurityAlert | null {
  const badUrls = urls.filter((u) => u.risk === "HIGH" || u.risk === "MEDIUM");
  const insAlert = ins.level === "HIGH" || ins.level === "MEDIUM";
  if (!insAlert && badUrls.length === 0) return null;
  const level = ins.level === "HIGH" || badUrls.some((u) => u.risk === "HIGH") ? "HIGH" : "MEDIUM";
  const findings = ins.sentences.flatMap((s) => s.findings);
  const attempted = [...new Set(findings.map((f) => ATTEMPT[f.category]).filter((x): x is string => Boolean(x)))];
  const why = [...new Set(findings.filter((f) => f.severity !== "low").map((f) => f.reason))];
  for (const u of badUrls) why.push(`Link to ${u.hostname ?? "an unparseable destination"}: ${u.indicators.map((i) => i.reason).join(" ")}`);
  const detected = [insAlert ? "embedded instructions that conflict with the user's task" : null, badUrls.length ? `${badUrls.length} suspicious link${badUrls.length > 1 ? "s" : ""}` : null].filter(Boolean).join(" and ");
  return Object.freeze({
    level,
    detected: `Detected ${detected}.`,
    origin,
    why: Object.freeze(why.slice(0, 8)),
    attemptedActions: Object.freeze(attempted),
    potentialImpact: findings.some((f) => f.category === "credential-request" || f.category === "external-transfer" || f.category === "agent-tool-request")
      ? "Disclosure of secrets or confidential data to an outside party, or actions the user did not ask for."
      : findings.some((f) => f.category === "destructive-action")
        ? "Loss of files or records."
        : badUrls.length
          ? "Credential phishing or malware delivery if the link were opened."
          : "The agent could be steered away from the user's task.",
    contentHandling: "AgentShield inspects the content as data. Links are never visited and attachments are never opened or executed by AgentShield.",
  });
}
