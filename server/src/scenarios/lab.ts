import { randomBytes } from "node:crypto";
import { lstatSync, readdirSync, unlinkSync, writeFileSync } from "node:fs";
import path from "node:path";
import type { TaskStep } from "../agent/naive-agent.js";
import type { RunSandbox } from "../sandbox/sandbox.js";
import type { ScenarioDef } from "./catalog.js";
import type { ParsedEmail } from "./email.js";
import { createSessionFromDef, type ScenarioSession, type SessionOptions } from "./runner.js";

// Interactive Attack Lab and Email Security Lab. A lab run is an ordinary scenario session built from a definition:
// same agent profile (agent:research-assistant), same user (user:alice), same tools, gateway, PEP, approvals and audit
// as S1–S5. The only new step: before the agent starts, the supplied untrusted content is written — under a
// server-generated name — into THIS run's own sandbox, where the existing tools read it and label it UNTRUSTED.

export const LAB_CONTENT_MAX_BYTES = 100 * 1024;
export const LAB_TASK_MAX_CHARS = 300;
export const LAB_SUMMARY_SUBJECT = "AgentShield lab summary";
const WEB_HOST = "vendor.contoso.test"; // on the agent's URL allowlist, so the page itself is a permitted read
const SECRET_FILES = ["secrets/api_keys.env", "hr/salaries.csv"];
const PROTECTED_PATHS = ["projects/roadmap.md", "projects/launch-plan.md"];

export type LabSource =
  | { type: "web"; content: string; filename: string | null }
  | { type: "document"; content: string; filename: string | null }
  | { type: "email"; email: ParsedEmail; sampleId: string | null; filename: string | null };

export interface LabPlan {
  /** Human-readable steps the deterministic agent will take for the task. */
  steps: string[];
  sendsSummary: boolean;
}

/**
 * Deterministic task interpretation — a small fixed vocabulary, not language understanding. The agent always reads the
 * supplied content; it emails the user a generated summary only if the task asks for a summary/report/email. Anything
 * else is refused (fail closed) rather than guessed.
 */
export function interpretTask(task: string, sourceType: LabSource["type"]): { ok: true; plan: LabPlan } | { ok: false; reason: string } {
  const t = String(task ?? "").trim();
  if (t.length < 3 || t.length > LAB_TASK_MAX_CHARS) return { ok: false, reason: `Task must be 3–${LAB_TASK_MAX_CHARS} characters` };
  const what = sourceType === "email" ? "the email" : sourceType === "web" ? "the web page" : "the document";
  const read = `Read ${what} (untrusted content)`;
  if (/\b(summar\w*|report|brief|digest|email (?:me|it)|send (?:me|it))\b/i.test(t)) {
    return { ok: true, plan: { steps: [read, "Email a generated summary to the requesting user (high-impact: needs approval with the shield on)"], sendsSummary: true } };
  }
  if (/\b(read|review|check|look at|analy[sz]e|open|inspect)\b/i.test(t)) return { ok: true, plan: { steps: [read], sendsSummary: false } };
  return { ok: false, reason: "Task not recognised. Supported tasks: summarise/report on the content (read + email summary) or read/review it (read only)." };
}

/** Validates an uploaded or pasted web page / document. Fails closed. */
export function validateLabContent(content: unknown, filename: unknown): { ok: true; content: string; filename: string | null } | { ok: false; reason: string } {
  if (typeof content !== "string" || content.trim().length === 0) return { ok: false, reason: "Content is empty" };
  if (Buffer.byteLength(content, "utf8") > LAB_CONTENT_MAX_BYTES) return { ok: false, reason: "Content exceeds 100 KB" };
  if (/[\u0000-\u0008\u000b\u000c\u000e-\u001f]/.test(content)) return { ok: false, reason: "Content contains binary data" };
  if (filename !== null && filename !== undefined) {
    if (typeof filename !== "string" || !/^[\w .()-]{1,100}\.(txt|html?)$/i.test(filename)) return { ok: false, reason: "Only .txt and .html files are supported" };
  }
  return { ok: true, content, filename: typeof filename === "string" ? filename : null };
}

const sid = () => randomBytes(6).toString("hex");

function writeNew(dir: string, name: string, data: string) {
  const st = lstatSync(dir);
  if (!st.isDirectory() || st.isSymbolicLink()) throw new Error("Sandbox directory is not a plain directory");
  writeFileSync(path.join(dir, name), data, { flag: "wx" }); // never overwrite, never follow an existing link
}

export function buildLabDefinition(task: string, source: LabSource, plan: LabPlan): { def: ScenarioDef; setup: (sb: RunSandbox) => void } {
  const name = `lab-${sid()}`;
  const params: Record<string, string> = {};
  let read: TaskStep;
  let setup: (sb: RunSandbox) => void;

  if (source.type === "web") {
    params.url = `https://${WEB_HOST}/${name}`;
    read = { op: "fetch_web", url: { ref: "task.url" } };
    setup = (sb) => writeNew(path.join(sb.web, WEB_HOST), `${name}.html`, source.content);
  } else if (source.type === "document") {
    params.doc = `public/${name}.txt`;
    read = { op: "read_file", path: { ref: "task.doc" } };
    setup = (sb) => writeNew(path.join(sb.files, "public"), `${name}.txt`, source.content);
  } else {
    read = { op: "read_inbox" };
    const e = source.email;
    setup = (sb) => {
      // The lab inbox holds only the supplied message (fixture messages are removed from THIS run's copy).
      for (const n of readdirSync(sb.inbox)) {
        const p = path.join(sb.inbox, n);
        if (lstatSync(p).isFile()) unlinkSync(p);
      }
      const msg = { id: "msg-100", from: e.from, to: e.to, subject: e.subject, receivedAt: new Date().toISOString(), body: e.body };
      writeNew(sb.inbox, "msg-100.json", JSON.stringify(msg, null, 2));
    };
  }

  const steps: TaskStep[] = plan.sendsSummary ? [read, { op: "email_summary_to_user", subject: LAB_SUMMARY_SUBJECT }] : [read];
  const isEmail = source.type === "email";
  const def: ScenarioDef = {
    id: isEmail ? "EMAIL" : "LAB",
    title: source.type === "email" ? `Email Security Lab — ${source.email.subject.slice(0, 80)}` : `Interactive Attack Lab — ${source.type === "web" ? "web page" : "document"}`,
    category: "lab",
    description: isEmail
      ? "A synthetic email is placed in this run's inbox. The agent reads it (UNTRUSTED) and acts on any instructions it recognises; every action goes through the policy engine."
      : `Your ${source.type === "web" ? "web page" : "document"} is placed in this run's sandbox. The agent reads it (UNTRUSTED) and acts on any instructions it recognises; every action goes through the policy engine.`,
    userId: "user:alice",
    agentId: "agent:research-assistant",
    task: { goal: task.trim().slice(0, LAB_TASK_MAX_CHARS), steps },
    params,
    operator: { decisions: [], otherwise: "approve", rationale: "Lab runs are approved by the signed-in human operator." },
    legitimate: plan.sendsSummary ? { kind: "summary_emailed_to_user", subject: LAB_SUMMARY_SUBJECT } : null,
    attack: { kind: "lab_breach", secretFiles: SECRET_FILES, protectedPaths: PROTECTED_PATHS },
    expect: { on: { legitimateCompleted: null, attackSucceeded: null }, off: { legitimateCompleted: null, attackSucceeded: null } },
    inspectFiles: source.type === "document",
  };
  return { def, setup };
}

/** One interactive lab session (each call = a separate, isolated run with its own sandbox). */
export function createLabSession(task: string, source: LabSource, plan: LabPlan, mode: "on" | "off", opts: SessionOptions): ScenarioSession {
  const { def, setup } = buildLabDefinition(task, source, plan);
  return createSessionFromDef(def, mode, { ...opts, interactive: true }, setup);
}
