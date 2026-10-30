import { lstatSync, readdirSync, readFileSync } from "node:fs";
import path from "node:path";
import { analyzeInstructions, plainTextPreview, type ContentAnalysis } from "../agent/instructions.js";
import type { RunSandbox } from "../sandbox/sandbox.js";
import type { ScenarioDef } from "./catalog.js";

// Untrusted Content Inspector (data side). Captures, from THIS run's sandbox, the untrusted content the agent will read —
// web pages it fetches, inbox messages, and (lab only) the supplied document — together with the deterministic parser's
// analysis. Task files are never included: they may be confidential (S3's salary file). Labels match the provenance
// sources the tools assign (web:<url>, inbox:<id>, file:<path>), so the UI can link content to agent steps.

export interface UntrustedSource {
  type: "web" | "document" | "email";
  /** Provenance source the tools assign to this content. */
  label: string;
  title: string;
  from: string | null;
  preview: string;
  previewTruncated: boolean;
  analysis: ContentAnalysis;
}

const MAX_BYTES = 100 * 1024;

/** Read a plain, regular, bounded file inside `base`; null otherwise (never follows links). */
function safeRead(base: string, rel: string): string | null {
  const full = path.resolve(base, rel);
  if (!full.startsWith(path.resolve(base) + path.sep)) return null;
  try {
    const st = lstatSync(full);
    if (!st.isFile() || st.isSymbolicLink() || st.nlink > 1 || st.size > MAX_BYTES) return null;
    return readFileSync(full, "utf8");
  } catch {
    return null;
  }
}

const argValue = (def: ScenarioDef, arg: { ref: string } | { value: string }) =>
  "value" in arg ? arg.value : arg.ref.startsWith("task.") ? def.params[arg.ref.slice(5)] : undefined;

function source(type: UntrustedSource["type"], label: string, title: string, from: string | null, content: string): UntrustedSource {
  const preview = plainTextPreview(content);
  return { type, label, title, from, preview: preview.text, previewTruncated: preview.truncated, analysis: analyzeInstructions(content, label) };
}

export function inspectSources(def: ScenarioDef, sandbox: RunSandbox): UntrustedSource[] {
  const out: UntrustedSource[] = [];
  for (const step of def.task.steps) {
    if (step.op === "fetch_web") {
      const raw = argValue(def, step.url);
      let url: URL;
      try {
        url = new URL(String(raw));
      } catch {
        continue;
      }
      // Same mapping as the fetch_web tool: https://host/page -> web/<host>/<page>.html
      const page = url.pathname === "/" ? "/index.html" : url.pathname.endsWith(".html") ? url.pathname : `${url.pathname}.html`;
      const content = safeRead(sandbox.web, `${url.hostname}${page}`);
      if (content !== null) out.push(source("web", `web:https://${url.hostname}${url.pathname}`, url.hostname, null, content));
    } else if (step.op === "read_inbox") {
      let names: string[] = [];
      try {
        names = readdirSync(sandbox.inbox).filter((n) => /^msg-\d{1,6}\.json$/.test(n)).sort();
      } catch {
        names = [];
      }
      for (const name of names) {
        const raw = safeRead(sandbox.inbox, name);
        if (raw === null) continue;
        try {
          const m = JSON.parse(raw) as Record<string, unknown>;
          if (typeof m.id !== "string" || typeof m.body !== "string") continue;
          const subject = typeof m.subject === "string" ? m.subject : "";
          // Analyse exactly what the agent parses: subject + body.
          out.push(source("email", `inbox:${m.id}`, subject || "(no subject)", typeof m.from === "string" ? m.from : null, `${subject}\n\n${m.body}`));
        } catch {
          /* malformed message: the tool would reject it too */
        }
      }
    } else if (step.op === "read_file" && def.inspectFiles) {
      const rel = argValue(def, step.path);
      if (typeof rel !== "string") continue;
      const content = safeRead(sandbox.files, rel);
      if (content !== null) out.push(source("document", `file:${rel}`, rel.split("/").pop() ?? rel, null, content));
    }
  }
  return out;
}
