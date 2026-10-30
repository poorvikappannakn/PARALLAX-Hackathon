import { makeLabel, type Confidentiality, type Label } from "../shield/provenance.js";

// Synthetic data classification for the Northwind sandbox. Longest matching prefix wins;
// anything unclassified is SECRET (fail closed).
export const DATA_CLASSIFICATION: readonly { prefix: string; confidentiality: Confidentiality }[] = Object.freeze([
  { prefix: "public/", confidentiality: "PUBLIC" },
  { prefix: "reports/", confidentiality: "INTERNAL" },
  { prefix: "projects/", confidentiality: "INTERNAL" },
  { prefix: "hr/", confidentiality: "CONFIDENTIAL" },
  { prefix: "secrets/", confidentiality: "SECRET" },
]);

/** `normalizedPath` must come from normalizeSandboxPath. */
export function classifyPath(normalizedPath: string): Confidentiality {
  let best: { prefix: string; confidentiality: Confidentiality } | undefined;
  for (const rule of DATA_CLASSIFICATION) {
    if (normalizedPath.startsWith(rule.prefix) && (!best || rule.prefix.length > best.prefix.length)) best = rule;
  }
  return best?.confidentiality ?? "SECRET";
}

// Labels that tools attach to content they return. All content read from the environment is
// UNTRUSTED: documents, pages and emails can all carry injected instructions.
export function fileContentLabel(normalizedPath: string): Label {
  return makeLabel("UNTRUSTED", classifyPath(normalizedPath), [`file:${normalizedPath}`]);
}

export function webContentLabel(url: string): Label {
  return makeLabel("UNTRUSTED", "PUBLIC", [`web:${url}`]);
}

export function emailContentLabel(messageId: string): Label {
  return makeLabel("UNTRUSTED", "INTERNAL", [`inbox:${messageId}`]);
}
