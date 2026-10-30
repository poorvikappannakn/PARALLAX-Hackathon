import { z } from "zod";
import type { ArgSpec, ToolManifest } from "../policy/manifests.js";
import { parseLabel, type Label } from "./provenance.js";

// Shared argument validation used by both the PEP and the tool executor, so the two can never disagree
// about what a well-formed call looks like.

export const labeledArgSchema = z.object({ value: z.unknown(), label: z.unknown() }).strict();

export function argValueSchema(spec: ArgSpec): z.ZodType {
  switch (spec.kind) {
    case "sandbox_path":
      return z.string().min(1).max(256);
    case "url":
      return z.string().min(1).max(2048);
    case "email":
      return z.email().max(254);
    case "text":
      return z.string().max(spec.maxLength ?? 1000);
    case "count":
      return z.int().min(1).max(50);
  }
}

export type ValidatedArgs =
  | { ok: true; values: Record<string, unknown>; labels: Record<string, Label> }
  | { ok: false; reason: string };

const has = (o: object, k: string) => Object.prototype.hasOwnProperty.call(o, k);

/** Strictly validates labelled arguments against a manifest: no extra, missing, unlabelled or invalid args. */
export function validateArgs(manifest: ToolManifest, args: Record<string, unknown>): ValidatedArgs {
  for (const name of Object.keys(args)) {
    if (!has(manifest.args, name)) return { ok: false, reason: `Unexpected argument "${name}" for ${manifest.name}` };
  }
  const values: Record<string, unknown> = {};
  const labels: Record<string, Label> = {};
  for (const [name, spec] of Object.entries(manifest.args)) {
    if (!has(args, name)) {
      if (spec.required) return { ok: false, reason: `Missing required argument "${name}"` };
      continue;
    }
    const arg = labeledArgSchema.safeParse(args[name]);
    if (!arg.success) return { ok: false, reason: `Argument "${name}" is not a labelled value` };
    const label = parseLabel(arg.data.label);
    if (!label) return { ok: false, reason: `Argument "${name}" has missing or malformed provenance` };
    if (!argValueSchema(spec).safeParse(arg.data.value).success) {
      return { ok: false, reason: `Argument "${name}" failed validation for kind ${spec.kind}` };
    }
    values[name] = arg.data.value;
    labels[name] = label;
  }
  return { ok: true, values, labels };
}
