// Tool manifests: what each tool can affect and the role of each argument.
//  - target: chooses *where* a high-impact action lands (recipient, file to delete) -> must be TRUSTED (P4)
//  - data:   content carried by the action -> UNTRUSTED data requires approval (A1)
//  - option: harmless parameters
// Argument kinds `sandbox_path` and `url` are also resource arguments, scope-checked by P2.

export type ToolEffect = "READ" | "EXTERNAL_SEND" | "DESTRUCTIVE";
export type ToolImpact = "LOW" | "HIGH";
export type ArgKind = "sandbox_path" | "url" | "email" | "text" | "count";
export type ArgRole = "target" | "data" | "option";

export interface ArgSpec {
  readonly kind: ArgKind;
  readonly role: ArgRole;
  readonly required: boolean;
  readonly maxLength?: number;
}

export interface ToolManifest {
  readonly name: string;
  readonly description: string;
  readonly effect: ToolEffect;
  readonly impact: ToolImpact;
  readonly args: Readonly<Record<string, ArgSpec>>;
}

function deepFreeze<T>(o: T): T {
  if (o && typeof o === "object") {
    for (const v of Object.values(o)) deepFreeze(v);
    Object.freeze(o);
  }
  return o;
}

export const TOOL_MANIFESTS: Readonly<Record<string, ToolManifest>> = deepFreeze({
  read_file: {
    name: "read_file",
    description: "Read a file from the agent's sandbox.",
    effect: "READ",
    impact: "LOW",
    args: { path: { kind: "sandbox_path", role: "option", required: true } },
  },
  fetch_web: {
    name: "fetch_web",
    description: "Fetch an allow-listed web page (served from local fixtures; no real network).",
    effect: "READ",
    impact: "LOW",
    args: { url: { kind: "url", role: "option", required: true } },
  },
  read_inbox: {
    name: "read_inbox",
    description: "List recent messages in the user's synthetic inbox.",
    effect: "READ",
    impact: "LOW",
    args: { limit: { kind: "count", role: "option", required: false } },
  },
  send_email: {
    name: "send_email",
    description: "Send an email (written to the sandbox outbox; never really sent).",
    effect: "EXTERNAL_SEND",
    impact: "HIGH",
    args: {
      to: { kind: "email", role: "target", required: true },
      subject: { kind: "text", role: "data", required: true, maxLength: 200 },
      body: { kind: "text", role: "data", required: true, maxLength: 10_000 },
    },
  },
  delete_file: {
    name: "delete_file",
    description: "Delete a file inside the agent's sandbox.",
    effect: "DESTRUCTIVE",
    impact: "HIGH",
    args: { path: { kind: "sandbox_path", role: "target", required: true } },
  },
});
