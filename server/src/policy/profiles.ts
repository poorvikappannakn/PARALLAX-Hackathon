import type { Confidentiality } from "../shield/provenance.js";

export interface AgentProfile {
  readonly id: string;
  readonly description: string;
  readonly allowedTools: readonly string[];
  readonly fileScopes: readonly string[]; // lower-case directory prefixes ending in "/"
  readonly urlAllowlist: readonly string[]; // exact hostnames, https only
  readonly maxConfidentiality: Confidentiality;
}

export interface UserPrincipal {
  readonly id: string;
  readonly displayName: string;
  readonly email: string;
  readonly clearance: Confidentiality;
}

// All identities and domains are synthetic (.test is reserved and never resolves).
export const AGENT_PROFILES: Readonly<Record<string, AgentProfile>> = Object.freeze({
  "agent:research-assistant": Object.freeze({
    id: "agent:research-assistant",
    description: "Reads reports, web pages and mail; may send email with approval. Cannot delete.",
    allowedTools: Object.freeze(["read_file", "fetch_web", "read_inbox", "send_email"]),
    fileScopes: Object.freeze(["public/", "reports/", "projects/", "hr/"]),
    urlAllowlist: Object.freeze(["vendor.contoso.test", "intranet.northwind.test"]),
    maxConfidentiality: "CONFIDENTIAL",
  }),
  "agent:ops-assistant": Object.freeze({
    id: "agent:ops-assistant",
    description: "Housekeeping agent for project files; may delete with approval. No email.",
    allowedTools: Object.freeze(["read_file", "delete_file"]),
    fileScopes: Object.freeze(["projects/"]),
    urlAllowlist: Object.freeze([]),
    maxConfidentiality: "INTERNAL",
  }),
});

export const USERS: Readonly<Record<string, UserPrincipal>> = Object.freeze({
  "user:alice": Object.freeze({
    id: "user:alice",
    displayName: "Alice Rao (Analyst)",
    email: "alice@northwind.test",
    clearance: "INTERNAL",
  }),
  "user:hana": Object.freeze({
    id: "user:hana",
    displayName: "Hana Iyer (HR Lead)",
    email: "hana@northwind.test",
    clearance: "CONFIDENTIAL",
  }),
});
