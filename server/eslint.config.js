import tseslint from "typescript-eslint";

// Architectural import boundaries (security-relevant; verified by tests/import-boundaries.test.ts).
// Flat config: for a given file the LAST matching block's "no-restricted-imports" wins, so each area lists its full set.

const TOOL_IMPL = { group: ["**/tools/impl", "**/tools/impl.js"], message: "Tool implementations are reachable only via the executor." };
const EXECUTION = {
  group: ["**/tools", "**/tools/index", "**/tools/index.js", "**/shield/tickets", "**/shield/tickets.js"],
  message: "Only the gateway may issue tickets or run tools (use the ToolGateway).",
};

export default tseslint.config(
  ...tseslint.configs.recommended,
  {
    // Everything except the gateway, tools and agent: no ticket issuance, no executor, no tool implementations.
    // This stops API or other modules from assembling PEP + issuer + executor and skipping the audit trail.
    files: ["src/**/*.ts"],
    ignores: ["src/gateway/**", "src/tools/**", "src/agent/**"],
    rules: { "no-restricted-imports": ["error", { patterns: [TOOL_IMPL, EXECUTION] }] },
  },
  {
    // The gateway is the one place that wires PEP -> audit -> ticket -> executor.
    files: ["src/gateway/**/*.ts"],
    rules: { "no-restricted-imports": ["error", { patterns: [TOOL_IMPL] }] },
  },
  {
    // Tools may not evaluate policy or mint tickets; they only receive a ticket redeemer (type import allowed).
    files: ["src/tools/**/*.ts"],
    rules: {
      "no-restricted-imports": [
        "error",
        {
          patterns: [
            { group: ["**/shield/pep", "**/shield/pep.js"], allowTypeImports: true, message: "Tools must not call the PEP." },
            { group: ["**/shield/tickets", "**/shield/tickets.js"], allowTypeImports: true, message: "Tools must not issue tickets." },
          ],
        },
      ],
    },
  },
  {
    // Agent code receives only the gateway handle (request / resume / refs). It may import the gateway's TYPES,
    // nothing that can approve, audit, evaluate policy, issue tickets, run tools or touch storage.
    files: ["src/agent/**/*.ts"],
    rules: {
      "no-restricted-imports": [
        "error",
        {
          patterns: [
            { group: ["**/tools", "**/tools/**", "**/tools/*.js"], message: "Agent code must not import tools; use the ToolGateway." },
            { group: ["**/gateway/gateway", "**/gateway/gateway.js"], allowTypeImports: true, message: "Agents may only import gateway types; the handle is injected." },
            { group: ["**/gateway/approvals", "**/gateway/approvals.js"], message: "Agents must never decide approvals." },
            { group: ["**/audit", "**/audit/**", "**/db", "**/db/**"], message: "Agents must not touch audit or database storage." },
            { group: ["**/shield/pep", "**/shield/pep.js", "**/shield/tickets", "**/shield/tickets.js"], message: "Agents must not evaluate policy or handle tickets." },
            { group: ["**/policy/loader", "**/policy/loader.js", "**/policy/shield-config", "**/policy/shield-config.js"], message: "Agents must not load or change policy." },
            { group: ["**/sandbox", "**/sandbox/**"], message: "Agents must not touch the sandbox." },
            { group: ["node:fs", "node:fs/promises", "fs", "fs/promises", "node:sqlite", "node:child_process", "child_process", "node:net", "node:http", "node:https"], message: "Agents must not perform I/O directly." },
          ],
        },
      ],
    },
  },
);
