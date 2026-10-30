import tseslint from "typescript-eslint";

export default tseslint.config(
  ...tseslint.configs.recommended,
  {
    // Tool implementations are reachable only through the ticket-checking executor (src/tools/index.ts).
    files: ["src/**/*.ts"],
    ignores: ["src/tools/**"],
    rules: {
      "no-restricted-imports": [
        "error",
        { patterns: [{ group: ["**/tools/impl", "**/tools/impl.js"], message: "Use the tool executor (tools/index.ts)." }] },
      ],
    },
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
    // No-bypass guarantee: the agent may only reach tools through the ToolGateway.
    files: ["src/agent/**/*.ts"],
    rules: {
      "no-restricted-imports": [
        "error",
        {
          patterns: [
            {
              group: ["**/tools", "**/tools/**", "**/tools/*.js"],
              message: "Agent code must not import tools directly; use the ToolGateway.",
            },
            {
              group: ["**/shield/tickets", "**/shield/tickets.js", "**/sandbox/**"],
              message: "Agent code must not touch tickets or the sandbox.",
            },
          ],
        },
      ],
    },
  },
);
