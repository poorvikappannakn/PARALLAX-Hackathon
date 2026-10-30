import tseslint from "typescript-eslint";

export default tseslint.config(
  ...tseslint.configs.recommended,
  {
    // No-bypass guarantee: the agent may only reach tools through the ToolGateway.
    files: ["src/agent/**/*.ts"],
    rules: {
      "no-restricted-imports": [
        "error",
        {
          patterns: [
            {
              group: ["**/tools", "**/tools/**"],
              message: "Agent code must not import tools directly; use the ToolGateway.",
            },
          ],
        },
      ],
    },
  },
);
