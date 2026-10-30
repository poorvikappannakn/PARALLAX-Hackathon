import { fileURLToPath } from "node:url";
import { ESLint } from "eslint";
import { describe, expect, it } from "vitest";

// Verifies the security-relevant import boundaries in eslint.config.js (review findings F2 and F3) by linting
// probe snippets placed (virtually) in each source area. The probes are never written to disk.

const serverDir = fileURLToPath(new URL("..", import.meta.url));
const eslint = new ESLint({ cwd: serverDir });

async function restricted(filePath: string, code: string): Promise<boolean> {
  const [result] = await eslint.lintText(code, { filePath });
  return (result?.messages ?? []).some((m) => m.ruleId === "no-restricted-imports");
}

describe("F2: agent code receives only the gateway interface", () => {
  it.each([
    ['import { decideApproval } from "../gateway/approvals.js"; void decideApproval;', "approvals"],
    ['import { startRun } from "../gateway/gateway.js"; void startRun;', "gateway runtime"],
    ['import { createStores } from "../audit/store.js"; void createStores;', "audit store"],
    ['import { openDatabase } from "../db/sqlite.js"; void openDatabase;', "database"],
    ['import { evaluate } from "../shield/pep.js"; void evaluate;', "PEP"],
    ['import { createTicketAuthority } from "../shield/tickets.js"; void createTicketAuthority;', "tickets"],
    ['import { loadPolicy } from "../policy/loader.js"; void loadPolicy;', "policy loader"],
    ['import { loadShieldConfig } from "../policy/shield-config.js"; void loadShieldConfig;', "shield config"],
    ['import { createToolExecutor } from "../tools/index.js"; void createToolExecutor;', "tool executor"],
    ['import { TOOL_IMPLS } from "../tools/impl.js"; void TOOL_IMPLS;', "tool impls"],
    ['import { createRunSandbox } from "../sandbox/sandbox.js"; void createRunSandbox;', "sandbox"],
    ['import { readFileSync } from "node:fs"; void readFileSync;', "filesystem"],
    ['import { DatabaseSync } from "node:sqlite"; void DatabaseSync;', "sqlite"],
  ])("blocks agent import: %s (%s)", async (code) => {
    expect(await restricted("src/agent/probe.ts", code)).toBe(true);
  });

  it("allows type-only import of the gateway interface", async () => {
    const code = 'import type { ToolGateway } from "../gateway/gateway.js"; export type G = Pick<ToolGateway, "request" | "resume" | "refs">;';
    expect(await restricted("src/agent/probe.ts", code)).toBe(false);
  });
});

describe("F3: only the gateway can assemble PEP + ticket issuer + executor", () => {
  const bypass = [
    'import { createTicketAuthority } from "../shield/tickets.js"; void createTicketAuthority;',
    'import { createToolExecutor } from "../tools/index.js"; void createToolExecutor;',
    'import { createToolExecutor } from "../tools"; void createToolExecutor;',
    'import { TOOL_IMPLS } from "../tools/impl.js"; void TOOL_IMPLS;',
  ];

  it.each(["src/api/probe.ts", "src/scenarios/probe.ts", "src/probe.ts", "src/shield/probe.ts"])("blocks bypass imports in %s", async (file) => {
    for (const code of bypass) expect(await restricted(file, code)).toBe(true);
  });

  it("the gateway may import tickets and the executor, but not tool implementations", async () => {
    expect(await restricted("src/gateway/probe.ts", 'import { createTicketAuthority } from "../shield/tickets.js"; void createTicketAuthority;')).toBe(false);
    expect(await restricted("src/gateway/probe.ts", 'import { createToolExecutor } from "../tools/index.js"; void createToolExecutor;')).toBe(false);
    expect(await restricted("src/gateway/probe.ts", 'import { TOOL_IMPLS } from "../tools/impl.js"; void TOOL_IMPLS;')).toBe(true);
  });

  it("tools still cannot call the PEP or mint tickets", async () => {
    expect(await restricted("src/tools/probe.ts", 'import { evaluate } from "../shield/pep.js"; void evaluate;')).toBe(true);
    expect(await restricted("src/tools/probe.ts", 'import { createTicketAuthority } from "../shield/tickets.js"; void createTicketAuthority;')).toBe(true);
  });

  it("the real source tree passes all boundaries", async () => {
    const results = await eslint.lintFiles(["src"]);
    const violations = results.flatMap((r) => r.messages.filter((m) => m.ruleId === "no-restricted-imports").map((m) => `${r.filePath}: ${m.message}`));
    expect(violations).toEqual([]);
  });
});
