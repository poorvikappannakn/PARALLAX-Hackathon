import type { DatabaseSync } from "node:sqlite";
import { createStores, type AuditEventInput, type Stores } from "../src/audit/store.js";
import { openDatabase } from "../src/db/sqlite.js";
import { startRun, type RunSpec } from "../src/gateway/gateway.js";
import { loadShieldConfig } from "../src/policy/shield-config.js";

export const ON = loadShieldConfig("on");
export const OFF = loadShieldConfig("off");

export function memoryStores(): { db: DatabaseSync; stores: Stores } {
  const db = openDatabase(":memory:");
  return { db, stores: createStores(db) };
}

/** Wraps stores so that audit appends matching `failOn` throw (simulated disk/DB failure). */
export function failingStores(base: Stores, failOn: (e: AuditEventInput) => boolean): Stores {
  return {
    ...base,
    audit: {
      ...base.audit,
      append(e, now) {
        if (failOn(e)) throw new Error("simulated audit failure");
        return base.audit.append(e, now);
      },
    },
  };
}

export const S_ALICE: RunSpec = {
  scenarioId: "test",
  userId: "user:alice",
  agentId: "agent:research-assistant",
  task: { text: "Summarise the Q3 report and email it to me", params: { report: "reports/q3-report.txt" } },
};

export function start(
  mode: "on" | "off",
  runtimeDir: string,
  opts: { stores?: Stores; clock?: () => number; spec?: Partial<RunSpec> } = {},
) {
  const stores = opts.stores ?? memoryStores().stores;
  const started = startRun(
    { config: mode === "on" ? ON : OFF, stores, sandbox: { runtimeDir }, ...(opts.clock ? { clock: opts.clock } : {}) },
    { ...S_ALICE, ...opts.spec },
  );
  return { ...started, stores, kinds: () => stores.audit.listEvents(started.run.id).map((e) => e.kind) };
}
