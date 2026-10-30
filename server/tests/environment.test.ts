import { describe, expect, it } from "vitest";
import { openDatabase } from "../src/db/sqlite.js";

// Foundation checks: node:sqlite supports what the audit/approval design relies on.
describe("environment: node:sqlite", () => {
  it("runs on Node 24+", () => {
    expect(Number(process.versions.node.split(".")[0])).toBeGreaterThanOrEqual(24);
  });

  it("supports transactions with rollback", () => {
    const db = openDatabase(":memory:");
    db.exec("CREATE TABLE t (x INTEGER)");
    db.exec("BEGIN IMMEDIATE");
    db.prepare("INSERT INTO t VALUES (?)").run(1);
    db.exec("ROLLBACK");
    expect(db.prepare("SELECT COUNT(*) AS c FROM t").get()).toEqual({ c: 0 });
  });

  it("reports changes so an approval can be consumed exactly once", () => {
    const db = openDatabase(":memory:");
    db.exec("CREATE TABLE approvals (id TEXT PRIMARY KEY, used INTEGER NOT NULL DEFAULT 0)");
    db.prepare("INSERT INTO approvals (id) VALUES (?)").run("a1");
    const consume = db.prepare("UPDATE approvals SET used = 1 WHERE id = ? AND used = 0");
    expect(Number(consume.run("a1").changes)).toBe(1);
    expect(Number(consume.run("a1").changes)).toBe(0);
  });
});
