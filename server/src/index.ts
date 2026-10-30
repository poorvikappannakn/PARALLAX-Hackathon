import Fastify from "fastify";
import { openDatabase } from "./db/sqlite.js";

const HOST = "127.0.0.1"; // local only, by design
const PORT = Number(process.env.PORT ?? 3000);
const DB_FILE = process.env.DB_FILE ?? "../data/agentshield.db";

const db = openDatabase(DB_FILE);
const app = Fastify({ logger: true });

app.get("/api/health", async () => {
  const row = db.prepare("SELECT sqlite_version() AS v").get() as { v: string };
  return { ok: true, node: process.version, sqlite: row.v };
});

await app.listen({ host: HOST, port: PORT });
