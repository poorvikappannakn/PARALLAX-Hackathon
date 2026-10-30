import { buildApp } from "./api/app.js";
import { generateOperatorSecret } from "./api/session.js";
import { openDatabase } from "./db/sqlite.js";

const HOST = "127.0.0.1"; // local only, by design (never 0.0.0.0)
const port = (name: string, fallback: number) => {
  const v = Number(process.env[name] ?? fallback);
  if (!Number.isInteger(v) || v < 1 || v > 65535) throw new Error(`${name} must be a TCP port`);
  return v;
};
// AGENTSHIELD_API_PORT / AGENTSHIELD_WEB_PORT are shared with web/vite.config.ts so the Host/Origin allowlists and the
// dev proxy always agree. (PORT is accepted for backwards compatibility.)
const API_PORT = port("AGENTSHIELD_API_PORT", port("PORT", 3000));
const WEB_PORT = port("AGENTSHIELD_WEB_PORT", 5173);
const DB_FILE = process.env.DB_FILE ?? "../data/agentshield.db";

const db = openDatabase(DB_FILE);
// A fresh operator secret per server start. It is printed once here and never logged anywhere else.
const operatorSecret = generateOperatorSecret();
const app = buildApp({
  db,
  operatorSecret,
  port: API_PORT,
  devOrigins: [`http://127.0.0.1:${WEB_PORT}`, `http://localhost:${WEB_PORT}`],
  logger: true,
});

await app.listen({ host: HOST, port: API_PORT });
console.log(
  [
    "",
    `AgentShield API listening on http://127.0.0.1:${API_PORT}  (dashboard: http://127.0.0.1:${WEB_PORT})`,
    "Operator secret (shown once; required to log in as operator:alice):",
    `  ${operatorSecret}`,
    "",
  ].join("\n"),
);
