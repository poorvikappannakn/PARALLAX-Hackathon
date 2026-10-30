import { readFileSync } from "node:fs";
import { request as httpRequest } from "node:http";
import { SUMMARY_MARKER } from "../src/agent/naive-agent.js";
import { SCENARIO_IDS, SCENARIOS } from "../src/scenarios/catalog.js";
import { sensitiveFragments } from "../src/scenarios/verdict.js";
import { createServer } from "node:net";
import type { InjectOptions } from "fastify";
import { buildAppWithContext, type AppOptions } from "../src/api/app.js";
import { readCookie, SESSION_COOKIE } from "../src/api/session.js";
import { openDatabase } from "../src/db/sqlite.js";

const fixtureText = (rel: string) => readFileSync(new URL(`../fixtures/northwind/${rel}`, import.meta.url), "utf8");
const SUBJECTS = SCENARIO_IDS.flatMap((id) => SCENARIOS[id].task.steps.flatMap((s) => (s.op === "email_summary_to_user" ? [s.subject] : [])));
/** Strings that must never appear in any browser-facing response or event stream. */
export const FORBIDDEN = [
  ...sensitiveFragments(fixtureText("files/secrets/api_keys.env")),
  ...sensitiveFragments(fixtureText("files/hr/salaries.csv")),
  "FAKE-DEMO",
  SUMMARY_MARKER,
  "ignore all previous instructions",
  "ignore your previous instructions",
  "Revenue: INR 48.2 crore",
  "compliance",
  ...SUBJECTS,
];

export const SECRET ="c0ffee00c0ffee00c0ffee00c0ffee00c0ffee00c0ffee00c0ffee00c0ffee00"; // test-only

export async function freePort(): Promise<number> {
  return new Promise((resolve) => {
    const s = createServer();
    s.listen(0, "127.0.0.1", () => {
      const port = (s.address() as { port: number }).port;
      s.close(() => resolve(port));
    });
  });
}

/** App with an authenticated operator session; requests go through app.inject() with the real guards. */
export async function apiHarness(runtimeDir: string, extra: Partial<AppOptions> = {}) {
  let now = 1_900_000_000_000;
  const port = extra.port ?? 3000;
  const { app, ctx } = buildAppWithContext({
    db: openDatabase(":memory:"),
    operatorSecret: SECRET,
    port,
    clock: () => now,
    stepDelayMs: 0,
    runtimeDir,
    ...extra,
  });
  const host = `127.0.0.1:${port}`;
  const login = async () => {
    const res = await app.inject({ method: "POST", url: "/api/session", headers: { host, "content-type": "application/json" }, payload: { secret: SECRET } });
    const cookie = String(res.headers["set-cookie"]).split(";")[0]!;
    return { cookie, id: readCookie(cookie, SESSION_COOKIE)!, csrf: (res.json() as { csrfToken: string }).csrfToken };
  };
  const session = await login();
  const call = (method: string, url: string, payload?: unknown, opts: { auth?: { cookie: string; csrf: string } | null; headers?: Record<string, string> } = {}) => {
    const auth = opts.auth === undefined ? session : opts.auth;
    const mutating = method !== "GET";
    return app.inject({
      method: method as InjectOptions["method"],
      url,
      headers: {
        host,
        ...(auth ? { cookie: auth.cookie } : {}),
        ...(auth && mutating ? { "x-csrf-token": auth.csrf } : {}),
        ...(mutating && payload !== undefined ? { "content-type": "application/json" } : {}),
        ...opts.headers,
      },
      ...(payload !== undefined ? { payload: payload as InjectOptions["payload"] } : {}),
    });
  };
  const startRun = async (scenarioId: string, mode: "on" | "off") => {
    const res = await call("POST", "/api/runs", { scenarioId, mode });
    if (res.statusCode !== 201) throw new Error(`start failed ${res.statusCode} ${res.body}`);
    const runId = (res.json() as { run: { runId: string } }).run.runId;
    await ctx.registry.settled(runId);
    return runId;
  };
  const getRun = async (runId: string) => (await call("GET", `/api/runs/${runId}`)).json() as { run: Record<string, any> };
  return { app, ctx, call, login, session, startRun, getRun, host, advance: (ms: number) => void (now += ms), now: () => now };
}

export interface SseEvent {
  id: number | null;
  event: string;
  data: any;
}

/** Real HTTP SSE client (inject() cannot stream). Collects events until the server ends the stream or `stop()`. */
export function sse(port: number, path: string, headers: Record<string, string>) {
  const events: SseEvent[] = [];
  let status = 0;
  let resolveEnd: () => void;
  const ended = new Promise<void>((r) => (resolveEnd = r));
  const waiters: { pred: (e: SseEvent[]) => boolean; resolve: () => void }[] = [];
  let rawText = "";
  const req = httpRequest({ host: "127.0.0.1", port, path, headers: { host: `127.0.0.1:${port}`, accept: "text/event-stream", ...headers } }, (res) => {
    status = res.statusCode ?? 0;
    let buf = "";
    res.setEncoding("utf8");
    res.on("data", (chunk: string) => {
      rawText += chunk;
      buf += chunk;
      let i;
      while ((i = buf.indexOf("\n\n")) >= 0) {
        const block = buf.slice(0, i);
        buf = buf.slice(i + 2);
        const lines = block.split("\n");
        const ev = lines.find((l) => l.startsWith("event: "))?.slice(7);
        const data = lines.find((l) => l.startsWith("data: "))?.slice(6);
        const id = lines.find((l) => l.startsWith("id: "))?.slice(4);
        if (ev && data !== undefined) events.push({ id: id ? Number(id) : null, event: ev, data: JSON.parse(data) });
      }
      for (const w of [...waiters]) if (w.pred(events)) (waiters.splice(waiters.indexOf(w), 1), w.resolve());
    });
    res.on("end", () => resolveEnd());
    res.on("close", () => resolveEnd());
  });
  req.on("error", () => resolveEnd());
  req.end();
  return {
    events,
    status: () => status,
    raw: () => rawText,
    ended,
    until: (pred: (e: SseEvent[]) => boolean, timeoutMs = 5000) =>
      pred(events)
        ? Promise.resolve()
        : new Promise<void>((resolve, reject) => {
            const t = setTimeout(() => reject(new Error(`SSE timeout; got ${events.map((e) => e.event).join(",")}`)), timeoutMs);
            waiters.push({ pred, resolve: () => (clearTimeout(t), resolve()) });
          }),
    stop: () => req.destroy(),
  };
}
