import type { FastifyInstance, FastifyReply } from "fastify";
import { z } from "zod";
import { OPERATORS } from "../policy/profiles.js";
import { SCENARIO_IDS } from "../scenarios/catalog.js";
import type { AppContext } from "./app.js";
import { sendError } from "./errors.js";
import type { RunEvent } from "./runs.js";
import { clearedSessionCookie, sessionCookie, type OperatorSession } from "./session.js";
import { runSuite } from "./suite.js";
import { scenarioListView } from "./views.js";

// API routes. Every response body is an explicit-allowlist projection (views.ts) or a small fixed object.

const RUN_ID = /^run-[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const APPROVAL_ID = /^appr-[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
export const SSE_HEARTBEAT_MS = 15_000;

// Strict: any other field (e.g. a client-chosen "operatorId", task steps, raw requests) is rejected.
const loginBody = z.object({ secret: z.string().min(1).max(512) }).strict();
const startRunBody = z.object({ scenarioId: z.enum(SCENARIO_IDS as unknown as [string, ...string[]]), mode: z.enum(["on", "off"]) }).strict();
const decisionBody = z.object({ verdict: z.enum(["approve", "reject"]) }).strict();
const approvalsQuery = z.object({ status: z.literal("pending").optional() }).strict();
const emptyBody = z.object({}).strict();
const runParams = z.object({ runId: z.string().regex(RUN_ID) }).strict();
const approvalParams = z.object({ approvalId: z.string().regex(APPROVAL_ID) }).strict();

const badRequest = (reply: FastifyReply) => sendError(reply, 400, "BAD_REQUEST", "Malformed request");
const notFound = (reply: FastifyReply) => sendError(reply, 404, "NOT_FOUND", "Not found");

function sessionView(s: OperatorSession) {
  const op = OPERATORS[s.operatorId]!;
  return { operator: { id: op.id, displayName: op.displayName }, csrfToken: s.csrfToken, expiresAt: s.expiresAt };
}

export function registerRoutes(app: FastifyInstance, ctx: AppContext) {
  app.get("/api/health", async () => {
    const row = ctx.db.prepare("SELECT sqlite_version() AS v").get() as { v: string };
    return { ok: true, sqlite: row.v };
  });

  // ---- session (M5.2) -----------------------------------------------------------------------------------------------
  app.post("/api/session", async (req, reply) => {
    // Keyed by the TCP peer address only (trustProxy=false; X-Forwarded-For is ignored). On a loopback-only server this is
    // effectively a global limit, which is the intent.
    if (!ctx.loginLimiter.attempt(req.socket.remoteAddress ?? "unknown")) {
      return sendError(reply, 429, "RATE_LIMITED", "Too many login attempts; try again later");
    }
    const body = loginBody.safeParse(req.body);
    if (!body.success) return badRequest(reply);
    if (!ctx.sessions.verifySecret(body.data.secret)) return sendError(reply, 401, "INVALID_CREDENTIALS", "Invalid credentials");

    // New session id on every login (no fixation); an existing session presented with the request is ended.
    if (req.operatorSession) ctx.sessions.destroy(req.operatorSession.id);
    const s = ctx.sessions.create();
    reply.header("Set-Cookie", sessionCookie(s.id, s.expiresAt - ctx.clock(), ctx.secureCookies));
    return reply.code(201).send(sessionView(s));
  });

  app.get("/api/session", async (req, reply) => {
    const s = req.operatorSession;
    if (!s) return sendError(reply, 401, "UNAUTHENTICATED", "Authentication required");
    return sessionView(s);
  });

  app.delete("/api/session", async (req, reply) => {
    const s = req.operatorSession;
    if (s) ctx.sessions.destroy(s.id);
    reply.header("Set-Cookie", clearedSessionCookie(ctx.secureCookies));
    return reply.code(204).send();
  });

  // ---- scenarios and runs (M5.3) ------------------------------------------------------------------------------------
  app.get("/api/scenarios", async () => ({ scenarios: scenarioListView() }));

  app.get("/api/runs", async () => ({ runs: ctx.registry.list() }));

  app.post("/api/runs", async (req, reply) => {
    const body = startRunBody.safeParse(req.body);
    if (!body.success) return badRequest(reply);
    const started = ctx.registry.start(body.data.scenarioId as (typeof SCENARIO_IDS)[number], body.data.mode);
    if (!started.ok) return sendError(reply, 429, "CAPACITY", "Too many active runs; wait for one to finish");
    return reply.code(201).send({ run: started.run });
  });

  app.get("/api/runs/:runId", async (req, reply) => {
    const p = runParams.safeParse(req.params);
    if (!p.success) return notFound(reply);
    const v = ctx.registry.view(p.data.runId);
    return v ? { run: v } : notFound(reply);
  });

  // ---- approvals (M5.4) ---------------------------------------------------------------------------------------------
  app.get("/api/approvals", async (req, reply) => {
    if (!approvalsQuery.safeParse(req.query).success) return badRequest(reply);
    return { approvals: ctx.registry.pendingApprovals() };
  });

  app.post("/api/approvals/:approvalId/decision", async (req, reply) => {
    const p = approvalParams.safeParse(req.params);
    if (!p.success) return notFound(reply);
    const body = decisionBody.safeParse(req.body);
    if (!body.success) return badRequest(reply);
    // The approver is the authenticated session's operator — never a value from the request.
    const res = ctx.registry.decide(p.data.approvalId, req.operatorSession!.operatorId, body.data.verdict);
    if (res.ok) return { run: res.run };
    switch (res.code) {
      case "NOT_FOUND":
        return notFound(reply);
      case "CONFLICT":
        return sendError(reply, 409, "CONFLICT", "Approval was already decided");
      case "EXPIRED":
        return sendError(reply, 409, "APPROVAL_EXPIRED", "Approval has expired; the action will not run");
      case "FORBIDDEN":
        return sendError(reply, 403, "FORBIDDEN", "Not permitted to decide this approval");
      default:
        return sendError(reply, 500, "AUDIT_FAILURE", "Decision could not be recorded; approval left pending");
    }
  });

  // ---- live events (M5.5) -------------------------------------------------------------------------------------------
  app.get("/api/runs/:runId/events", async (req, reply) => {
    const p = runParams.safeParse(req.params);
    if (!p.success) return notFound(reply);
    const raw = req.headers["last-event-id"];
    const lastEventId = typeof raw === "string" && /^\d{1,9}$/.test(raw) ? Number(raw) : null;

    const out = reply.raw;
    let heartbeat: ReturnType<typeof setInterval> | null = null;
    let unsubscribe = () => {};
    let open = true;
    const close = () => {
      if (!open) return;
      open = false;
      if (heartbeat) clearInterval(heartbeat);
      unsubscribe();
      out.end();
    };
    const write = (e: RunEvent) => {
      if (!open) return;
      out.write(`id: ${e.id}\nevent: ${e.event}\ndata: ${JSON.stringify(e.data)}\n\n`);
      if (e.event === "done" || e.event === "failed") close();
    };

    const sub = ctx.registry.subscribe(p.data.runId, write, lastEventId);
    if (!sub.ok) {
      return sub.code === "NOT_FOUND" ? notFound(reply) : sendError(reply, 429, "TOO_MANY_SUBSCRIBERS", "Too many open event streams");
    }
    unsubscribe = sub.unsubscribe;

    reply.hijack(); // the onSend hook does not run for hijacked replies: set the security headers here
    out.writeHead(200, {
      "Content-Type": "text/event-stream; charset=utf-8",
      "Cache-Control": "no-store",
      Connection: "keep-alive",
      "X-Accel-Buffering": "no",
      "X-Content-Type-Options": "nosniff",
      "Referrer-Policy": "no-referrer",
      "X-Frame-Options": "DENY",
      "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
    });
    out.write("retry: 3000\n\n");
    out.on("close", close); // client went away (the request's own "close" fires once a GET is read, too early)
    for (const e of sub.replay) write(e);
    if (sub.finished) return close();
    heartbeat = setInterval(() => open && out.write(": ping\n\n"), ctx.sseHeartbeatMs);
    heartbeat.unref();
  });

  // ---- suite (M5.6) -------------------------------------------------------------------------------------------------
  app.post("/api/suite", async (req, reply) => {
    if (!emptyBody.safeParse(req.body).success) return badRequest(reply);
    if (ctx.suiteRunning) return sendError(reply, 409, "SUITE_RUNNING", "The suite is already running");
    ctx.suiteRunning = true;
    try {
      return runSuite(ctx.stores, ctx.clock, ctx.runtimeDir);
    } catch {
      return sendError(reply, 500, "SUITE_FAILED", "The suite could not be completed");
    } finally {
      ctx.suiteRunning = false;
    }
  });
}
