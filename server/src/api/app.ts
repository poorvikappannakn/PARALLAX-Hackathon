import type { DatabaseSync } from "node:sqlite";
import Fastify, { type FastifyError, type FastifyInstance, type FastifyRequest } from "fastify";
import { createStores, type Stores } from "../audit/store.js";
import { OPERATORS } from "../policy/profiles.js";
import { sendError } from "./errors.js";
import { registerRoutes, SSE_HEARTBEAT_MS } from "./routes.js";
import { createRunRegistry, type RegistryOptions, type RunRegistry } from "./runs.js";
import { createLoginLimiter, createSessionManager, readCookie, SESSION_COOKIE, type OperatorSession, type SessionManager } from "./session.js";

// Fastify application factory (M5.2). All request-level security lives here:
//   Host allowlist -> Origin allowlist -> JSON-only bodies -> session -> CSRF (state-changing) -> route.
// Proxy headers (X-Forwarded-*) are never trusted: trustProxy is false and nothing reads them.

export const API_BODY_LIMIT = 1024;
const STATE_CHANGING = new Set(["POST", "PUT", "PATCH", "DELETE"]);
/** Routes reachable without a session. Everything else (including unknown paths) requires one. */
const PUBLIC_ROUTES = new Set(["GET /api/health", "POST /api/session"]);
/** State-changing routes that cannot carry a CSRF token yet (no session exists before login). */
const CSRF_EXEMPT = new Set(["POST /api/session"]);
export const DEV_WEB_PORT = 5173; // Vite dev server (proxies /api to this server)

export interface AppOptions {
  db: DatabaseSync;
  /** Operator secret. The server entry point generates it; tests inject one. */
  operatorSecret: string;
  /** Port this server listens on (used for the Host allowlist and own Origin). */
  port: number;
  operatorId?: string;
  /** Additional allowed browser origins. Defaults to the Vite dev server on 127.0.0.1/localhost:5173. */
  devOrigins?: readonly string[];
  /** Set only when served over HTTPS. */
  secureCookies?: boolean;
  clock?: () => number;
  logger?: boolean | { stream: { write(msg: string): void } };
  /** Per-run sandbox location (defaults to server/runtime/runs). */
  runtimeDir?: string;
  /** Pause between gateway calls of a live run so the dashboard can follow it (default 700 ms; tests use 0). */
  stepDelayMs?: number;
  /** SSE heartbeat interval (default 15 s). */
  sseHeartbeatMs?: number;
  /** Registry overrides (capacity, retention, fault injection) for tests. */
  registry?: Partial<Omit<RegistryOptions, "stores" | "clock" | "runtimeDir" | "stepDelayMs">>;
}

export interface AppContext {
  stores: Stores;
  sessions: SessionManager;
  loginLimiter: ReturnType<typeof createLoginLimiter>;
  registry: RunRegistry;
  clock: () => number;
  secureCookies: boolean;
  db: DatabaseSync;
  runtimeDir?: string;
  /** Serialises POST /api/suite. */
  suiteRunning: boolean;
  sseHeartbeatMs: number;
}

declare module "fastify" {
  interface FastifyRequest {
    operatorSession: OperatorSession | null;
  }
}

const routeKey = (req: FastifyRequest) => `${req.method} ${req.routeOptions.url ?? req.url.split("?")[0]}`;

export function buildApp(opts: AppOptions): FastifyInstance {
  return buildAppWithContext(opts).app;
}

/** As buildApp(), also returning the internal context (tests use the registry to await runs). */
export function buildAppWithContext(opts: AppOptions): { app: FastifyInstance; ctx: AppContext } {
  const clock = opts.clock ?? Date.now;
  const operatorId = opts.operatorId ?? "operator:alice";
  if (!Object.prototype.hasOwnProperty.call(OPERATORS, operatorId)) throw new Error("Configured operator is not registered");

  const allowedHosts = new Set([`127.0.0.1:${opts.port}`, `localhost:${opts.port}`]);
  const allowedOrigins = new Set([
    `http://127.0.0.1:${opts.port}`,
    `http://localhost:${opts.port}`,
    ...(opts.devOrigins ?? [`http://127.0.0.1:${DEV_WEB_PORT}`, `http://localhost:${DEV_WEB_PORT}`]),
  ]);

  const stores = createStores(opts.db);
  const ctx: AppContext = {
    stores,
    sessions: createSessionManager({ secret: opts.operatorSecret, operatorId, clock }),
    loginLimiter: createLoginLimiter(clock),
    registry: createRunRegistry({ stores, clock, stepDelayMs: opts.stepDelayMs ?? 700, ...(opts.runtimeDir ? { runtimeDir: opts.runtimeDir } : {}), ...opts.registry }),
    clock,
    secureCookies: opts.secureCookies === true,
    db: opts.db,
    ...(opts.runtimeDir ? { runtimeDir: opts.runtimeDir } : {}),
    suiteRunning: false,
    sseHeartbeatMs: opts.sseHeartbeatMs ?? SSE_HEARTBEAT_MS,
  };

  const app = Fastify({
    trustProxy: false,
    bodyLimit: API_BODY_LIMIT,
    // Request logging is reduced to method + path; headers (cookies, CSRF), bodies and query strings are never logged.
    logger:
      opts.logger === undefined || opts.logger === false
        ? false
        : {
            level: "info",
            ...(typeof opts.logger === "object" ? { stream: opts.logger.stream } : {}),
            serializers: {
              // The matched route pattern, never the raw path (which is caller-controlled text).
              req: (req: { method?: string; routeOptions?: { url?: string } }) => ({ method: req.method, route: req.routeOptions?.url ?? "(unmatched)" }),
              res: (res: { statusCode?: number }) => ({ statusCode: res.statusCode }),
            },
          },
  });

  // JSON is the only accepted body type (Fastify answers 415 for anything else). The built-in JSON parser rejects
  // __proto__/constructor poisoning.
  app.removeContentTypeParser("text/plain");
  app.decorateRequest("operatorSession", null);

  app.addHook("onRequest", async (req, reply) => {
    // 1. Host: only this server's loopback names and port. Forwarded host headers are ignored.
    const host = req.headers.host;
    if (typeof host !== "string" || !allowedHosts.has(host.toLowerCase())) return sendError(reply, 403, "FORBIDDEN_HOST", "Host not allowed");

    // 2. Origin (when sent): explicit allowlist. Also refuse requests the browser labels cross-site.
    const origin = req.headers.origin;
    if (origin !== undefined && (typeof origin !== "string" || !allowedOrigins.has(origin))) {
      return sendError(reply, 403, "FORBIDDEN_ORIGIN", "Origin not allowed");
    }
    if (req.headers["sec-fetch-site"] === "cross-site") return sendError(reply, 403, "FORBIDDEN_ORIGIN", "Cross-site request refused");

    const key = routeKey(req);
    const mutating = STATE_CHANGING.has(req.method);

    // 3. State-changing requests carry JSON or no body at all (POST always needs a JSON body).
    if (mutating) {
      const type = String(req.headers["content-type"] ?? "").split(";")[0]!.trim().toLowerCase();
      const hasBody = req.headers["content-length"] !== undefined && req.headers["content-length"] !== "0";
      if ((req.method === "POST" || hasBody || req.headers["transfer-encoding"] !== undefined) && type !== "application/json") {
        return sendError(reply, 415, "UNSUPPORTED_MEDIA_TYPE", "Request body must be application/json");
      }
    }

    // 4. Session (everything except the public routes, including unknown paths).
    const session = ctx.sessions.get(readCookie(req.headers.cookie, SESSION_COOKIE));
    req.operatorSession = session;
    if (!PUBLIC_ROUTES.has(key) && !session) return sendError(reply, 401, "UNAUTHENTICATED", "Authentication required");

    // 5. CSRF for state-changing requests with a session.
    if (mutating && !CSRF_EXEMPT.has(key) && (!session || !ctx.sessions.checkCsrf(session, req.headers["x-csrf-token"]))) {
      return sendError(reply, 403, "CSRF_FAILED", "Missing or invalid CSRF token");
    }
  });

  app.addHook("onSend", async (_req, reply, payload) => {
    reply.header("Cache-Control", "no-store");
    reply.header("X-Content-Type-Options", "nosniff");
    reply.header("Referrer-Policy", "no-referrer");
    reply.header("X-Frame-Options", "DENY");
    reply.header("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'");
    return payload;
  });

  // Safe errors: fixed messages per class; never the error message, stack, body or any user-controlled string.
  app.setErrorHandler((err: FastifyError, _req, reply) => {
    const status = err.statusCode ?? 500;
    if (status === 413) return sendError(reply, 413, "PAYLOAD_TOO_LARGE", "Request body too large");
    if (status === 415) return sendError(reply, 415, "UNSUPPORTED_MEDIA_TYPE", "Request body must be application/json");
    if (status >= 400 && status < 500) return sendError(reply, 400, "BAD_REQUEST", "Malformed request");
    reply.log.error({ code: err.code ?? "INTERNAL" }, "request failed"); // code only, no message/stack content
    return sendError(reply, 500, "INTERNAL", "Internal server error");
  });
  app.setNotFoundHandler((_req, reply) => sendError(reply, 404, "NOT_FOUND", "Not found"));

  registerRoutes(app, ctx);
  app.addHook("onClose", async () => ctx.registry.close());
  return { app, ctx };
}
