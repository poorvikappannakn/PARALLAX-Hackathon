import type { InjectOptions } from "fastify";
import { describe, expect, it } from "vitest";
import { buildApp, type AppOptions } from "../src/api/app.js";
import { clearedSessionCookie, createSessionManager, readCookie, safeEqual, SESSION_COOKIE } from "../src/api/session.js";
import { openDatabase } from "../src/db/sqlite.js";

const SECRET = "a3f1c2d4e5b60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f9a"; // test-only, 64 hex chars
const PORT = 3000;
const HOST = `127.0.0.1:${PORT}`;
const VITE_ORIGIN = "http://127.0.0.1:5173";

function setup(extra: Partial<AppOptions> = {}) {
  let now = 1_900_000_000_000;
  const logs: string[] = [];
  const app = buildApp({
    db: openDatabase(":memory:"),
    operatorSecret: SECRET,
    port: PORT,
    clock: () => now,
    logger: { stream: { write: (m) => void logs.push(m) } },
    ...extra,
  });
  const req = (o: { method: string; url: string; headers?: Record<string, string>; payload?: unknown; body?: string }) =>
    app.inject({
      method: o.method as InjectOptions["method"],
      url: o.url,
      headers: { host: HOST, ...o.headers },
      ...(o.body !== undefined ? { body: o.body } : o.payload !== undefined ? { payload: o.payload as InjectOptions["payload"] } : {}),
    });
  const login = async (secret = SECRET) => {
    const res = await req({ method: "POST", url: "/api/session", headers: { "content-type": "application/json" }, payload: { secret } });
    const cookie = String(res.headers["set-cookie"] ?? "");
    return { res, cookie, id: readCookie(cookie.split(";")[0], SESSION_COOKIE) ?? "", csrf: res.statusCode === 201 ? (res.json() as { csrfToken: string }).csrfToken : "" };
  };
  return { app, req, login, logs, advance: (ms: number) => void (now += ms) };
}

const errorOf = (res: { json(): unknown }) => (res.json() as { error: { code: string; message: string } }).error;

describe("login", () => {
  it("correct secret: 201, operator from server config, CSRF token, HttpOnly SameSite=Strict Path=/ cookie (no Secure on http)", async () => {
    const { login } = setup();
    const { res, cookie, id } = await login();
    expect(res.statusCode).toBe(201);
    expect(res.json()).toEqual({ operator: { id: "operator:alice", displayName: expect.any(String) }, csrfToken: expect.stringMatching(/^[A-Za-z0-9_-]{43}$/), expiresAt: 1_900_000_000_000 + 12 * 3600_000 });
    expect(id).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(cookie).toBe(`${SESSION_COOKIE}=${id}; HttpOnly; SameSite=Strict; Path=/; Max-Age=43200`);
    expect(JSON.stringify(res.json())).not.toContain(id); // the session id is only in the cookie
  });

  it("Secure is added when configured for HTTPS", async () => {
    const { cookie } = await setup({ secureCookies: true }).login();
    expect(cookie).toMatch(/; Secure$/);
  });

  it.each([
    ["wrong secret (same length)", SECRET.replace(/.$/, "0")],
    ["shorter secret", "x"],
    ["much longer secret", SECRET.repeat(7)],
    ["empty-looking secret", " "],
  ])("%s: 401, no cookie, no crash", async (_n, secret) => {
    const { res } = await setup().login(secret);
    expect(res.statusCode).toBe(401);
    expect(errorOf(res)).toEqual({ code: "INVALID_CREDENTIALS", message: "Invalid credentials" });
    expect(res.headers["set-cookie"]).toBeUndefined();
  });

  it.each([
    ["client-chosen operator identity", { secret: SECRET, operatorId: "operator:mallory" }],
    ["unknown field", { secret: SECRET, remember: true }],
    ["missing secret", {}],
    ["non-string secret", { secret: 12345 }],
    ["array body", [SECRET]],
  ])("%s: 400, no session", async (_n, payload) => {
    const { req } = setup();
    const res = await req({ method: "POST", url: "/api/session", headers: { "content-type": "application/json" }, payload });
    expect(res.statusCode).toBe(400);
    expect(errorOf(res).code).toBe("BAD_REQUEST");
    expect(res.headers["set-cookie"]).toBeUndefined();
  });

  it("each login creates a new session id; a presented old session is ended (no fixation)", async () => {
    const { login, req } = setup();
    const first = await login();
    const res = await req({ method: "POST", url: "/api/session", headers: { "content-type": "application/json", cookie: `${SESSION_COOKIE}=${first.id}` }, payload: { secret: SECRET } });
    const second = readCookie(String(res.headers["set-cookie"]).split(";")[0], SESSION_COOKIE);
    expect(second).not.toBe(first.id);
    expect((await req({ method: "GET", url: "/api/session", headers: { cookie: `${SESSION_COOKIE}=${first.id}` } })).statusCode).toBe(401);
  });
});

describe("session inspection, expiry and logout", () => {
  it("GET /api/session returns operator + CSRF token with a valid cookie; 401 without", async () => {
    const { login, req } = setup();
    const s = await login();
    const ok = await req({ method: "GET", url: "/api/session", headers: { cookie: `${SESSION_COOKIE}=${s.id}` } });
    expect(ok.statusCode).toBe(200);
    expect(ok.json()).toMatchObject({ operator: { id: "operator:alice" }, csrfToken: s.csrf });
    const none = await req({ method: "GET", url: "/api/session" });
    expect(none.statusCode).toBe(401);
    expect(errorOf(none)).toEqual({ code: "UNAUTHENTICATED", message: "Authentication required" });
  });

  it.each([
    ["garbage cookie", `${SESSION_COOKIE}=not-a-session`],
    ["well-formed unknown id", `${SESSION_COOKIE}=${"A".repeat(43)}`],
    ["duplicate cookie (ambiguous)", `${SESSION_COOKIE}=${"A".repeat(43)}; ${SESSION_COOKIE}=${"B".repeat(43)}`],
  ])("%s: 401", async (_n, cookie) => {
    expect((await setup().req({ method: "GET", url: "/api/session", headers: { cookie } })).statusCode).toBe(401);
  });

  it("an expired session is rejected (injected clock, 12 h)", async () => {
    const { login, req, advance } = setup();
    const s = await login();
    advance(12 * 3600_000 - 1);
    expect((await req({ method: "GET", url: "/api/session", headers: { cookie: `${SESSION_COOKIE}=${s.id}` } })).statusCode).toBe(200);
    advance(1);
    expect((await req({ method: "GET", url: "/api/session", headers: { cookie: `${SESSION_COOKIE}=${s.id}` } })).statusCode).toBe(401);
  });

  it("logout invalidates the session immediately and clears the cookie", async () => {
    const { login, req } = setup();
    const s = await login();
    const out = await req({ method: "DELETE", url: "/api/session", headers: { cookie: `${SESSION_COOKIE}=${s.id}`, "x-csrf-token": s.csrf } });
    expect(out.statusCode).toBe(204);
    expect(out.headers["set-cookie"]).toBe(clearedSessionCookie(false));
    expect((await req({ method: "GET", url: "/api/session", headers: { cookie: `${SESSION_COOKIE}=${s.id}` } })).statusCode).toBe(401);
  });

  it("unknown paths require authentication first, then answer a safe 404", async () => {
    const { login, req } = setup();
    expect((await req({ method: "GET", url: "/api/runs" })).statusCode).toBe(401);
    const s = await login();
    const res = await req({ method: "GET", url: "/api/does-not-exist?x=<script>", headers: { cookie: `${SESSION_COOKIE}=${s.id}` } });
    expect(res.statusCode).toBe(404);
    expect(res.json()).toEqual({ error: { code: "NOT_FOUND", message: "Not found" } });
  });

  it("health is public", async () => {
    const res = await setup().req({ method: "GET", url: "/api/health" });
    expect(res.statusCode).toBe(200);
    expect(res.json()).toMatchObject({ ok: true });
  });
});

describe("CSRF", () => {
  it.each([
    ["missing token", undefined],
    ["wrong token", "A".repeat(43)],
    ["empty token", ""],
    ["oversized token", "A".repeat(5000)],
  ])("state-changing request with %s: 403, session survives", async (_n, token) => {
    const { login, req } = setup();
    const s = await login();
    const res = await req({ method: "DELETE", url: "/api/session", headers: { cookie: `${SESSION_COOKIE}=${s.id}`, ...(token !== undefined ? { "x-csrf-token": token } : {}) } });
    expect(res.statusCode).toBe(403);
    expect(errorOf(res)).toEqual({ code: "CSRF_FAILED", message: "Missing or invalid CSRF token" });
    expect((await req({ method: "GET", url: "/api/session", headers: { cookie: `${SESSION_COOKIE}=${s.id}` } })).statusCode).toBe(200);
  });

  it("another session's token is not accepted", async () => {
    const { login, req } = setup();
    const a = await login();
    const b = await login();
    const res = await req({ method: "DELETE", url: "/api/session", headers: { cookie: `${SESSION_COOKIE}=${a.id}`, "x-csrf-token": b.csrf } });
    expect(res.statusCode).toBe(403);
  });

  it("an expired session with a once-valid token: 401 (expiry wins), not accepted", async () => {
    const { login, req, advance } = setup();
    const s = await login();
    advance(12 * 3600_000);
    const res = await req({ method: "DELETE", url: "/api/session", headers: { cookie: `${SESSION_COOKIE}=${s.id}`, "x-csrf-token": s.csrf } });
    expect(res.statusCode).toBe(401);
  });
});

describe("Host and Origin", () => {
  it.each(["evil.test", "127.0.0.1", "127.0.0.1:3001", "localhost:5173", "attacker.127.0.0.1.nip.io:3000", "[::1]:3000"])("Host %j is refused (403)", async (host) => {
    const res = await setup().req({ method: "GET", url: "/api/health", headers: { host } });
    expect(res.statusCode).toBe(403);
    expect(errorOf(res).code).toBe("FORBIDDEN_HOST");
  });

  it("accepts the API's own hosts and the Vite proxy request shape (Host rewritten, browser Origin 127.0.0.1:5173)", async () => {
    const { req, login } = setup();
    expect((await req({ method: "GET", url: "/api/health", headers: { host: "localhost:3000" } })).statusCode).toBe(200);
    const res = await req({ method: "POST", url: "/api/session", headers: { origin: VITE_ORIGIN, "content-type": "application/json", "sec-fetch-site": "same-origin" }, payload: { secret: SECRET } });
    expect(res.statusCode).toBe(201);
    expect((await login()).res.statusCode).toBe(201);
  });

  it.each(["http://evil.test", "http://127.0.0.1:5174", "https://127.0.0.1:5173", "null", "http://127.0.0.1:5173.evil.test"])("Origin %j is refused (403)", async (origin) => {
    const res = await setup().req({ method: "POST", url: "/api/session", headers: { origin, "content-type": "application/json" }, payload: { secret: SECRET } });
    expect(res.statusCode).toBe(403);
    expect(errorOf(res).code).toBe("FORBIDDEN_ORIGIN");
    expect(res.headers["set-cookie"]).toBeUndefined();
  });

  it("requests the browser marks cross-site are refused", async () => {
    const res = await setup().req({ method: "POST", url: "/api/session", headers: { "sec-fetch-site": "cross-site", "content-type": "application/json" }, payload: { secret: SECRET } });
    expect(res.statusCode).toBe(403);
  });

  it("spoofed forwarded headers do not bypass Host checks or the login rate limit", async () => {
    const { req } = setup();
    const bad = await req({ method: "GET", url: "/api/health", headers: { host: "evil.test", "x-forwarded-host": HOST, forwarded: `host=${HOST}` } });
    expect(bad.statusCode).toBe(403);
    for (let i = 0; i < 10; i++) {
      await req({ method: "POST", url: "/api/session", headers: { "content-type": "application/json", "x-forwarded-for": `10.0.0.${i}` }, payload: { secret: "wrong" } });
    }
    const limited = await req({ method: "POST", url: "/api/session", headers: { "content-type": "application/json", "x-forwarded-for": "10.9.9.9", "x-real-ip": "10.9.9.9" }, payload: { secret: SECRET } });
    expect(limited.statusCode).toBe(429);
  });
});

describe("request bodies", () => {
  it.each([
    ["text/plain", "secret=x"],
    ["application/x-www-form-urlencoded", "secret=x"],
    ["multipart/form-data; boundary=x", "--x--"],
  ])("non-JSON %s body on a state-changing request: 415", async (type, body) => {
    const res = await setup().req({ method: "POST", url: "/api/session", headers: { "content-type": type }, body });
    expect(res.statusCode).toBe(415);
    expect(errorOf(res).code).toBe("UNSUPPORTED_MEDIA_TYPE");
  });

  it("POST without any body/content type: 415", async () => {
    expect((await setup().req({ method: "POST", url: "/api/session" })).statusCode).toBe(415);
  });

  it("body over 1 KB: 413", async () => {
    const res = await setup().req({ method: "POST", url: "/api/session", headers: { "content-type": "application/json" }, body: JSON.stringify({ secret: "x".repeat(2000) }) });
    expect(res.statusCode).toBe(413);
    expect(errorOf(res)).toEqual({ code: "PAYLOAD_TOO_LARGE", message: "Request body too large" });
  });

  it.each([
    ["malformed JSON", '{"secret": "abc'],
    ["prototype poisoning", '{"secret":"x","__proto__":{"admin":true}}'],
    ["empty JSON body", ""],
  ])("%s: safe 400, nothing echoed", async (_n, body) => {
    const res = await setup().req({ method: "POST", url: "/api/session", headers: { "content-type": "application/json" }, body });
    expect(res.statusCode).toBe(400);
    expect(res.json()).toEqual({ error: { code: "BAD_REQUEST", message: "Malformed request" } });
  });

  it("DELETE without a body needs no content type; DELETE with a non-JSON body is refused", async () => {
    const { login, req } = setup();
    const s = await login();
    const bad = await req({ method: "DELETE", url: "/api/session", headers: { cookie: `${SESSION_COOKIE}=${s.id}`, "x-csrf-token": s.csrf, "content-type": "text/plain" }, body: "x" });
    expect(bad.statusCode).toBe(415);
    const ok = await req({ method: "DELETE", url: "/api/session", headers: { cookie: `${SESSION_COOKIE}=${s.id}`, "x-csrf-token": s.csrf } });
    expect(ok.statusCode).toBe(204);
  });
});

describe("login rate limit", () => {
  it("allows 10 attempts per minute, then 429 even for the correct secret; resets after the window", async () => {
    const { req, advance, login } = setup();
    for (let i = 0; i < 10; i++) expect((await login("wrong")).res.statusCode).toBe(401);
    const blocked = await login();
    expect(blocked.res.statusCode).toBe(429);
    expect(errorOf(blocked.res).code).toBe("RATE_LIMITED");
    expect(blocked.res.headers["set-cookie"]).toBeUndefined();
    advance(60_000);
    expect((await login()).res.statusCode).toBe(201);
    void req;
  });
});

describe("no leakage in errors, headers or logs", () => {
  it("error bodies never contain the secret, session id, CSRF token, request body, stack traces or input strings", async () => {
    const { login, req, logs } = setup();
    const s = await login();
    const marker = "LEAK-MARKER-4711";
    const responses = await Promise.all([
      login(`${marker}-${SECRET}`).then((r) => r.res),
      req({ method: "POST", url: "/api/session", headers: { "content-type": "application/json" }, payload: { secret: SECRET, [marker]: marker } }),
      req({ method: "POST", url: "/api/session", headers: { "content-type": "application/json" }, body: `{"secret":"${marker}` }),
      req({ method: "POST", url: "/api/session", headers: { "content-type": "text/plain" }, body: marker }),
      req({ method: "GET", url: `/api/${marker}`, headers: { cookie: `${SESSION_COOKIE}=${s.id}` } }),
      req({ method: "DELETE", url: "/api/session", headers: { cookie: `${SESSION_COOKIE}=${s.id}`, "x-csrf-token": marker } }),
      req({ method: "GET", url: "/api/health", headers: { host: marker } }),
    ]);
    for (const res of responses) {
      expect(res.statusCode).toBeGreaterThanOrEqual(400);
      for (const forbidden of [marker, SECRET, s.id, s.csrf, " at ", "Error:", "stack"]) expect(res.body).not.toContain(forbidden);
      expect(Object.keys(res.json() as object)).toEqual(["error"]);
    }
    const logText = logs.join("");
    expect(logText.length).toBeGreaterThan(0); // logging is on, and…
    for (const forbidden of [SECRET, s.id, s.csrf, marker, "cookie", "x-csrf-token"]) expect(logText).not.toContain(forbidden);
  });

  it("security headers are set on every response", async () => {
    const res = await setup().req({ method: "GET", url: "/api/health" });
    expect(res.headers).toMatchObject({
      "cache-control": "no-store",
      "x-content-type-options": "nosniff",
      "referrer-policy": "no-referrer",
      "x-frame-options": "DENY",
      "content-security-policy": "default-src 'none'; frame-ancestors 'none'",
    });
  });
});

describe("session primitives", () => {
  it("safeEqual handles unequal lengths without throwing", () => {
    expect(safeEqual("a", "a".repeat(1000))).toBe(false);
    expect(safeEqual("", "")).toBe(true);
    expect(safeEqual(SECRET, SECRET)).toBe(true);
  });

  it("the session manager refuses weak secrets and binds every session to the configured operator", () => {
    expect(() => createSessionManager({ secret: "short", operatorId: "operator:alice", clock: Date.now })).toThrow();
    const m = createSessionManager({ secret: SECRET, operatorId: "operator:alice", clock: Date.now });
    expect(m.create().operatorId).toBe("operator:alice");
  });

  it("buildApp refuses an operator that is not in the registry", () => {
    expect(() => buildApp({ db: openDatabase(":memory:"), operatorSecret: SECRET, port: PORT, operatorId: "operator:mallory" })).toThrow();
  });

  it("readCookie ignores malformed, duplicate and oversized headers", () => {
    expect(readCookie(`a=1; ${SESSION_COOKIE}=x; b=2`, SESSION_COOKIE)).toBe("x");
    expect(readCookie(`${SESSION_COOKIE}=x; ${SESSION_COOKIE}=y`, SESSION_COOKIE)).toBeUndefined();
    expect(readCookie(`x${SESSION_COOKIE}=z`, SESSION_COOKIE)).toBeUndefined();
    expect(readCookie(`${SESSION_COOKIE}=${"a".repeat(5000)}`, SESSION_COOKIE)).toBeUndefined();
    expect(readCookie(undefined, SESSION_COOKIE)).toBeUndefined();
  });
});
