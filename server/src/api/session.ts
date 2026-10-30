import { createHash, randomBytes, timingSafeEqual } from "node:crypto";

// Operator authentication (M5.2): one startup secret, in-memory sessions, CSRF tokens, login rate limiting.
// Secrets, session ids and CSRF tokens are never logged or echoed by this module.

export const SESSION_COOKIE = "as_session";
export const SESSION_TTL_MS = 12 * 60 * 60 * 1000;
export const LOGIN_LIMIT = 10;
export const LOGIN_WINDOW_MS = 60_000;
const ID_BYTES = 32;
const ID_PATTERN = /^[A-Za-z0-9_-]{43}$/; // base64url of 32 bytes

export interface OperatorSession {
  readonly id: string;
  readonly operatorId: string;
  readonly csrfToken: string;
  readonly createdAt: number;
  readonly expiresAt: number;
}

const digest = (s: string) => createHash("sha256").update(s, "utf8").digest();

/** Constant-time string comparison: both sides are hashed to fixed-length digests first (no length leak, no throw). */
export function safeEqual(a: string, b: string): boolean {
  return timingSafeEqual(digest(a), digest(b));
}

export const randomToken = () => randomBytes(ID_BYTES).toString("base64url");

/** A fresh 32-byte operator secret (hex), for the server entry point. */
export const generateOperatorSecret = () => randomBytes(32).toString("hex");

export interface SessionManager {
  verifySecret(candidate: string): boolean;
  create(): OperatorSession;
  /** The live session for this id, or null (unknown, malformed or expired — expired sessions are deleted). */
  get(id: string | undefined): OperatorSession | null;
  destroy(id: string): void;
  checkCsrf(session: OperatorSession, token: unknown): boolean;
  size(): number;
}

export function createSessionManager(opts: { secret: string; operatorId: string; clock: () => number; ttlMs?: number }): SessionManager {
  if (typeof opts.secret !== "string" || opts.secret.length < 32) throw new Error("Operator secret must be at least 32 characters");
  const ttl = opts.ttlMs ?? SESSION_TTL_MS;
  const sessions = new Map<string, OperatorSession>();

  const sweep = () => {
    const now = opts.clock();
    for (const [id, s] of sessions) if (s.expiresAt <= now) sessions.delete(id);
  };

  return {
    verifySecret: (candidate) => typeof candidate === "string" && safeEqual(candidate, opts.secret),
    create() {
      sweep();
      const now = opts.clock();
      // The operator identity comes from server configuration, never from the client.
      const s = Object.freeze({ id: randomToken(), operatorId: opts.operatorId, csrfToken: randomToken(), createdAt: now, expiresAt: now + ttl });
      sessions.set(s.id, s);
      return s;
    },
    get(id) {
      if (typeof id !== "string" || !ID_PATTERN.test(id)) return null;
      const s = sessions.get(id);
      if (!s) return null;
      if (s.expiresAt <= opts.clock()) {
        sessions.delete(id);
        return null;
      }
      return s;
    },
    destroy: (id) => void sessions.delete(id),
    checkCsrf: (session, token) => typeof token === "string" && token.length > 0 && token.length <= 128 && safeEqual(token, session.csrfToken),
    size: () => sessions.size,
  };
}

/** Fixed-window login limiter keyed by the TCP peer address (never by forwarded headers). */
export function createLoginLimiter(clock: () => number, limit = LOGIN_LIMIT, windowMs = LOGIN_WINDOW_MS) {
  const windows = new Map<string, { start: number; count: number }>();
  return {
    /** Counts an attempt; returns false if this key is over the limit for the current window. */
    attempt(key: string): boolean {
      const now = clock();
      const w = windows.get(key);
      if (!w || now - w.start >= windowMs) {
        windows.set(key, { start: now, count: 1 });
        return true;
      }
      w.count++;
      return w.count <= limit;
    },
  };
}

/** Value of the named cookie; undefined if absent, duplicated (ambiguous) or malformed. */
export function readCookie(header: string | undefined, name: string): string | undefined {
  if (typeof header !== "string" || header.length > 4096) return undefined;
  const values = header
    .split(";")
    .map((p) => p.trim())
    .filter((p) => p.startsWith(`${name}=`))
    .map((p) => p.slice(name.length + 1));
  return values.length === 1 ? values[0] : undefined;
}

/**
 * Session cookie. HttpOnly + SameSite=Strict + Path=/. `Secure` is set only when the server is served over HTTPS: the demo
 * runs on plain http://127.0.0.1, where browsers would drop a Secure cookie (documented in SYSTEM_ARCHITECTURE §8).
 */
export function sessionCookie(id: string, maxAgeMs: number, secure: boolean): string {
  return `${SESSION_COOKIE}=${id}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${Math.max(0, Math.floor(maxAgeMs / 1000))}${secure ? "; Secure" : ""}`;
}

export function clearedSessionCookie(secure: boolean): string {
  return `${SESSION_COOKIE}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0${secure ? "; Secure" : ""}`;
}
