import type { PendingApproval, Run, RunSummary, Scenario, SessionInfo, SuiteResult } from "./types";

// Same-origin API client (the Vite dev server proxies /api). The session cookie is HttpOnly; the CSRF token from the
// session endpoint is sent on every state-changing request.

export class ApiError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
  ) {
    super(message);
  }
}

let csrfToken: string | null = null;
export const setCsrf = (t: string | null) => void (csrfToken = t);

async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
  const headers: Record<string, string> = {};
  if (body !== undefined) headers["Content-Type"] = "application/json";
  if (method !== "GET" && csrfToken) headers["X-CSRF-Token"] = csrfToken;
  let res: Response;
  try {
    res = await fetch(path, { method, headers, credentials: "same-origin", body: body === undefined ? undefined : JSON.stringify(body) });
  } catch {
    throw new ApiError(0, "NETWORK", "The AgentShield API is not reachable");
  }
  if (res.status === 204) return undefined as T;
  const json = (await res.json().catch(() => null)) as { error?: { code: string; message: string } } | null;
  if (!res.ok) throw new ApiError(res.status, json?.error?.code ?? "HTTP", json?.error?.message ?? `HTTP ${res.status}`);
  return json as T;
}

export const api = {
  health: () => request<{ ok: boolean; sqlite: string }>("GET", "/api/health"),
  session: () => request<SessionInfo>("GET", "/api/session"),
  login: (secret: string) => request<SessionInfo>("POST", "/api/session", { secret }),
  logout: () => request<void>("DELETE", "/api/session"),
  scenarios: () => request<{ scenarios: Scenario[] }>("GET", "/api/scenarios").then((r) => r.scenarios),
  runs: () => request<{ runs: RunSummary[] }>("GET", "/api/runs").then((r) => r.runs),
  run: (id: string) => request<{ run: Run }>("GET", `/api/runs/${id}`).then((r) => r.run),
  startRun: (scenarioId: string, mode: "on" | "off") => request<{ run: Run }>("POST", "/api/runs", { scenarioId, mode }).then((r) => r.run),
  approvals: () => request<{ approvals: PendingApproval[] }>("GET", "/api/approvals?status=pending").then((r) => r.approvals),
  decide: (approvalId: string, verdict: "approve" | "reject") =>
    request<{ run: Run }>("POST", `/api/approvals/${approvalId}/decision`, { verdict }).then((r) => r.run),
  suite: () => request<SuiteResult>("POST", "/api/suite", {}),
};
