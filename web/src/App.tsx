import { useCallback, useEffect, useState, type FormEvent } from "react";
import { api, ApiError, setCsrf } from "./api";
import { RunPage } from "./RunPage";
import { SuitePage } from "./SuitePage";
import type { Mode, RunSummary, Scenario, SessionInfo } from "./types";
import { Badge, Button, Card, cx, Empty, ErrorNote, fmtTime, ModeBadge, Spinner, statusTone } from "./ui";

// AgentShield dashboard. All data comes from the authenticated API; nothing here is mocked.

type View = { page: "dashboard" } | { page: "run"; runId: string } | { page: "suite" };

const CATEGORY: Record<string, string> = {
  legitimate: "Legitimate task",
  prompt_injection: "Prompt injection",
  sensitive_data: "Sensitive-data access",
  excess_permission: "Beyond-permission action",
  fail_closed: "Fail-closed edge cases",
};

function useHealth() {
  const [ok, setOk] = useState<boolean | null>(null);
  useEffect(() => {
    let stop = false;
    const check = () => api.health().then(() => !stop && setOk(true), () => !stop && setOk(false));
    check();
    const t = setInterval(check, 5000);
    return () => {
      stop = true;
      clearInterval(t);
    };
  }, []);
  return ok;
}

function Login({ onLogin }: { onLogin: (s: SessionInfo) => void }) {
  const [secret, setSecret] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      onLogin(await api.login(secret.trim()));
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Login failed");
    } finally {
      setBusy(false);
      setSecret("");
    }
  };
  return (
    <div className="mx-auto mt-24 max-w-md px-4">
      <Card title="Operator sign-in">
        <form onSubmit={submit} className="space-y-3">
          <label htmlFor="secret" className="block text-sm text-slate-300">
            Operator secret
          </label>
          <input
            id="secret"
            type="password"
            autoComplete="off"
            value={secret}
            onChange={(e) => setSecret(e.target.value)}
            className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 font-mono text-sm text-slate-100 focus:border-sky-500 focus:outline-none"
            placeholder="64 hex characters"
          />
          <p className="text-xs text-slate-500">The API prints a fresh secret once in its console at startup. Approvals are made as operator:alice.</p>
          <ErrorNote error={error} />
          <Button type="submit" busy={busy} disabled={!secret.trim()}>
            Sign in
          </Button>
        </form>
      </Card>
    </div>
  );
}

function ScenarioPicker({ scenarios, onStart }: { scenarios: Scenario[]; onStart: (id: string, mode: Mode) => Promise<void> }) {
  const [selected, setSelected] = useState<string | null>(null);
  const [mode, setMode] = useState<Mode>("off");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const current = scenarios.find((s) => s.id === selected) ?? null;

  const start = async () => {
    if (!current) return;
    setBusy(true);
    setError(null);
    try {
      await onStart(current.id, mode);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Could not start the run");
    } finally {
      setBusy(false);
    }
  };

  return (
    <Card title="Scenarios">
      <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
        {scenarios.map((s) => (
          <button
            key={s.id}
            onClick={() => setSelected(s.id)}
            aria-pressed={selected === s.id}
            className={cx(
              "rounded-lg border p-3 text-left transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-400",
              selected === s.id ? "border-sky-500 bg-sky-500/5" : "border-slate-800 hover:border-slate-600",
            )}
          >
            <div className="flex items-center gap-2">
              <Badge tone="info">{s.id}</Badge>
              <span className="text-xs text-slate-400">{CATEGORY[s.category] ?? s.category}</span>
            </div>
            <p className="mt-2 text-sm font-semibold text-slate-100">{s.title}</p>
            <p className="mt-1 line-clamp-3 text-xs text-slate-400">{s.description}</p>
          </button>
        ))}
      </div>
      {current && (
        <div className="mt-4 flex flex-wrap items-center gap-3 rounded-lg border border-slate-800 bg-slate-950/40 p-3">
          <div className="mr-auto text-sm text-slate-300">
            <p>
              <b>{current.id}</b>: “{current.goal}” · {current.userId} · {current.agentId}
            </p>
            {current.expectationNote && <p className="mt-1 max-w-3xl text-xs text-slate-400">{current.expectationNote}</p>}
          </div>
          <div role="radiogroup" aria-label="Shield mode" className="flex rounded-lg bg-slate-800 p-0.5">
            {(["off", "on"] as const).map((m) => (
              <button
                key={m}
                role="radio"
                aria-checked={mode === m}
                onClick={() => setMode(m)}
                className={cx(
                  "rounded-md px-3 py-1.5 text-sm font-semibold",
                  mode === m ? (m === "on" ? "bg-emerald-600 text-white" : "bg-rose-600 text-white") : "text-slate-400",
                )}
              >
                Shield {m.toUpperCase()}
              </button>
            ))}
          </div>
          <Button onClick={start} busy={busy}>
            Start run
          </Button>
        </div>
      )}
      <ErrorNote error={error} />
    </Card>
  );
}

function RecentRuns({ runs, onOpen }: { runs: RunSummary[]; onOpen: (id: string) => void }) {
  return (
    <Card title="Recent runs">
      {runs.length === 0 ? (
        <Empty>No runs yet. Pick a scenario and start one.</Empty>
      ) : (
        <ul className="divide-y divide-slate-800">
          {runs.map((r) => (
            <li key={r.runId}>
              <button onClick={() => onOpen(r.runId)} className="flex w-full flex-wrap items-center gap-2 py-2 text-left hover:bg-slate-800/40">
                <Badge tone="info">{r.scenarioId}</Badge>
                <ModeBadge mode={r.mode} />
                <Badge tone={statusTone(r.state)}>{r.state === "waiting" ? "needs approval" : r.state}</Badge>
                <code className="text-xs text-slate-500">{r.runId}</code>
                <span className="ml-auto text-xs text-slate-500">{fmtTime(r.createdAt)}</span>
              </button>
            </li>
          ))}
        </ul>
      )}
    </Card>
  );
}

export default function App() {
  const health = useHealth();
  const [session, setSession] = useState<SessionInfo | null>(null);
  const [checking, setChecking] = useState(true);
  const [scenarios, setScenarios] = useState<Scenario[]>([]);
  const [runs, setRuns] = useState<RunSummary[]>([]);
  const [view, setView] = useState<View>({ page: "dashboard" });
  const [error, setError] = useState<string | null>(null);

  const adopt = (s: SessionInfo | null) => {
    setCsrf(s?.csrfToken ?? null);
    setSession(s);
  };

  useEffect(() => {
    api.session().then(adopt, () => adopt(null)).finally(() => setChecking(false));
  }, []);

  const loadRuns = useCallback(() => api.runs().then(setRuns).catch((e) => e instanceof ApiError && e.status === 401 && adopt(null)), []);

  useEffect(() => {
    if (!session) return;
    api.scenarios().then(setScenarios, (e) => setError(e instanceof Error ? e.message : String(e)));
    loadRuns();
    const t = setInterval(loadRuns, 3000);
    return () => clearInterval(t);
  }, [session, loadRuns]);

  const start = async (scenarioId: string, mode: Mode) => {
    const run = await api.startRun(scenarioId, mode);
    void loadRuns();
    setView({ page: "run", runId: run.runId });
  };

  const waiting = runs.filter((r) => r.state === "waiting");
  const active = runs.filter((r) => r.state === "running" || r.state === "created");

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100">
      <header className="sticky top-0 z-10 border-b border-slate-800 bg-slate-950/90 backdrop-blur">
        <div className="mx-auto flex max-w-7xl flex-wrap items-center gap-3 px-4 py-3">
          <button onClick={() => setView({ page: "dashboard" })} className="flex items-center gap-2 text-left">
            <span aria-hidden className="grid h-8 w-8 place-items-center rounded-lg bg-sky-600 font-bold">◆</span>
            <span>
              <span className="block text-base font-semibold leading-tight">AgentShield</span>
              <span className="block text-xs text-slate-400">Provenance-aware policy enforcement for tool-using agents</span>
            </span>
          </button>
          {session && (
            <nav className="ml-4 flex gap-1" aria-label="Main">
              {(
                [
                  ["dashboard", "Dashboard"],
                  ["suite", "ON/OFF comparison"],
                ] as const
              ).map(([page, label]) => (
                <button
                  key={page}
                  onClick={() => setView({ page })}
                  className={cx("rounded-md px-3 py-1.5 text-sm", view.page === page ? "bg-slate-800 text-white" : "text-slate-400 hover:text-white")}
                >
                  {label}
                </button>
              ))}
            </nav>
          )}
          <div className="ml-auto flex items-center gap-2 text-xs">
            {health === null ? <Badge>checking API…</Badge> : health ? <Badge tone="good">● API connected</Badge> : <Badge tone="bad">● API unreachable</Badge>}
            {session && (
              <>
                <Badge tone="info">{session.operator.id}</Badge>
                <Button variant="secondary" onClick={() => api.logout().finally(() => adopt(null))}>
                  Sign out
                </Button>
              </>
            )}
          </div>
        </div>
      </header>

      <main className="mx-auto max-w-7xl space-y-4 px-4 py-6">
        {checking ? (
          <p className="flex items-center gap-2 text-sm text-slate-400">
            <Spinner /> Checking session…
          </p>
        ) : !session ? (
          <Login onLogin={adopt} />
        ) : (
          <>
            <ErrorNote error={error} />
            {waiting.length > 0 && view.page !== "run" && (
              <div className="flex flex-wrap items-center gap-3 rounded-xl border border-amber-500/40 bg-amber-500/5 px-4 py-3 text-sm">
                <Badge tone="warn">{waiting.length} run(s) waiting for your approval</Badge>
                {waiting.map((r) => (
                  <Button key={r.runId} variant="secondary" onClick={() => setView({ page: "run", runId: r.runId })}>
                    Review {r.scenarioId} ({r.mode.toUpperCase()})
                  </Button>
                ))}
              </div>
            )}
            {view.page === "dashboard" && (
              <>
                <div className="grid gap-3 sm:grid-cols-3">
                  <Card>
                    <p className="text-xs uppercase tracking-wider text-slate-500">Scenarios</p>
                    <p className="mt-1 text-2xl font-semibold">{scenarios.length}</p>
                  </Card>
                  <Card>
                    <p className="text-xs uppercase tracking-wider text-slate-500">Runs executing</p>
                    <p className="mt-1 text-2xl font-semibold">{active.length}</p>
                  </Card>
                  <Card>
                    <p className="text-xs uppercase tracking-wider text-slate-500">Awaiting approval</p>
                    <p className={cx("mt-1 text-2xl font-semibold", waiting.length > 0 && "text-amber-300")}>{waiting.length}</p>
                  </Card>
                </div>
                {scenarios.length === 0 ? (
                  <Card>
                    <p className="flex items-center gap-2 text-sm text-slate-400">
                      <Spinner /> Loading scenarios…
                    </p>
                  </Card>
                ) : (
                  <ScenarioPicker scenarios={scenarios} onStart={start} />
                )}
                <RecentRuns runs={runs} onOpen={(runId) => setView({ page: "run", runId })} />
              </>
            )}
            {view.page === "run" && (
              <>
                <Button variant="secondary" onClick={() => setView({ page: "dashboard" })}>
                  ← Back to dashboard
                </Button>
                <RunPage key={view.runId} runId={view.runId} onRunAgain={(id, mode) => void start(id, mode).catch((e) => setError(e instanceof Error ? e.message : String(e)))} />
              </>
            )}
            {view.page === "suite" && <SuitePage />}
          </>
        )}
      </main>
    </div>
  );
}
