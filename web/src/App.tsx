import { useCallback, useEffect, useState, type FormEvent, type ReactNode } from "react";
import { Activity } from "./Activity";
import { api, ApiError, setCsrf } from "./api";
import { AttackLab } from "./AttackLab";
import { AuditExplorer } from "./AuditExplorer";
import { Overview, ScenarioExplorer } from "./Dashboard";
import { EmailLab } from "./EmailLab";
import { IconArrowLeft, IconBug, IconHand, IconLayers, IconList, IconLock, IconLogout, IconMail, IconShield, IconShieldCheck, IconUser } from "./icons";
import { RunPage } from "./RunPage";
import { SuitePage } from "./SuitePage";
import type { Mode, RunSummary, Scenario, SessionInfo } from "./types";
import { Badge, Button, cx, ErrorNote, Spinner } from "./ui";

// AgentShield operator console. All data comes from the authenticated API; nothing here is mocked.
// Routing uses the URL hash (#/overview, #/run/<id>, …) so a browser refresh or back/forward lands on a valid page.

type Page = "overview" | "scenarios" | "attack" | "email" | "audit" | "activity";
type View = { page: Page } | { page: "run"; runId: string };

const PAGES: readonly Page[] = ["overview", "scenarios", "attack", "email", "audit", "activity"];
const RUN_ID = /^run-[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

function parseHash(hash: string): View {
  const parts = hash.replace(/^#\/?/, "").split("/");
  if (parts[0] === "run" && parts[1] && RUN_ID.test(parts[1])) return { page: "run", runId: parts[1] };
  return PAGES.includes(parts[0] as Page) ? { page: parts[0] as Page } : { page: "overview" };
}
const toHash = (v: View) => (v.page === "run" ? `#/run/${v.runId}` : `#/${v.page}`);

function useHashView(): [View, (v: View) => void] {
  const [view, setViewState] = useState<View>(() => parseHash(window.location.hash));
  useEffect(() => {
    const onHash = () => setViewState(parseHash(window.location.hash));
    window.addEventListener("hashchange", onHash);
    return () => window.removeEventListener("hashchange", onHash);
  }, []);
  const setView = useCallback((v: View) => {
    const h = toHash(v);
    if (window.location.hash !== h) window.location.hash = h; // triggers hashchange → state
    else setViewState(v);
  }, []);
  return [view, setView];
}

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

function Brand({ compact }: { compact?: boolean }) {
  return (
    <span className="flex items-center gap-3">
      <span className="grid h-9 w-9 place-items-center rounded-xl bg-gradient-to-br from-cyan-400 to-blue-600 text-ink-950 shadow-[0_8px_24px_-8px_rgb(34_211_238/0.7)]">
        <IconShieldCheck size={20} />
      </span>
      <span className="text-left">
        <span className="block text-[17px] font-semibold leading-tight tracking-tight text-white">AgentShield</span>
        {!compact && <span className="block text-xs text-slate-400">Provenance-aware agent security</span>}
      </span>
    </span>
  );
}

function ConnectionBadge({ health }: { health: boolean | null }) {
  if (health === null) return <Badge>Checking API…</Badge>;
  return health ? (
    <Badge tone="good">
      <span className="h-1.5 w-1.5 rounded-full bg-emerald-400" /> API connected
    </Badge>
  ) : (
    <Badge tone="bad">
      <span className="h-1.5 w-1.5 rounded-full bg-rose-400" /> API unreachable
    </Badge>
  );
}

function Login({ onLogin, health }: { onLogin: (s: SessionInfo) => void; health: boolean | null }) {
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
    <div className="grid min-h-screen lg:grid-cols-2">
      <div className="relative hidden overflow-hidden border-r border-line bg-gradient-to-br from-ink-850 via-ink-900 to-ink-950 p-12 lg:flex lg:flex-col lg:justify-between">
        <div className="pointer-events-none absolute -left-24 top-1/3 h-96 w-96 rounded-full bg-cyan-400/10 blur-3xl" aria-hidden />
        <Brand />
        <div className="relative max-w-lg">
          <h1 className="text-4xl font-semibold leading-tight tracking-tight text-white">Every agent action, decided by policy — with proof.</h1>
          <p className="mt-4 text-base leading-relaxed text-slate-300">
            AgentShield tracks where every value came from and decides each tool call before it runs. Watch a prompt-injection attack succeed
            without it, and fail with it.
          </p>
          <ul className="mt-8 space-y-3 text-sm text-slate-300">
            {["Deterministic policy engine with explainable rules", "Human approval bound to the exact call, used once", "Fail-closed, append-only audit trail"].map((t) => (
              <li key={t} className="flex items-center gap-3">
                <span className="grid h-6 w-6 place-items-center rounded-full bg-emerald-400/15 text-emerald-300">
                  <IconShieldCheck size={14} />
                </span>
                {t}
              </li>
            ))}
          </ul>
        </div>
        <p className="relative text-xs text-slate-500">PARALLAX 2026 · Problem Statement 01 · Synthetic data, local sandbox only</p>
      </div>
      <div className="flex items-center justify-center px-4 py-12">
        <form onSubmit={submit} className="w-full max-w-md space-y-6 animate-fade-in">
          <div className="lg:hidden">
            <Brand />
          </div>
          <div>
            <h2 className="text-2xl font-semibold tracking-tight text-white">Operator sign-in</h2>
            <p className="mt-2 text-sm leading-relaxed text-slate-400">
              The API prints a fresh 64-character operator secret once in its console at startup. Copy it and paste it below — approvals you
              make are recorded as <code className="font-mono text-slate-300">operator:alice</code>.
            </p>
          </div>
          <div className="space-y-2">
            <label htmlFor="secret" className="block text-sm font-medium text-slate-200">
              Operator secret
            </label>
            <div className="relative">
              <IconLock size={16} className="pointer-events-none absolute left-3.5 top-1/2 -translate-y-1/2 text-slate-500" />
              <input
                id="secret"
                type="password"
                autoComplete="off"
                spellCheck={false}
                value={secret}
                onChange={(e) => setSecret(e.target.value)}
                className="h-12 w-full rounded-xl border border-line-strong bg-ink-900 pl-10 pr-3 font-mono text-sm text-slate-100 placeholder:text-slate-600 focus:border-cyan-400 focus:outline-none focus:ring-2 focus:ring-cyan-400/30"
                placeholder="Paste the secret (Ctrl+V)"
              />
            </div>
            {secret && <p className="text-xs text-slate-500">{secret.trim().length} characters entered{secret.trim().length !== 64 && " — the secret is 64 characters"}</p>}
          </div>
          <ErrorNote error={error} />
          <Button type="submit" size="lg" busy={busy} disabled={!secret.trim()} className="w-full">
            Sign in
          </Button>
          <div className="flex items-center justify-between text-xs text-slate-500">
            <ConnectionBadge health={health} />
            <span>Local only · 127.0.0.1</span>
          </div>
        </form>
      </div>
    </div>
  );
}

const NAV: readonly { page: Page; label: string; icon: (p: { size?: number }) => ReactNode }[] = [
  { page: "overview", label: "Overview", icon: IconShield },
  { page: "scenarios", label: "Predefined Scenarios", icon: IconLayers },
  { page: "attack", label: "Interactive Attack Lab", icon: IconBug },
  { page: "email", label: "Email Security Lab", icon: IconMail },
  { page: "audit", label: "Audit Explorer", icon: IconList },
];

function NavButton({ active, onClick, icon, children, badge }: { active: boolean; onClick: () => void; icon: ReactNode; children: ReactNode; badge?: number }) {
  return (
    <button
      onClick={onClick}
      aria-current={active ? "page" : undefined}
      className={cx(
        "flex w-full items-center gap-3 rounded-xl px-3 py-2.5 text-sm font-medium transition-colors",
        active ? "bg-cyan-400/10 text-white ring-1 ring-inset ring-cyan-400/25" : "text-slate-400 hover:bg-white/[0.04] hover:text-slate-100",
      )}
    >
      <span className={active ? "text-cyan-300" : ""}>{icon}</span>
      <span className="flex-1 text-left">{children}</span>
      {badge ? <span className="rounded-full bg-amber-400/15 px-2 text-xs font-semibold text-amber-300">{badge}</span> : null}
    </button>
  );
}

export default function App() {
  const health = useHealth();
  const [session, setSession] = useState<SessionInfo | null>(null);
  const [checking, setChecking] = useState(true);
  const [scenarios, setScenarios] = useState<Scenario[] | null>(null);
  const [runs, setRuns] = useState<RunSummary[]>([]);
  const [view, setView] = useHashView();
  const [error, setError] = useState<string | null>(null);
  const [signingOut, setSigningOut] = useState(false);

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

  useEffect(() => {
    window.scrollTo({ top: 0 });
  }, [view]);

  const openRun = useCallback((runId: string) => setView({ page: "run", runId }), [setView]);
  const go = useCallback((page: Page) => setView({ page }), [setView]);

  const start = async (scenarioId: string, mode: Mode) => {
    const run = await api.startRun(scenarioId, mode);
    void loadRuns();
    openRun(run.runId);
  };

  const signOut = () => {
    setSigningOut(true);
    api.logout().finally(() => {
      setSigningOut(false);
      adopt(null);
    });
  };

  if (checking) {
    return (
      <div className="grid min-h-screen place-items-center">
        <p className="flex items-center gap-3 text-sm text-slate-400">
          <Spinner /> Checking session…
        </p>
      </div>
    );
  }
  if (!session) return <Login onLogin={adopt} health={health} />;

  const waiting = runs.filter((r) => r.state === "waiting");
  const activeNav: Page = view.page === "run" || view.page === "activity" ? "overview" : view.page;

  return (
    <div className="min-h-screen lg:grid lg:grid-cols-[272px_minmax(0,1fr)]">
      {/* Sidebar (desktop) */}
      <aside className="sticky top-0 hidden h-screen flex-col border-r border-line bg-ink-900/70 p-5 backdrop-blur lg:flex">
        <button onClick={() => go("overview")} className="rounded-xl text-left">
          <Brand />
        </button>
        <nav aria-label="Main" className="mt-8 space-y-1">
          {NAV.map((n) => (
            <NavButton key={n.page} active={activeNav === n.page} onClick={() => go(n.page)} icon={<n.icon size={18} />} badge={n.page === "overview" ? waiting.length : undefined}>
              {n.label}
            </NavButton>
          ))}
        </nav>
        <div className="mt-8 rounded-xl border border-line bg-ink-950/50 p-4 text-xs leading-relaxed text-slate-400">
          <p className="flex items-center gap-2 font-semibold text-slate-200">
            <IconShield size={14} className="text-cyan-300" /> Demo environment
          </p>
          <p className="mt-1.5">Deterministic simulated agent (not an LLM) · synthetic data · per-run sandbox · no real email or network.</p>
        </div>
        <div className="mt-auto space-y-3">
          <ConnectionBadge health={health} />
          <div className="flex items-center gap-3 rounded-xl border border-line bg-ink-950/50 p-3">
            <span className="grid h-9 w-9 place-items-center rounded-full bg-white/[0.06] text-slate-300">
              <IconUser size={18} />
            </span>
            <div className="min-w-0 flex-1">
              <p className="truncate text-sm font-semibold text-slate-100">{session.operator.displayName}</p>
              <p className="truncate font-mono text-xs text-slate-500">{session.operator.id}</p>
            </div>
            <button onClick={signOut} disabled={signingOut} aria-label="Sign out" title="Sign out" className="rounded-lg p-2 text-slate-400 hover:bg-white/[0.06] hover:text-white disabled:opacity-50">
              {signingOut ? <Spinner /> : <IconLogout size={18} />}
            </button>
          </div>
        </div>
      </aside>

      {/* Top bar (mobile / tablet) */}
      <header className="sticky top-0 z-20 border-b border-line bg-ink-950/90 backdrop-blur lg:hidden">
        <div className="flex items-center justify-between gap-3 px-4 py-3">
          <button onClick={() => go("overview")}>
            <Brand compact />
          </button>
          <div className="flex items-center gap-2">
            <ConnectionBadge health={health} />
            <Button variant="ghost" size="sm" onClick={signOut} busy={signingOut} ariaLabel="Sign out">
              <IconLogout size={16} />
            </Button>
          </div>
        </div>
        <nav aria-label="Main" className="flex gap-1 overflow-x-auto px-3 pb-3">
          {NAV.map((n) => (
            <button
              key={n.page}
              onClick={() => go(n.page)}
              aria-current={activeNav === n.page ? "page" : undefined}
              className={cx("flex shrink-0 items-center gap-2 rounded-lg px-3 py-2 text-sm", activeNav === n.page ? "bg-cyan-400/10 text-white" : "text-slate-400")}
            >
              <n.icon size={16} /> {n.label}
            </button>
          ))}
        </nav>
      </header>

      <main className="mx-auto w-full max-w-[1480px] min-w-0 space-y-5 px-4 py-6 sm:px-6 lg:px-10 lg:py-8">
        <ErrorNote error={error} />
        {waiting.length > 0 && !(view.page === "run" && waiting.some((w) => w.runId === view.runId)) && (
          <div className="flex flex-wrap items-center gap-3 rounded-2xl border border-amber-400/35 bg-amber-400/[0.07] px-5 py-3.5 animate-fade-in" role="status">
            <span className="grid h-9 w-9 place-items-center rounded-xl bg-amber-400/15 text-amber-300">
              <IconHand size={18} />
            </span>
            <p className="text-sm font-medium text-amber-100">
              {waiting.length} run{waiting.length === 1 ? " is" : "s are"} waiting for your approval
            </p>
            <div className="ml-auto flex flex-wrap gap-2">
              {waiting.slice(0, 4).map((r) => (
                <Button key={r.runId} variant="secondary" size="sm" onClick={() => openRun(r.runId)}>
                  Review {r.scenarioId} · Shield {r.mode.toUpperCase()}
                </Button>
              ))}
            </div>
          </div>
        )}

        {view.page === "overview" && <Overview runs={runs} onStart={start} onOpenRun={openRun} onNavigate={go} />}
        {view.page === "scenarios" && (
          <div className="space-y-6">
            <header>
              <p className="inline-flex items-center gap-2 text-xs font-semibold uppercase tracking-[0.16em] text-cyan-300">
                <IconLayers size={14} /> Predefined Scenarios
              </p>
              <h1 className="mt-2 text-3xl font-semibold tracking-tight text-white">Five reproducible cases, two shield modes.</h1>
              <p className="mt-2 max-w-3xl text-base text-slate-300">
                Launch a single scenario to follow it live and approve its high-impact actions yourself, or run the full suite below for the
                Shield OFF vs ON comparison.
              </p>
            </header>
            <ScenarioExplorer scenarios={scenarios} onStart={start} />
            <SuitePage />
          </div>
        )}
        {/* Lab pages stay mounted while hidden so a lab's results survive opening a run and coming back. */}
        <div hidden={view.page !== "attack"}>
          <AttackLab onOpenRun={openRun} />
        </div>
        <div hidden={view.page !== "email"}>
          <EmailLab onOpenRun={openRun} />
        </div>
        {view.page === "audit" && <AuditExplorer onOpenRun={openRun} />}
        {view.page === "activity" && <Activity runs={runs} onOpen={openRun} />}
        {view.page === "run" && (
          <>
            <Button variant="ghost" size="sm" onClick={() => (window.history.length > 1 ? window.history.back() : go("overview"))}>
              <IconArrowLeft size={16} /> Back
            </Button>
            <RunPage key={view.runId} runId={view.runId} onRunAgain={(id, mode) => void start(id, mode).catch((e) => setError(e instanceof Error ? e.message : String(e)))} />
          </>
        )}
      </main>
    </div>
  );
}
