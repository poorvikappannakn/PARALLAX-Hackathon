import { useEffect, useState } from "react";
import { api, ApiError } from "./api";
import { IconActivity, IconArrowRight, IconBan, IconBug, IconHand, IconLayers, IconList, IconMail, IconShield, IconShieldCheck, IconShieldOff, IconUser, ToolIcon } from "./icons";
import { metaFor } from "./scenarioMeta";
import type { AuditExplorerEvent, Mode, Overview as OverviewData, RunSummary, Scenario } from "./types";
import { Badge, Button, cx, DecisionChip, Empty, ErrorNote, fmtTime, ModeBadge, Panel, Spinner, STATE_LABEL, Stat, statusTone } from "./ui";

// Overview (real counts from /api/overview and events from /api/audit) and the predefined-scenario explorer.

function Hero({ onLab, onLaunchS2, busy }: { onLab: () => void; onLaunchS2: () => void; busy: boolean }) {
  return (
    <section className="relative overflow-hidden rounded-3xl border border-line bg-gradient-to-br from-ink-850 via-ink-900 to-ink-950 px-6 py-8 sm:px-10 sm:py-10">
      <div className="pointer-events-none absolute -right-32 -top-40 h-96 w-96 rounded-full bg-cyan-400/10 blur-3xl" aria-hidden />
      <div className="pointer-events-none absolute -bottom-40 left-1/3 h-80 w-80 rounded-full bg-blue-500/10 blur-3xl" aria-hidden />
      <div className="relative grid items-center gap-8 lg:grid-cols-[1.4fr_1fr]">
        <div>
          <p className="inline-flex items-center gap-2 rounded-full bg-cyan-400/10 px-3 py-1 text-xs font-semibold uppercase tracking-[0.16em] text-cyan-300 ring-1 ring-cyan-400/25">
            <IconShieldCheck size={14} /> Policy enforcement for tool-using AI agents
          </p>
          <h1 className="mt-4 text-3xl font-semibold leading-tight tracking-tight text-white sm:text-[40px]">
            Secure the agent's <span className="bg-gradient-to-r from-cyan-300 to-blue-400 bg-clip-text text-transparent">actions</span>, not just its prompt.
          </h1>
          <p className="mt-4 max-w-2xl text-base leading-relaxed text-slate-300">
            AgentShield sits between an AI agent and its tools. Every value carries <b className="text-slate-100">provenance</b> — where it came
            from and how sensitive it is — and every tool call is decided <b className="text-emerald-300">ALLOW</b>, <b className="text-rose-300">DENY</b> or{" "}
            <b className="text-amber-300">REQUIRE APPROVAL</b> by a deterministic policy engine, before anything runs. Injected instructions can
            make the agent <i>try</i>; they cannot make it <i>succeed</i>.
          </p>
          <div className="mt-6 flex flex-wrap gap-3">
            <Button size="lg" onClick={onLaunchS2} busy={busy}>
              <IconShieldOff size={18} /> Run the prompt-injection attack
            </Button>
            <Button size="lg" variant="secondary" onClick={onLab}>
              <IconBug size={18} /> Write your own attack
            </Button>
          </div>
        </div>
        <ol className="grid gap-3 text-sm">
          {[
            { icon: <IconLayers size={18} />, title: "Label every value", text: "Task and profile data are TRUSTED; web pages, inbox and files are UNTRUSTED with a confidentiality level." },
            { icon: <IconShield size={18} />, title: "Decide every tool call", text: "Rules check where each argument came from and what the tool can affect. Missing data fails closed." },
            { icon: <IconHand size={18} />, title: "Humans approve the rest", text: "High-impact calls pause for an operator; the approval is bound to that exact call and used once." },
          ].map((s, i) => (
            <li key={s.title} className="flex gap-3 rounded-2xl border border-line bg-ink-950/50 p-4">
              <span className="grid h-9 w-9 shrink-0 place-items-center rounded-xl bg-cyan-400/10 text-cyan-300 ring-1 ring-cyan-400/20">{s.icon}</span>
              <div>
                <p className="font-semibold text-slate-100">
                  <span className="mr-1.5 font-mono text-xs text-slate-500">0{i + 1}</span>
                  {s.title}
                </p>
                <p className="mt-0.5 text-slate-400">{s.text}</p>
              </div>
            </li>
          ))}
        </ol>
      </div>
    </section>
  );
}

function ScenarioCard({ s, onLaunch, featured }: { s: Scenario; onLaunch: (mode: Mode) => Promise<void>; featured: boolean }) {
  const m = metaFor(s.category);
  const [busy, setBusy] = useState<Mode | null>(null);
  const [error, setError] = useState<string | null>(null);
  const launch = async (mode: Mode) => {
    setBusy(mode);
    setError(null);
    try {
      await onLaunch(mode);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Could not start the run");
      setBusy(null);
    }
  };
  return (
    <article
      className={cx(
        "group flex flex-col rounded-2xl border p-5 transition-colors",
        featured ? "border-rose-400/40 bg-gradient-to-br from-rose-500/[0.08] via-ink-900 to-ink-900 md:col-span-2" : "border-line bg-ink-900/70 hover:border-line-strong",
      )}
    >
      <div className="flex items-start gap-4">
        <span className={cx("grid h-12 w-12 shrink-0 place-items-center rounded-xl ring-1 ring-inset", m.accent)}>{m.icon(featured ? 24 : 22)}</span>
        <div className="min-w-0 flex-1">
          <div className="flex items-center justify-between gap-2">
            <Badge tone="brand" className="font-mono">
              {s.id}
            </Badge>
            <Badge tone={m.severity.tone}>{m.severity.label === "Baseline" ? "Baseline" : `Severity: ${m.severity.label}`}</Badge>
          </div>
          <p className="mt-1.5 text-xs font-semibold uppercase tracking-[0.12em] text-slate-400">{m.label}</p>
          <h3 className={cx("mt-2 font-semibold text-slate-50", featured ? "text-xl" : "text-base")}>{s.title}</h3>
          <p className="mt-1 text-sm text-slate-400">{m.threat}</p>
        </div>
      </div>
      <p className={cx("mt-4 flex-1 text-sm leading-relaxed text-slate-300", !featured && "line-clamp-4")}>{s.description}</p>
      {s.expectationNote && (
        <p title={s.expectationNote} className="mt-2 line-clamp-2 text-xs leading-relaxed text-slate-500">
          Note: {s.expectationNote}
        </p>
      )}
      <div className="mt-5 grid grid-cols-2 gap-2">
        <Button variant="secondary" onClick={() => launch("off")} busy={busy === "off"} disabled={busy !== null} ariaLabel={`Launch ${s.id} with Shield OFF`}>
          <IconShieldOff size={16} className="text-rose-300" /> Shield OFF
        </Button>
        <Button variant={featured ? "primary" : "secondary"} onClick={() => launch("on")} busy={busy === "on"} disabled={busy !== null} ariaLabel={`Launch ${s.id} with Shield ON`}>
          <IconShieldCheck size={16} className={featured ? "" : "text-emerald-300"} /> Shield ON
        </Button>
      </div>
      {error && (
        <div className="mt-3">
          <ErrorNote error={error} />
        </div>
      )}
    </article>
  );
}

/** Polls the real overview and audit endpoints. */
function useOverviewData() {
  const [overview, setOverview] = useState<OverviewData | null>(null);
  const [events, setEvents] = useState<AuditExplorerEvent[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    let stop = false;
    const load = () => {
      api.overview().then(
        (o) => !stop && (setOverview(o), setError(null)),
        (e) => !stop && setError(e instanceof Error ? e.message : String(e)),
      );
      api.audit().then(
        (e) => !stop && setEvents(e),
        () => {},
      );
    };
    load();
    const t = setInterval(load, 3000);
    return () => {
      stop = true;
      clearInterval(t);
    };
  }, []);
  return { overview, events, error };
}

export function RunRow({ r, onOpen }: { r: RunSummary; onOpen: (id: string) => void }) {
  return (
    <button
      onClick={() => onOpen(r.runId)}
      className="flex w-full flex-wrap items-center gap-3 rounded-xl px-3 py-2.5 text-left transition-colors hover:bg-white/[0.04]"
    >
      <Badge tone={r.kind === "scenario" ? "brand" : "info"} className="font-mono">
        {r.scenarioId}
      </Badge>
      <ModeBadge mode={r.mode} />
      <Badge tone={statusTone(r.state)}>{STATE_LABEL[r.state] ?? r.state}</Badge>
      <span className="hidden min-w-0 flex-1 truncate text-sm text-slate-400 md:inline">{r.title}</span>
      <span className="ml-auto flex items-center gap-2 text-xs tabular-nums text-slate-500">
        {fmtTime(r.createdAt)} <IconArrowRight size={14} />
      </span>
    </button>
  );
}

function ArchitectureStrip() {
  const steps = [
    { icon: <IconUser size={16} />, title: "User task", text: "TRUSTED", tone: "text-emerald-300" },
    { icon: <IconBug size={16} />, title: "Untrusted content", text: "web · email · document", tone: "text-rose-300" },
    { icon: <IconActivity size={16} />, title: "Agent tool request", text: "deterministic simulation", tone: "text-slate-300" },
    { icon: <IconShield size={16} />, title: "Policy Enforcement Point", text: "ALLOW · DENY · APPROVAL", tone: "text-cyan-300" },
    { icon: <IconLayers size={16} />, title: "Gateway → sandboxed tool", text: "single-use ticket", tone: "text-slate-300" },
    { icon: <IconList size={16} />, title: "Audit log", text: "written before & after", tone: "text-slate-300" },
  ];
  return (
    <Panel title="How AgentShield enforces" subtitle="Every tool call takes this path — there is no other way for the agent to act" icon={<IconShield size={16} />}>
      <ol className="grid gap-2 sm:grid-cols-2 lg:grid-cols-6">
        {steps.map((s, i) => (
          <li key={s.title} className="relative rounded-xl border border-line bg-ink-950/50 p-3">
            <span className={cx("flex items-center gap-2 text-sm font-semibold text-slate-100")}>
              <span className="text-slate-400">{s.icon}</span>
              {s.title}
            </span>
            <span className={cx("mt-1 block text-xs", s.tone)}>{s.text}</span>
            {i < steps.length - 1 && <IconArrowRight size={14} className="absolute -right-2.5 top-1/2 hidden -translate-y-1/2 text-slate-600 lg:block" />}
          </li>
        ))}
      </ol>
    </Panel>
  );
}

const EVENT_LABEL: Record<string, string> = { decision: "Policy decision", re_decision: "Re-evaluation", approval_decided: "Human decision" };

export function Overview({
  runs,
  onStart,
  onOpenRun,
  onNavigate,
}: {
  runs: RunSummary[];
  onStart: (scenarioId: string, mode: Mode) => Promise<void>;
  onOpenRun: (id: string) => void;
  onNavigate: (page: "scenarios" | "attack" | "email" | "audit" | "activity") => void;
}) {
  const [heroBusy, setHeroBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const data = useOverviewData();
  const o = data.overview;
  const security = (data.events ?? []).filter((e) => e.decision === "DENY" || e.decision === "REQUIRE_APPROVAL").slice(0, 8);

  const launchS2 = async () => {
    setHeroBusy(true);
    setError(null);
    try {
      await onStart("S2", "off");
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Could not start the run");
      setHeroBusy(false);
    }
  };

  return (
    <div className="space-y-6">
      <Hero onLab={() => onNavigate("attack")} onLaunchS2={launchS2} busy={heroBusy} />
      <ErrorNote error={error ?? data.error} />

      <section aria-label="Security overview" className="grid gap-4 sm:grid-cols-2 xl:grid-cols-5">
        <Stat label="Runs this session" value={o?.runs ?? "—"} hint={o ? `${o.live} executing` : "Loading…"} icon={<IconActivity size={18} />} />
        <Stat label="Allowed actions" value={o?.decisions.allow ?? "—"} tone="good" hint="Policy decisions: ALLOW" icon={<IconShieldCheck size={18} />} />
        <Stat label="Denied actions" value={o?.decisions.deny ?? "—"} tone="bad" hint="Policy decisions: DENY" icon={<IconBan size={18} />} />
        <Stat label="Pending approvals" value={o?.waiting ?? "—"} tone={o && o.waiting > 0 ? "warn" : undefined} hint={o ? `${o.decisions.approval} approval requests so far` : "Loading…"} icon={<IconHand size={18} />} />
        <Stat
          label="Attacks blocked · Shield ON"
          value={o?.attacksBlocked ?? "—"}
          tone="good"
          hint={o ? `${o.attacksSucceeded} attack${o.attacksSucceeded === 1 ? "" : "s"} succeeded across all runs` : "Loading…"}
          icon={<IconShield size={18} />}
        />
      </section>
      <p className="-mt-3 text-xs text-slate-500">
        Shield mode is chosen per run. Counts cover the interactive runs the API holds in memory (scenarios and labs); the suite comparison is separate.
      </p>

      <ArchitectureStrip />

      <section aria-label="Start here" className="grid gap-4 md:grid-cols-3">
        {[
          { page: "scenarios" as const, icon: <IconLayers size={20} />, title: "Predefined scenarios", text: "S1–S5: legitimate task, prompt injection, sensitive data, beyond-permission, fail-closed." },
          { page: "attack" as const, icon: <IconBug size={20} />, title: "Interactive Attack Lab", text: "Write or upload your own malicious page or document and run it with the shield off and on." },
          { page: "email" as const, icon: <IconMail size={20} />, title: "Email Security Lab", text: "Feed the agent a malicious email and watch the policy engine stop secret theft and deletion." },
        ].map((c) => (
          <button key={c.page} onClick={() => onNavigate(c.page)} className="group rounded-2xl border border-line bg-ink-900/70 p-5 text-left transition-colors hover:border-cyan-400/40">
            <span className="grid h-10 w-10 place-items-center rounded-xl bg-cyan-400/10 text-cyan-300 ring-1 ring-cyan-400/20">{c.icon}</span>
            <p className="mt-3 flex items-center gap-2 font-semibold text-slate-100">
              {c.title} <IconArrowRight size={15} className="text-slate-500 transition-transform group-hover:translate-x-0.5" />
            </p>
            <p className="mt-1 text-sm text-slate-400">{c.text}</p>
          </button>
        ))}
      </section>

      <div className="grid gap-6 xl:grid-cols-2">
        <Panel
          title="Recent security events"
          subtitle="Denials and approval requests from the audit log"
          icon={<IconBan size={16} />}
          actions={
            <Button variant="ghost" size="sm" onClick={() => onNavigate("audit")}>
              Audit Explorer <IconArrowRight size={14} />
            </Button>
          }
        >
          {data.events === null ? (
            <p className="flex items-center gap-2 text-sm text-slate-400">
              <Spinner /> Loading…
            </p>
          ) : security.length === 0 ? (
            <Empty icon={<IconShieldCheck />} title="No denials or approval requests yet">
              Run S2 or a lab with Shield ON to watch the policy engine block an attack.
            </Empty>
          ) : (
            <ul className="divide-y divide-line">
              {security.map((e) => (
                <li key={`${e.runId}-${e.seq}`}>
                  <button onClick={() => onOpenRun(e.runId)} className="flex w-full items-start gap-3 py-3 text-left hover:bg-white/[0.02]">
                    <span className="mt-0.5 text-slate-400">{e.tool ? <ToolIcon tool={e.tool} /> : <IconShield />}</span>
                    <span className="min-w-0 flex-1">
                      <span className="flex flex-wrap items-center gap-2">
                        <span className="text-sm text-slate-300">{EVENT_LABEL[e.kind] ?? e.kind}</span>
                        {e.tool && <code className="font-mono text-sm text-slate-100">{e.tool}</code>}
                        <DecisionChip decision={e.decision} ruleId={e.ruleId} />
                        <Badge tone="brand" className="font-mono">
                          {e.scenarioId}
                        </Badge>
                        <ModeBadge mode={e.mode} />
                      </span>
                      {e.reason && <span className="mt-1 block truncate text-sm text-slate-400">{e.reason}</span>}
                    </span>
                  </button>
                </li>
              ))}
            </ul>
          )}
        </Panel>
        <Panel
          title="Recent runs"
          subtitle="Scenario and lab runs in this server session"
          icon={<IconActivity size={16} />}
          actions={
            runs.length > 0 && (
              <Button variant="ghost" size="sm" onClick={() => onNavigate("activity")}>
                View all <IconArrowRight size={14} />
              </Button>
            )
          }
        >
          {runs.length === 0 ? (
            <Empty icon={<IconActivity />} title="No runs yet">
              Start with a predefined scenario or one of the labs.
            </Empty>
          ) : (
            <div className="-mx-3">
              {runs.slice(0, 7).map((r) => (
                <RunRow key={r.runId} r={r} onOpen={onOpenRun} />
              ))}
            </div>
          )}
        </Panel>
      </div>
    </div>
  );
}

/** Predefined scenarios S1–S5: launch cards. */
export function ScenarioExplorer({ scenarios, onStart }: { scenarios: Scenario[] | null; onStart: (scenarioId: string, mode: Mode) => Promise<void> }) {
  const ordered = scenarios ? [...scenarios].sort((a, b) => (a.id === "S2" ? -1 : b.id === "S2" ? 1 : a.id.localeCompare(b.id))) : null;
  return (
    <Panel title="Scenario explorer" subtitle="Launch any scenario with the shield off or on — same agent, same tools, same data." icon={<IconShield size={16} />}>
      {!ordered ? (
        <p className="flex items-center gap-2 text-sm text-slate-400">
          <Spinner /> Loading scenarios…
        </p>
      ) : (
        <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
          {ordered.map((s) => (
            <ScenarioCard key={s.id} s={s} featured={s.id === "S2"} onLaunch={(mode) => onStart(s.id, mode)} />
          ))}
        </div>
      )}
    </Panel>
  );
}
