import { useEffect, useState } from "react";
import { api, ApiError } from "./api";
import { IconAlert, IconArrowRight, IconCheck, IconCompare, IconFile, IconMail, IconPlay, IconShieldCheck, IconShieldOff, ToolIcon } from "./icons";
import { metaFor } from "./scenarioMeta";
import type { SuiteResult, SuiteSide } from "./types";
import { Badge, Button, cx, DecisionChip, Empty, ErrorNote, Panel, Spinner, Stat, VerdictBadge } from "./ui";

// Shield OFF vs ON comparison (POST /api/suite). The server runs every scenario in both modes with the deterministic
// scripted runner; everything shown here is taken from that response.

function Consequences({ s }: { s: SuiteSide }) {
  const deleted = s.protectedFiles.filter((f) => !f.present);
  return (
    <ul className="space-y-1.5 text-sm">
      <li className="flex items-center gap-2 text-slate-300">
        <IconMail size={15} className={s.outbox.external > 0 ? "text-rose-300" : "text-slate-500"} />
        {s.outbox.total} email{s.outbox.total === 1 ? "" : "s"} in outbox
        {s.outbox.external > 0 && <Badge tone="bad">{s.outbox.external} to external recipients</Badge>}
      </li>
      {s.protectedFiles.length > 0 && (
        <li className="flex items-center gap-2 text-slate-300">
          <IconFile size={15} className={deleted.length > 0 ? "text-rose-300" : "text-slate-500"} />
          {deleted.length > 0 ? <Badge tone="bad">{deleted.length} protected file(s) deleted</Badge> : <span>protected files intact</span>}
        </li>
      )}
      {s.approvals.map((a, i) => (
        <li key={i} className="flex flex-wrap items-center gap-2 text-slate-400">
          <Badge tone="warn">scripted {a.action}</Badge> {a.tool} → {a.result ?? "—"} {a.executed ? "· executed" : "· not executed"}
        </li>
      ))}
    </ul>
  );
}

function SideCard({ s, mode }: { s: SuiteSide; mode: "on" | "off" }) {
  const off = mode === "off";
  const succeeded = s.attack.applicable && s.attack.result === true;
  return (
    <div
      className={cx(
        "flex h-full flex-col rounded-xl border p-4",
        succeeded ? "border-rose-400/40 bg-rose-500/[0.06]" : s.attack.applicable ? "border-emerald-400/30 bg-emerald-400/[0.04]" : "border-line bg-ink-950/40",
      )}
    >
      <div className="flex flex-wrap items-center justify-between gap-2">
        <span className={cx("inline-flex items-center gap-1.5 text-xs font-semibold uppercase tracking-[0.12em]", off ? "text-rose-300" : "text-emerald-300")}>
          {off ? <IconShieldOff size={14} /> : <IconShieldCheck size={14} />} Shield {mode.toUpperCase()}
        </span>
        <VerdictBadge kind="attack" applicable={s.attack.applicable} result={s.attack.result} />
      </div>
      <div className="mt-3">
        <p className="text-xs font-semibold uppercase tracking-[0.12em] text-slate-500">{off ? "Policy" : "Blocked by policy"}</p>
        {s.denied.length === 0 ? (
          <p className="mt-1 text-sm text-slate-400">{off ? "Permissive — no enforcement (structural checks only)" : "No calls needed blocking"}</p>
        ) : (
          <ul className="mt-1.5 flex flex-wrap gap-1.5">
            {s.denied.map((d, i) => (
              <li key={i} className="inline-flex items-center gap-1.5 rounded-lg bg-ink-950/60 px-2 py-1 ring-1 ring-white/10">
                <ToolIcon tool={d.tool} size={14} />
                <code className="text-xs text-slate-200">{d.tool}</code>
                <DecisionChip decision="DENY" ruleId={d.ruleId} />
              </li>
            ))}
          </ul>
        )}
      </div>
      <div className="mt-3">
        <p className="text-xs font-semibold uppercase tracking-[0.12em] text-slate-500">Consequences (sandbox)</p>
        <div className="mt-1.5">
          <Consequences s={s} />
        </div>
      </div>
      <div className="mt-auto flex flex-wrap items-center gap-2 pt-3 text-xs text-slate-400">
        Legitimate task <VerdictBadge kind="legit" applicable={s.legitimate.applicable} result={s.legitimate.result} />
        {s.expectationsMet ? <Badge tone="good">Expected</Badge> : <Badge tone="warn">Unexpected</Badge>}
      </div>
    </div>
  );
}

export function SuitePage() {
  const [result, setResult] = useState<SuiteResult | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [elapsed, setElapsed] = useState(0);

  useEffect(() => {
    if (!busy) return;
    const t0 = Date.now();
    const t = setInterval(() => setElapsed(Math.floor((Date.now() - t0) / 100) / 10), 100);
    return () => clearInterval(t);
  }, [busy]);

  const run = async () => {
    setBusy(true);
    setError(null);
    setElapsed(0);
    try {
      setResult(await api.suite());
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Suite failed");
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="space-y-6">
      <section className="relative overflow-hidden rounded-3xl border border-line bg-gradient-to-br from-ink-850 via-ink-900 to-ink-950 px-6 py-8 sm:px-10">
        <div className="pointer-events-none absolute -left-24 -top-24 h-72 w-72 rounded-full bg-rose-500/10 blur-3xl" aria-hidden />
        <div className="pointer-events-none absolute -right-24 -bottom-24 h-72 w-72 rounded-full bg-emerald-400/10 blur-3xl" aria-hidden />
        <div className="relative flex flex-wrap items-center justify-between gap-6">
          <div className="max-w-2xl">
            <p className="inline-flex items-center gap-2 text-xs font-semibold uppercase tracking-[0.16em] text-cyan-300">
              <IconCompare size={14} /> Shield OFF vs Shield ON
            </p>
            <h1 className="mt-2 text-3xl font-semibold tracking-tight text-white">The same agent. The same attacks. One difference.</h1>
            <p className="mt-3 text-base text-slate-300">
              Every scenario runs twice — with a permissive policy and with AgentShield enforcing — using the same agent, tools and synthetic
              data. Verdicts come from what actually happened in each sandbox, not from what the agent says.
            </p>
          </div>
          <Button size="lg" onClick={run} busy={busy}>
            <IconPlay size={18} /> {result ? "Run the suite again" : "Run the full suite (10 runs)"}
          </Button>
        </div>
        {busy && (
          <div className="relative mt-6" role="status" aria-live="polite">
            <div className="h-1.5 overflow-hidden rounded-full bg-white/10">
              <div className="h-full w-1/3 animate-indeterminate rounded-full bg-gradient-to-r from-cyan-400 to-blue-500" />
            </div>
            <p className="mt-2 flex items-center gap-2 text-sm text-slate-400">
              <Spinner /> Running 5 scenarios × 2 modes on the server… {elapsed.toFixed(1)} s
            </p>
          </div>
        )}
      </section>

      <ErrorNote error={error} />

      {!result && !busy && (
        <Empty icon={<IconCompare />} title="No comparison yet">
          Run the suite to see, scenario by scenario, which attacks succeed without the shield and which policy rule stops them with it.
        </Empty>
      )}

      {result && (
        <>
          <section aria-label="Suite summary" className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
            <Stat label="Attacks succeeded · Shield OFF" value={result.totals.attacksSucceededOff} tone="bad" icon={<IconShieldOff size={18} />} hint="Real effects in the sandbox" />
            <Stat
              label="Attacks succeeded · Shield ON"
              value={result.totals.attacksSucceededOn}
              tone={result.totals.attacksSucceededOn === 0 ? "good" : "bad"}
              icon={<IconShieldCheck size={18} />}
              hint="Same attacks, policy enforced"
            />
            <Stat
              label="Expected outcomes"
              value={`${result.totals.expectationsMet}/${result.totals.runs}`}
              tone={result.totals.expectationsMet === result.totals.runs ? "good" : "warn"}
              icon={<IconCheck size={18} />}
              hint="Matched the catalogued expectation"
            />
            <Stat label="Runs executed" value={result.totals.runs} icon={<IconPlay size={18} />} hint={`Finished ${new Date(result.generatedAt).toLocaleTimeString()}`} />
          </section>

          <div className="space-y-4">
            {result.scenarios.map((s) => {
              const m = metaFor(s.category);
              return (
                <Panel key={s.id} padded={false}>
                  <div className="grid gap-4 p-5 lg:grid-cols-[minmax(0,280px)_1fr_auto_1fr] lg:items-stretch">
                    <div className="flex items-start gap-3">
                      <span className={cx("grid h-11 w-11 shrink-0 place-items-center rounded-xl ring-1 ring-inset", m.accent)}>{m.icon(20)}</span>
                      <div>
                        <div className="flex items-center gap-2">
                          <Badge tone="brand" className="font-mono">
                            {s.id}
                          </Badge>
                          <span className="text-xs font-semibold uppercase tracking-[0.12em] text-slate-400">{m.label}</span>
                        </div>
                        <p className="mt-1.5 font-semibold text-slate-100">{s.title}</p>
                        <p className="mt-1 text-sm text-slate-400">{s.on.attack.check}</p>
                      </div>
                    </div>
                    <SideCard s={s.off} mode="off" />
                    <div className="hidden items-center text-slate-600 lg:flex" aria-hidden>
                      <IconArrowRight size={22} />
                    </div>
                    <SideCard s={s.on} mode="on" />
                  </div>
                </Panel>
              );
            })}
          </div>

          <p className="flex items-start gap-2 text-sm text-slate-500">
            <IconAlert size={16} className="mt-0.5 shrink-0" /> {result.note}
          </p>
        </>
      )}
    </div>
  );
}
