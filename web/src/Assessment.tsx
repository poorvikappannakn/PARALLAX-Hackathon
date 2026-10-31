import { IconAlert, IconGlobe, IconShield } from "./icons";
import type { Enforcement, InspectorSource, OutgoingContent, SecurityAlert, ThreatLevel, UrlFinding } from "./types";
import { Badge, cx, type Tone } from "./ui";

// Security assessment views. Source trust, instruction threat and URL threat are shown as three SEPARATE classifications,
// exactly as computed by the backend analyzers. They are advisory: every tool request is still decided by the PEP.

export const LEVEL_TONE: Record<ThreatLevel, Tone> = { LOW: "good", MEDIUM: "warn", HIGH: "bad", UNKNOWN: "neutral" };
const TRUST_TONE = { TRUSTED: "good", UNTRUSTED: "warn", UNKNOWN: "neutral" } as const;

export function LevelBadge({ level, label }: { level: ThreatLevel; label?: string }) {
  return (
    <Badge tone={LEVEL_TONE[level]}>
      {label ? `${label}: ` : ""}
      {level}
    </Badge>
  );
}

/** What actually happened to the requests this content caused, in this run — from real step outcomes. */
export function EnforcementBlock({ e }: { e: Enforcement }) {
  const row = (label: string, tone: "bad" | "good" | "warn", xs: Enforcement["executed"]) =>
    xs.length > 0 && (
      <div className="flex flex-wrap items-center gap-1.5">
        <span className="w-24 text-xs uppercase tracking-[0.12em] text-slate-400">{label}</span>
        {xs.map((x, i) => (
          <Badge key={i} tone={tone}>
            {x.tool}
            {x.ruleId && x.ruleId !== "OFF" ? ` · ${x.ruleId}` : ""}
          </Badge>
        ))}
      </div>
    );
  return (
    <div className="space-y-1.5" data-testid="enforcement">
      <div className="flex flex-wrap items-center gap-2">
        <Badge tone={e.mode === "on" ? "good" : "bad"}>{e.mode === "on" ? "Shield ON" : "Shield OFF — no enforcement"}</Badge>
        <span className="text-sm text-slate-200">{e.statement}</span>
      </div>
      {row("Executed", e.mode === "off" ? "bad" : "warn", e.executed)}
      {row("Denied", "good", e.denied)}
      {row("Awaiting", "warn", e.pending)}
    </div>
  );
}

export function OutgoingNote({ outgoing }: { outgoing: OutgoingContent }) {
  const flagged = outgoing.level === "HIGH" || outgoing.level === "MEDIUM";
  return (
    <div className={cx("rounded-xl border p-3 text-sm", flagged ? "border-amber-400/40 bg-amber-400/[0.06]" : "border-line bg-white/[0.02]")}>
      <p className="flex flex-wrap items-center gap-2 font-semibold text-slate-100">
        <IconShield size={15} /> Outgoing content check <LevelBadge level={outgoing.level} />
        {outgoing.categories.map((c) => (
          <Badge key={c}>{c.replace(/-/g, " ")}</Badge>
        ))}
      </p>
      <p className="mt-1 text-xs text-slate-400">{outgoing.note} Advisory only — it does not change the policy decision.</p>
    </div>
  );
}

export function AlertCard({ alert, enforcement }: { alert: SecurityAlert; enforcement: Enforcement | null }) {
  const high = alert.level === "HIGH";
  return (
    <div role="alert" className={cx("rounded-xl border p-4", high ? "border-rose-400/40 bg-rose-500/[0.07]" : "border-amber-400/40 bg-amber-400/[0.06]")}>
      <p className={cx("flex items-center gap-2 text-sm font-semibold", high ? "text-rose-200" : "text-amber-200")}>
        <IconAlert size={16} /> {high ? "High-risk content detected" : "Suspicious content detected"} · {alert.detected}
      </p>
      <dl className="mt-3 grid gap-x-6 gap-y-2 text-sm md:grid-cols-2">
        <div>
          <dt className="text-xs uppercase tracking-[0.12em] text-slate-400">Origin</dt>
          <dd className="break-all font-mono text-slate-200">{alert.origin}</dd>
        </div>
        <div>
          <dt className="text-xs uppercase tracking-[0.12em] text-slate-400">Potential impact</dt>
          <dd className="text-slate-200">{alert.potentialImpact}</dd>
        </div>
        {alert.attemptedActions.length > 0 && (
          <div className="md:col-span-2">
            <dt className="text-xs uppercase tracking-[0.12em] text-slate-400">What it tried to make the agent do</dt>
            <dd className="text-slate-200">{alert.attemptedActions.join("; ")}</dd>
          </div>
        )}
        <div className="md:col-span-2">
          <dt className="text-xs uppercase tracking-[0.12em] text-slate-400">Why it is suspicious</dt>
          <dd>
            <ul className="list-inside list-disc text-slate-300">
              {alert.why.map((w) => (
                <li key={w}>{w}</li>
              ))}
            </ul>
          </dd>
        </div>
        <div className="md:col-span-2">
          <dt className="text-xs uppercase tracking-[0.12em] text-slate-400">What actually happened in this run</dt>
          <dd className="mt-1">{enforcement ? <EnforcementBlock e={enforcement} /> : <span className="text-slate-500">Run outcome unavailable.</span>}</dd>
        </div>
        <div className="md:col-span-2">
          <dt className="text-xs uppercase tracking-[0.12em] text-slate-400">Content handling</dt>
          <dd className="text-slate-300">{alert.contentHandling}</dd>
        </div>
      </dl>
    </div>
  );
}

function UrlRow({ u }: { u: UrlFinding }) {
  return (
    <li className="rounded-lg bg-white/[0.03] p-2.5 ring-1 ring-white/10">
      <div className="flex flex-wrap items-center gap-2">
        <LevelBadge level={u.risk} label="URL risk" />
        <span className="break-all font-mono text-sm text-slate-100">{u.hostname ?? u.url}</span>
        {u.unicodeHostname && <span className="text-xs text-slate-400">displayed as “{u.unicodeHostname}”</span>}
        {u.score !== null && <span className="text-xs text-slate-500">score {u.score}</span>}
        <span className="text-xs text-slate-500">confidence {u.confidence} · reputation {u.reputation}</span>
      </div>
      <p className="mt-1 text-xs text-slate-400">{u.summary}</p>
      {u.indicators.length > 0 && (
        <ul className="mt-1 list-inside list-disc text-xs text-slate-300">
          {u.indicators.map((i) => (
            <li key={i.id}>{i.reason}</li>
          ))}
        </ul>
      )}
    </li>
  );
}

/** The three separate classifications of one source, plus the per-sentence evidence and the URL analysis. */
export function SourceAssessmentPanel({ source }: { source: InspectorSource }) {
  const a = source.assessment;
  const t = a.instructionThreat;
  return (
    <div className="space-y-3 rounded-xl border border-line bg-ink-950/40 p-3">
      <p className="flex items-center gap-2 text-xs font-semibold uppercase tracking-[0.12em] text-slate-400">
        <IconShield size={14} /> Security assessment (advisory — the PEP decides every tool call)
      </p>
      <div className="flex flex-wrap gap-2">
        <Badge tone={TRUST_TONE[a.sourceTrust]}>Source trust: {a.sourceTrust}</Badge>
        <LevelBadge level={t.level} label="Instruction threat" />
        {a.urlRisk !== null && <LevelBadge level={a.urlRisk} label="URL risk" />}
        {t.score !== null && <span className="self-center text-xs text-slate-500">evidence score {t.score} · confidence {t.confidence}</span>}
      </div>
      <p className="text-sm text-slate-300">
        {t.summary} <span className="text-slate-500">{t.counts.information} informational and {t.counts.instruction} instruction-like sentence(s).</span>
      </p>
      {t.uncertainty && <p className="text-xs text-slate-500">{t.uncertainty}</p>}
      {a.alert ? <AlertCard alert={a.alert} enforcement={source.enforcement} /> : source.enforcement && source.enforcement.requested > 0 && <EnforcementBlock e={source.enforcement} />}
      {t.sentences.some((s) => s.findings.length > 0) && (
        <ul className="space-y-2">
          {t.sentences
            .filter((s) => s.findings.length > 0)
            .map((s, i) => (
              <li key={i} className="rounded-lg bg-white/[0.03] p-2.5 ring-1 ring-white/10">
                <div className="flex flex-wrap items-center gap-2">
                  <LevelBadge level={s.level} />
                  <Badge>{s.role.replace(/-/g, " ")}</Badge>
                  {s.decoded && <Badge tone="warn">decoded from hidden encoding</Badge>}
                  {s.conflictsWithObjective && <Badge tone="warn">conflicts with the user's task</Badge>}
                </div>
                <p className="mt-1 text-sm text-slate-200">“{s.evidence}”</p>
                <ul className="mt-1 list-inside list-disc text-xs text-slate-400">
                  {s.findings.map((f) => (
                    <li key={f.category}>{f.reason}</li>
                  ))}
                </ul>
              </li>
            ))}
        </ul>
      )}
      {a.urls.length > 0 && (
        <div>
          <p className="flex items-center gap-2 text-xs font-semibold uppercase tracking-[0.12em] text-slate-400">
            <IconGlobe size={14} /> URL analysis (links are never visited)
          </p>
          <p className="mt-1 text-xs text-slate-500">
            URL risk is an advisory classification of each link, not a policy decision. "Allowed"/"Denied" elsewhere refer only to the agent's tool calls.
          </p>
          <ul className="mt-2 space-y-2">
            {a.urls.map((u) => (
              <UrlRow key={u.url} u={u} />
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}
