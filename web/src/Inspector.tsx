import { useEffect, useState } from "react";
import { api } from "./api";
import { IconAlert, IconArrowRight, IconBug, IconGlobe, IconInbox, IconFile, IconUser, ToolIcon } from "./icons";
import { LevelBadge, SourceAssessmentPanel } from "./Assessment";
import { matchDecision } from "./runUtil";
import { IntegrityBadge, SourceChips } from "./provenance";
import type { InspectorSource, Run, RunContent, Step } from "./types";
import { Badge, cx, DecisionChip, Empty, Panel, Spinner } from "./ui";

// Untrusted Content Inspector: what the untrusted content actually says, how the deterministic agent interpreted it,
// which tool requests resulted, and what the policy engine decided. All text is rendered as React text — HTML is shown
// as inert source/preview, never executed.

/** `version` changes as the run progresses (state, step count), so the per-run enforcement outcome stays current. */
export function useRunContent(runId: string | null, version = "") {
  const [content, setContent] = useState<RunContent | null>(null);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => setContent(null), [runId]);
  useEffect(() => {
    if (!runId) return;
    let stop = false;
    api
      .content(runId)
      .then((c) => !stop && setContent(c))
      .catch((e) => !stop && setError(e instanceof Error ? e.message : String(e)));
    return () => {
      stop = true;
    };
  }, [runId, version]);
  return { content, error };
}

const SIGNAL_TONE: Record<string, "bad" | "warn"> = { "instruction override": "bad", concealment: "bad", "authority claim": "warn", urgency: "warn" };
const CATEGORY_TONE: Record<string, "bad" | "warn" | "neutral"> = {
  "sensitive-data access": "bad",
  "external disclosure": "bad",
  "destructive action": "bad",
  "file read": "neutral",
};

function SourceIcon({ type }: { type: InspectorSource["type"] }) {
  return type === "web" ? <IconGlobe size={18} /> : type === "email" ? <IconInbox size={18} /> : <IconFile size={18} />;
}

/** Highlight the evidence sentences inside the inert preview text. */
function HighlightedPreview({ text, evidence }: { text: string; evidence: string[] }) {
  const marks = evidence.map((e) => e.replace(/…$/, "")).filter((e) => e.length > 8 && text.includes(e));
  if (marks.length === 0) return <>{text}</>;
  const parts: { t: string; hit: boolean }[] = [];
  let rest = text;
  while (rest.length > 0) {
    let best: { i: number; m: string } | null = null;
    for (const m of marks) {
      const i = rest.indexOf(m);
      if (i >= 0 && (!best || i < best.i)) best = { i, m };
    }
    if (!best) {
      parts.push({ t: rest, hit: false });
      break;
    }
    if (best.i > 0) parts.push({ t: rest.slice(0, best.i), hit: false });
    parts.push({ t: best.m, hit: true });
    rest = rest.slice(best.i + best.m.length);
  }
  return (
    <>
      {parts.map((p, i) =>
        p.hit ? (
          <mark key={i} className="rounded bg-rose-500/20 px-0.5 text-rose-100 ring-1 ring-rose-400/40">
            {p.t}
          </mark>
        ) : (
          <span key={i}>{p.t}</span>
        ),
      )}
    </>
  );
}

function SourceInspector({ source, run }: { source: InspectorSource; run: Run | null }) {
  // Link recognised actions to the agent's injected steps from this source, in order, per tool.
  const used = new Set<Step>();
  const stepFor = (tool: string): Step | null => {
    if (!run) return null;
    const s = run.steps.find((x) => x.origin === "injected" && x.source === source.label && x.tool === tool && !used.has(x));
    if (s) used.add(s);
    return s ?? null;
  };
  const evidence = source.instructions.filter((i) => i.recognized.length > 0 || i.signals.length > 0).map((i) => i.evidence);
  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-2">
        <span className="grid h-9 w-9 place-items-center rounded-xl bg-rose-500/10 text-rose-300 ring-1 ring-rose-400/25">
          <SourceIcon type={source.type} />
        </span>
        <div className="min-w-0">
          <p className="truncate text-[15px] font-semibold text-slate-100">{source.title}</p>
          <div className="mt-0.5 flex flex-wrap items-center gap-2 text-xs text-slate-400">
            <span className="uppercase tracking-[0.12em]">{source.type === "web" ? "Web page" : source.type === "email" ? "Email" : "Document"}</span>
            {source.from && <span>from {source.from}</span>}
            <SourceChips sources={[source.label]} />
          </div>
        </div>
        <span className="ml-auto">
          <IntegrityBadge integrity={source.assessment.sourceTrust === "TRUSTED" ? "TRUSTED" : "UNTRUSTED"} />
        </span>
      </div>

      <SourceAssessmentPanel source={source} />

      <div className="grid gap-4 xl:grid-cols-2">
        <div>
          <p className="text-xs font-semibold uppercase tracking-[0.12em] text-slate-400">Untrusted content · inert text preview</p>
          <div className="mt-2 max-h-80 overflow-auto whitespace-pre-wrap break-words rounded-xl border border-rose-400/20 bg-ink-950/70 p-4 font-mono text-[13px] leading-relaxed text-slate-300">
            {source.preview ? <HighlightedPreview text={source.preview} evidence={evidence} /> : <span className="text-slate-500">(no text content)</span>}
          </div>
          {source.previewTruncated && <p className="mt-1 text-xs text-slate-500">Preview truncated.</p>}
        </div>

        <div>
          <p className="text-xs font-semibold uppercase tracking-[0.12em] text-slate-400">Agent's interpretation → tool request → policy decision</p>
          {source.instructions.length === 0 ? (
            <div className="mt-2">
              <Empty title="No instructions recognised">The deterministic agent found nothing in this content it would act on.</Empty>
            </div>
          ) : (
            <ol className="mt-2 space-y-3">
              {source.instructions.map((ins, i) => (
                <li key={i} className="rounded-xl border border-line bg-ink-950/50 p-3">
                  <p className="text-sm text-slate-200">“{ins.evidence}”</p>
                  {ins.signals.length > 0 && (
                    <div className="mt-2 flex flex-wrap gap-1.5">
                      {ins.signals.map((s) => (
                        <Badge key={s} tone={SIGNAL_TONE[s] ?? "warn"}>
                          <IconAlert size={12} /> {s}
                        </Badge>
                      ))}
                    </div>
                  )}
                  {ins.recognized.map((r, j) => {
                    const step = stepFor(r.tool);
                    const d = step && run ? matchDecision(run, step) : undefined;
                    return (
                      <div key={j} className="mt-2 flex flex-wrap items-center gap-2 rounded-lg bg-white/[0.03] px-2.5 py-2 ring-1 ring-white/10">
                        <Badge tone={CATEGORY_TONE[r.category] ?? "neutral"}>{r.category}</Badge>
                        <IconArrowRight size={14} className="text-slate-600" />
                        <span className="inline-flex items-center gap-1.5 font-mono text-sm text-slate-100">
                          <ToolIcon tool={r.tool} size={14} /> {r.tool}
                          <span className="text-slate-400">({r.target})</span>
                        </span>
                        <IconArrowRight size={14} className="text-slate-600" />
                        {!run ? (
                          <span className="text-xs text-slate-500">decision appears in the run</span>
                        ) : step ? (
                          <DecisionChip decision={d?.decision ?? (step.status === "ok" ? "ALLOW" : null)} ruleId={step.ruleId} />
                        ) : (
                          <span className="text-xs text-slate-500">{run.state === "running" || run.state === "created" ? "not reached yet" : "not attempted (duplicate or limit)"}</span>
                        )}
                      </div>
                    );
                  })}
                  {ins.unsupported.map((u, j) => (
                    <p key={j} className="mt-2 text-xs text-slate-400">
                      <Badge>unsupported</Badge> {u.tool}: {u.reason} — nothing is executed for it.
                    </p>
                  ))}
                </li>
              ))}
            </ol>
          )}
        </div>
      </div>
    </div>
  );
}

export function ContentInspector({ content, run, compact }: { content: RunContent | null; run: Run | null; compact?: boolean }) {
  if (!content)
    return (
      <Panel title="Untrusted Content Inspector" icon={<IconBug size={16} />}>
        <p className="flex items-center gap-2 text-sm text-slate-400">
          <Spinner /> Loading content…
        </p>
      </Panel>
    );
  return (
    <Panel
      title="Untrusted Content Inspector"
      subtitle="What the untrusted input actually says, how the agent read it, and what the policy engine decided"
      icon={<IconBug size={16} />}
    >
      <div className="space-y-5">
        <div className={cx("grid gap-3", !compact && "md:grid-cols-[1fr_1fr]")}>
          <div className="rounded-xl border border-emerald-400/25 bg-emerald-400/[0.05] p-3">
            <p className="flex items-center gap-2 text-xs font-semibold uppercase tracking-[0.12em] text-emerald-300">
              <IconUser size={14} /> User's task · TRUSTED
            </p>
            <p className="mt-1 text-sm text-slate-100">“{content.task}”</p>
          </div>
          <div className="rounded-xl border border-line bg-ink-950/50 p-3">
            <p className="text-xs font-semibold uppercase tracking-[0.12em] text-slate-400">Agent's plan for the task (deterministic)</p>
            <ol className="mt-1 list-inside list-decimal text-sm text-slate-300">
              {content.plan.map((p) => (
                <li key={p}>{p}</li>
              ))}
            </ol>
          </div>
        </div>
        {content.sources.length === 0 ? (
          <Empty title="No untrusted content captured">This scenario reads only the user's own task data (task files are never shown here).</Empty>
        ) : (
          content.sources.map((s) => <SourceInspector key={s.label} source={s} run={run} />)
        )}
        {content.outgoing.length > 0 && (
          <div className="rounded-xl border border-line bg-ink-950/40 p-3">
            <p className="text-xs font-semibold uppercase tracking-[0.12em] text-slate-400">Outgoing emails · content check (advisory; text not shown)</p>
            <ul className="mt-2 space-y-1.5">
              {content.outgoing.map((o) => (
                <li key={o.seq} className="flex flex-wrap items-center gap-2 text-sm text-slate-300">
                  <DecisionChip decision={o.decision} ruleId={o.ruleId} />
                  <span>{o.recipient === "requesting_user" ? "to the requesting user" : o.recipient === "external" ? "to an external recipient" : "recipient unknown"}</span>
                  <LevelBadge level={o.level} label="embedded instructions" />
                  <span className="text-xs text-slate-500">{o.note}</span>
                </li>
              ))}
            </ul>
          </div>
        )}
      </div>
    </Panel>
  );
}
