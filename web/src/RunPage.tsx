import { useCallback, useEffect, useRef, useState } from "react";
import { api, ApiError } from "./api";
import {
  IconActivity,
  IconAlert,
  IconArrowRight,
  IconBug,
  IconCheck,
  IconClock,
  IconDatabase,
  IconFile,
  IconHand,
  IconLayers,
  IconList,
  IconMail,
  IconShield,
  IconShieldCheck,
  IconX,
  ToolIcon,
} from "./icons";
import { ContentInspector, useRunContent } from "./Inspector";
import { ArgumentProvenance, LabelInline, ProvenanceLegend, SourceChips } from "./provenance";
import { isLabRun, matchDecision } from "./runUtil";
import type { AuditEvent, Decision, PendingApproval, Run, Step } from "./types";
import { Badge, Button, cx, DecisionChip, decisionKind, Empty, ErrorNote, fmtTime, ModeBadge, Panel, Spinner, STATE_LABEL, statusTone, VerdictBadge } from "./ui";

// Live run view. The server executes the run one gateway call at a time; this page follows it over SSE
// (GET /api/runs/:id/events) and renders only the sanitised projections the API sends.

type Live = { run: Run | null; connected: boolean; finished: boolean; error: string | null };

export function useRunStream(runId: string | null) {
  const [live, setLive] = useState<Live>({ run: null, connected: false, finished: false, error: null });

  useEffect(() => {
    if (!runId) return;
    let closed = false;
    const es = new EventSource(`/api/runs/${runId}/events`);
    const update = (fn: (r: Run) => Run) => setLive((l) => (l.run ? { ...l, run: fn(l.run) } : l));
    const on = (name: string, fn: (data: any) => void) => es.addEventListener(name, (e) => fn(JSON.parse((e as MessageEvent).data)));

    es.onopen = () => setLive((l) => ({ ...l, connected: true, error: null }));
    es.onerror = () => {
      if (closed) return;
      setLive((l) => ({ ...l, connected: false }));
      // On network errors EventSource reconnects by itself (sending Last-Event-ID). A non-200 answer (404: the run is no
      // longer held by the API, 401: signed out) closes it for good — ask the REST endpoint why and show that.
      if (es.readyState === EventSource.CLOSED) {
        api.run(runId).then(
          (run) => setLive((l) => ({ ...l, run, finished: true })),
          (e) =>
            setLive((l) => ({
              ...l,
              error:
                e instanceof ApiError && e.status === 404
                  ? "This run is no longer held by the API (runs are kept in memory and cleared when the API restarts)."
                  : e instanceof Error
                    ? e.message
                    : String(e),
            })),
        );
      }
    };
    on("snapshot", (d: { run: Run }) => setLive((l) => ({ ...l, run: d.run })));
    on("step", (s: Step) => update((r) => ({ ...r, steps: [...r.steps.filter((x) => x.step !== s.step || x.call !== s.call), s] })));
    on("decision", (d: Decision) => update((r) => ({ ...r, decisions: [...r.decisions.filter((x) => x.seq !== d.seq), d] })));
    on("audit", (a: AuditEvent) => update((r) => ({ ...r, audit: [...r.audit.filter((x) => x.seq !== a.seq), a] })));
    on("state", (s: { state: string }) => update((r) => ({ ...r, state: s.state })));
    const finish = (d: { run: Run | null }) => {
      closed = true;
      es.close();
      setLive((l) => ({ ...l, run: d.run ?? l.run, finished: true, connected: false }));
    };
    on("done", finish);
    on("failed", finish);
    return () => {
      closed = true;
      es.close();
    };
  }, [runId]);

  const refresh = useCallback(async () => {
    if (!runId) return;
    try {
      const run = await api.run(runId);
      setLive((l) => ({ ...l, run }));
    } catch (e) {
      setLive((l) => ({ ...l, error: e instanceof Error ? e.message : String(e) }));
    }
  }, [runId]);

  return { ...live, refresh };
}


const STEP_LABEL: Record<string, string> = {
  ok: "Executed",
  denied: "Blocked",
  approval_required: "Paused for approval",
  approval_pending: "Awaiting decision",
  rejected: "Rejected before evaluation",
  tool_error: "Tool error",
  halted: "Halted",
};

// ---- header -------------------------------------------------------------------------------------------------------

function PhaseStepper({ run }: { run: Run }) {
  const needsApproval = run.steps.some((s) => s.status === "approval_required") || run.state === "waiting";
  const finished = !["created", "running", "waiting"].includes(run.state);
  const phases = [
    { key: "start", label: "Run started", done: true },
    { key: "exec", label: "Agent executing", done: run.steps.length > 0 && run.state !== "created", active: run.state === "running" || run.state === "created" },
    ...(needsApproval ? [{ key: "appr", label: "Human approval", done: run.approvals.length > 0 || (finished && run.state !== "waiting"), active: run.state === "waiting" }] : []),
    { key: "result", label: finished ? STATE_LABEL[run.state] ?? run.state : "Result", done: finished, failed: run.state === "halted" || run.state === "step_limit" },
  ];
  return (
    <ol className="flex flex-wrap items-center gap-2" aria-label="Run progress">
      {phases.map((p, i) => (
        <li key={p.key} className="flex items-center gap-2">
          <span
            className={cx(
              "inline-flex items-center gap-2 rounded-full px-3 py-1.5 text-sm font-medium ring-1 ring-inset",
              "failed" in p && p.failed && p.done
                ? "bg-rose-500/10 text-rose-200 ring-rose-400/30"
                : "active" in p && p.active
                  ? "bg-cyan-400/10 text-cyan-200 ring-cyan-400/40"
                  : p.done
                    ? "bg-emerald-400/10 text-emerald-200 ring-emerald-400/25"
                    : "bg-white/[0.03] text-slate-500 ring-white/10",
            )}
          >
            {"active" in p && p.active ? <Spinner className="h-3.5 w-3.5" /> : p.done ? <IconCheck size={14} /> : <IconClock size={14} />}
            {p.label}
          </span>
          {i < phases.length - 1 && <IconArrowRight size={14} className="text-slate-600" />}
        </li>
      ))}
    </ol>
  );
}

function AttackSummary({ run }: { run: Run }) {
  const injected = run.steps.filter((s) => s.origin === "injected");
  if (injected.length === 0) return null;
  const sources = [...new Set(injected.map((s) => s.source).filter(Boolean))] as string[];
  const blocked = injected.filter((s) => s.status === "denied" || s.status === "rejected").length;
  const executed = injected.filter((s) => s.status === "ok").length;
  return (
    <div className={cx("rounded-2xl border p-5", executed > 0 ? "border-rose-400/40 bg-rose-500/[0.07]" : "border-emerald-400/30 bg-emerald-400/[0.05]")}>
      <div className="flex flex-wrap items-start gap-4">
        <span className={cx("grid h-11 w-11 shrink-0 place-items-center rounded-xl", executed > 0 ? "bg-rose-500/15 text-rose-300" : "bg-emerald-400/15 text-emerald-300")}>
          {executed > 0 ? <IconBug size={22} /> : <IconShieldCheck size={22} />}
        </span>
        <div className="min-w-0 flex-1">
          <p className="text-xs font-semibold uppercase tracking-[0.14em] text-slate-400">Injected instructions detected in untrusted content</p>
          <p className="mt-1 text-lg font-semibold text-slate-100">
            {executed > 0
              ? `${executed} of ${injected.length} injected action${injected.length === 1 ? "" : "s"} executed — the agent obeyed the attacker`
              : `All ${blocked} injected action${blocked === 1 ? " was" : "s were"} blocked by policy`}
          </p>
          <div className="mt-2 flex flex-wrap items-center gap-2 text-sm text-slate-400">
            <span>Instructions came from</span>
            <SourceChips sources={sources} />
          </div>
          <ul className="mt-3 flex flex-wrap gap-2">
            {injected.map((s) => {
              const d = matchDecision(run, s);
              return (
                <li key={s.step} className="flex items-center gap-2 rounded-lg bg-ink-950/60 px-2.5 py-1.5 ring-1 ring-white/10">
                  <ToolIcon tool={s.tool} size={15} />
                  <code className="text-sm text-slate-200">{s.tool}</code>
                  <DecisionChip decision={d?.decision ?? (s.status === "ok" ? "ALLOW" : null)} ruleId={s.ruleId} />
                </li>
              );
            })}
          </ul>
        </div>
      </div>
    </div>
  );
}

// ---- approval -----------------------------------------------------------------------------------------------------

export function ApprovalPanel({ runId }: { runId: string }) {
  const [approval, setApproval] = useState<PendingApproval | null>(null);
  const [busy, setBusy] = useState<"approve" | "reject" | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [decided, setDecided] = useState<"approve" | "reject" | null>(null);
  const [now, setNow] = useState(Date.now());

  useEffect(() => {
    let stop = false;
    const load = () =>
      api
        .approvals()
        .then((list) => !stop && setApproval(list.find((a) => a.runId === runId) ?? null))
        .catch(() => {});
    load();
    const t = setInterval(() => {
      setNow(Date.now());
      load();
    }, 1000);
    return () => {
      stop = true;
      clearInterval(t);
    };
  }, [runId]);

  if (decided && !approval) {
    return (
      <div role="status" className="flex items-center gap-3 rounded-2xl border border-cyan-400/30 bg-cyan-400/[0.06] px-5 py-4 text-sm text-cyan-100 animate-fade-in">
        <Spinner /> Decision recorded ({decided}). The policy engine is re-evaluating the exact call and the same run is resuming…
      </div>
    );
  }
  if (!approval) return null;
  const secondsLeft = Math.max(0, Math.round((approval.expiresAt - now) / 1000));
  const untrusted = approval.arguments.filter((a) => a.integrity !== "TRUSTED").length;

  const decide = async (verdict: "approve" | "reject") => {
    setBusy(verdict);
    setError(null);
    try {
      await api.decide(approval.approvalId, verdict);
      setDecided(verdict);
      setApproval(null);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Decision failed");
    } finally {
      setBusy(null);
    }
  };

  return (
    <section aria-live="polite" aria-label="Human approval required" className="overflow-hidden rounded-2xl border border-amber-400/40 bg-ink-900 shadow-[0_20px_60px_-30px_rgb(251_191_36/0.5)] animate-fade-in">
      <div className="flex flex-wrap items-center justify-between gap-4 border-b border-amber-400/20 bg-gradient-to-r from-amber-400/[0.12] to-transparent px-5 py-4">
        <div className="flex items-center gap-3">
          <span className="grid h-11 w-11 place-items-center rounded-xl bg-amber-400/15 text-amber-300 animate-pulse-ring">
            <IconHand size={22} />
          </span>
          <div>
            <p className="text-xs font-semibold uppercase tracking-[0.14em] text-amber-300">Human approval required</p>
            <p className="text-lg font-semibold text-slate-50">
              The agent wants to run <code className="rounded-md bg-amber-400/10 px-1.5 py-0.5 font-mono text-amber-200">{approval.tool}</code>
            </p>
          </div>
        </div>
        <div className="flex items-center gap-3">
          <span className={cx("inline-flex items-center gap-1.5 text-sm tabular-nums", secondsLeft < 60 ? "text-rose-300" : "text-slate-400")}>
            <IconClock size={15} /> expires in {Math.floor(secondsLeft / 60)}:{String(secondsLeft % 60).padStart(2, "0")}
          </span>
          <Button variant="danger" busy={busy === "reject"} disabled={busy !== null} onClick={() => decide("reject")}>
            <IconX size={16} /> Reject
          </Button>
          <Button variant="good" busy={busy === "approve"} disabled={busy !== null} onClick={() => decide("approve")}>
            <IconCheck size={16} /> Approve
          </Button>
        </div>
      </div>
      <div className="grid gap-6 p-5 lg:grid-cols-[1fr_1.2fr]">
        <div className="space-y-4">
          <div>
            <p className="text-xs font-semibold uppercase tracking-[0.12em] text-slate-400">Policy decision</p>
            <div className="mt-2 flex flex-wrap items-center gap-2">
              <DecisionChip decision="REQUIRE_APPROVAL" ruleId={approval.ruleId} />
              <Badge tone={approval.risk !== null && approval.risk >= 70 ? "bad" : "warn"}>risk {approval.risk ?? "—"} / 100</Badge>
              <Badge>{untrusted} untrusted argument{untrusted === 1 ? "" : "s"}</Badge>
            </div>
            <ul className="mt-3 space-y-1.5 text-sm text-slate-300">
              {approval.reasons.map((r) => (
                <li key={r} className="flex gap-2">
                  <span className="mt-2 h-1 w-1 shrink-0 rounded-full bg-amber-300" />
                  {r}
                </li>
              ))}
            </ul>
          </div>
          {approval.recipient && (
            <div className={cx("rounded-xl border p-3 text-sm", approval.recipient === "requesting_user" ? "border-emerald-400/25 bg-emerald-400/[0.06] text-emerald-100" : "border-rose-400/30 bg-rose-500/[0.08] text-rose-100")}>
              <p className="flex items-center gap-2 font-semibold">
                <IconMail size={16} />
                {approval.recipient === "requesting_user" ? "Recipient: the requesting user's own address" : "Recipient: an external address"}
              </p>
              <p className="mt-1 text-xs opacity-80">
                {approval.recipient === "requesting_user"
                  ? "Taken from the user's profile (TRUSTED) — not from anything the agent read."
                  : "The recipient is not the requesting user."}
              </p>
            </div>
          )}
          <p className="rounded-xl bg-white/[0.03] p-3 text-xs leading-relaxed text-slate-400 ring-1 ring-white/10">
            Approving lets the policy engine re-evaluate <b className="text-slate-200">this exact call</b> — same tool, arguments and their provenance,
            run, agent, user and policy version. DENY rules are checked again and can never be overridden. The approval is single-use and
            expires automatically.
          </p>
        </div>
        <div>
          <p className="text-xs font-semibold uppercase tracking-[0.12em] text-slate-400">Argument provenance · values are never shown</p>
          <div className="mt-2 rounded-xl border border-line bg-ink-950/50 px-4">
            <ArgumentProvenance args={approval.arguments} />
          </div>
          {approval.context && (
            <div className="mt-3 flex flex-wrap items-center gap-2 text-sm text-slate-400">
              <span>Run context when requested:</span>
              <LabelInline label={approval.context} />
            </div>
          )}
          <p className="mt-3 font-mono text-xs text-slate-500">approval {approval.approvalId}</p>
        </div>
      </div>
      {error && (
        <div className="px-5 pb-5">
          <ErrorNote error={error} />
        </div>
      )}
    </section>
  );
}

// ---- timeline -----------------------------------------------------------------------------------------------------

function StepCard({ run, step, last }: { run: Run; step: Step; last: boolean }) {
  const [open, setOpen] = useState(false);
  const d = matchDecision(run, step);
  const kind = decisionKind(d?.decision ?? (step.status === "ok" ? "ALLOW" : null));
  const injected = step.origin === "injected";
  const rail = kind === "DENY" || step.status === "rejected" ? "bg-rose-500" : kind === "REQUIRE_APPROVAL" ? "bg-amber-400" : kind === "ALLOW" ? "bg-emerald-400" : "bg-slate-500";
  return (
    <li className="relative pl-10 animate-fade-in">
      {!last && <span className="absolute left-[15px] top-9 h-[calc(100%-1.25rem)] w-px bg-line-strong" aria-hidden />}
      <span className={cx("absolute left-0 top-2 grid h-8 w-8 place-items-center rounded-full text-ink-950 ring-4 ring-ink-900", rail)}>
        <ToolIcon tool={step.tool} size={15} />
      </span>
      <div className={cx("rounded-xl border p-4", injected ? "border-rose-400/30 bg-rose-500/[0.05]" : "border-line bg-ink-950/40")}>
        <div className="flex flex-wrap items-center gap-2">
          <span className="font-mono text-xs text-slate-500">#{step.step}</span>
          <code className="font-mono text-[15px] font-semibold text-slate-50">{step.tool}</code>
          {injected ? (
            <Badge tone="bad">
              <IconBug size={12} /> Injected instruction
            </Badge>
          ) : (
            <Badge>Task step</Badge>
          )}
          {step.call === "resume" && (
            <Badge tone="brand">
              <IconActivity size={12} /> Resumed after approval
            </Badge>
          )}
          <span className="ml-auto flex items-center gap-2">
            <Badge tone={statusTone(step.status)}>{STEP_LABEL[step.status] ?? step.status}</Badge>
            {(d || step.ruleId) && <DecisionChip decision={d?.decision ?? null} ruleId={step.ruleId} />}
          </span>
        </div>
        {injected && step.source && (
          <p className="mt-2 flex flex-wrap items-center gap-2 text-sm text-rose-200/90">
            <IconAlert size={14} /> Hidden instruction found in <SourceChips sources={[step.source]} />
          </p>
        )}
        {d && d.reasons.length > 0 && <p className="mt-2 text-sm text-slate-300">{d.reasons[0]}</p>}
        {d && d.arguments.length > 0 && (
          <div className="mt-2">
            <button onClick={() => setOpen((o) => !o)} aria-expanded={open} className="text-sm font-medium text-cyan-300 hover:text-cyan-200">
              {open ? "Hide" : "Show"} provenance ({d.arguments.length} argument{d.arguments.length === 1 ? "" : "s"})
            </button>
            {open && (
              <div className="mt-2 rounded-lg border border-line bg-ink-950/60 px-3">
                <ArgumentProvenance args={d.arguments} />
              </div>
            )}
          </div>
        )}
      </div>
    </li>
  );
}

function Timeline({ run }: { run: Run }) {
  const running = run.state === "running" || run.state === "created";
  if (run.steps.length === 0)
    return (
      <Empty icon={<Spinner />} title="Waiting for the agent's first tool call">
        Each tool call appears here the moment the gateway decides it.
      </Empty>
    );
  return (
    <ol className="space-y-3" aria-live="polite">
      {run.steps.map((s, i) => (
        <StepCard key={`${s.call}-${s.step}`} run={run} step={s} last={i === run.steps.length - 1 && !running} />
      ))}
      {running && (
        <li className="relative flex items-center gap-3 pl-10 text-sm text-cyan-200">
          <span className="absolute left-0 grid h-8 w-8 place-items-center rounded-full bg-cyan-400/15 ring-4 ring-ink-900">
            <Spinner className="h-3.5 w-3.5" />
          </span>
          Agent is choosing its next action…
        </li>
      )}
    </ol>
  );
}

// ---- decisions and audit ------------------------------------------------------------------------------------------

function Decisions({ run }: { run: Run }) {
  if (run.decisions.length === 0) return <Empty icon={<IconShield />} title="No policy decisions yet" />;
  return (
    <div className="space-y-3">
      {run.decisions.map((d) => (
        <article key={d.seq} className="rounded-xl border border-line bg-ink-950/40 p-4">
          <div className="flex flex-wrap items-center gap-2">
            <ToolIcon tool={d.tool} />
            <code className="font-mono text-[15px] font-semibold text-slate-50">{d.tool}</code>
            <DecisionChip decision={d.decision} ruleId={d.ruleId} />
            {d.kind === "re_decision" && <Badge tone="brand">Re-evaluated after human decision</Badge>}
            <span className="ml-auto font-mono text-xs text-slate-500">
              audit #{d.seq} · risk {d.risk ?? "—"}
            </span>
          </div>
          <ul className="mt-3 space-y-1 text-sm text-slate-300">
            {d.reasons.map((r, i) => (
              <li key={i} className="flex gap-2">
                <span className={cx("mt-2 h-1 w-1 shrink-0 rounded-full", decisionKind(d.decision) === "DENY" ? "bg-rose-400" : decisionKind(d.decision) === "ALLOW" ? "bg-emerald-400" : "bg-amber-300")} />
                {r}
              </li>
            ))}
          </ul>
          <div className="mt-4 grid gap-4 lg:grid-cols-[1.4fr_1fr]">
            <div>
              <p className="text-xs font-semibold uppercase tracking-[0.12em] text-slate-500">Arguments</p>
              <div className="mt-1 rounded-lg border border-line bg-ink-950/50 px-3">
                <ArgumentProvenance args={d.arguments} />
              </div>
            </div>
            <div>
              <p className="text-xs font-semibold uppercase tracking-[0.12em] text-slate-500">Run context at decision time</p>
              <div className="mt-2 space-y-2">
                <LabelInline label={d.context} />
                {d.context && <SourceChips sources={d.context.sources} />}
              </div>
            </div>
          </div>
        </article>
      ))}
    </div>
  );
}

const AUDIT_LABEL: Record<string, string> = {
  run_started: "Run started",
  decision: "Policy decision",
  re_decision: "Re-evaluation after approval",
  outcome: "Tool outcome",
  approval_requested: "Approval requested",
  approval_decided: "Human decision recorded",
  request_rejected: "Request rejected",
  run_halted: "Run halted",
};

export function AuditTimeline({ run }: { run: Run }) {
  if (run.audit.length === 0) return <Empty icon={<IconList />} title="No audit events yet" />;
  const reasons = new Map(run.decisions.map((d) => [d.seq, d.reasons[0] ?? ""]));
  return (
    <ol className="relative space-y-0 border-l border-line-strong pl-6">
      {run.audit.map((e) => {
        const k = decisionKind(e.decision);
        const dot = e.kind === "run_halted" || k === "DENY" ? "bg-rose-500" : k === "REQUIRE_APPROVAL" || e.kind === "approval_requested" ? "bg-amber-400" : k === "ALLOW" || e.outcome === "executed" ? "bg-emerald-400" : "bg-slate-500";
        return (
          <li key={e.seq} className="relative pb-4 last:pb-0">
            <span className={cx("absolute -left-[31px] top-1.5 h-3 w-3 rounded-full ring-4 ring-ink-900", dot)} />
            <div className="flex flex-wrap items-center gap-2">
              <span className="font-mono text-xs tabular-nums text-slate-500">{fmtTime(e.ts)}</span>
              <span className="text-sm font-semibold text-slate-100">{AUDIT_LABEL[e.kind] ?? e.kind}</span>
              {e.tool && (
                <span className="inline-flex items-center gap-1 font-mono text-xs text-slate-300">
                  <ToolIcon tool={e.tool} size={13} />
                  {e.tool}
                </span>
              )}
              {e.decision && <DecisionChip decision={e.decision} ruleId={e.ruleId} />}
              {e.outcome && <Badge tone={e.outcome === "executed" ? "info" : "bad"}>{e.outcome}</Badge>}
              <span className="ml-auto font-mono text-xs text-slate-600">#{e.seq}</span>
            </div>
            {reasons.get(e.seq) && <p className="mt-1 text-sm text-slate-400">{reasons.get(e.seq)}</p>}
          </li>
        );
      })}
    </ol>
  );
}

// ---- side panels --------------------------------------------------------------------------------------------------

function ResultPanel({ run }: { run: Run }) {
  const finished = !["created", "running", "waiting"].includes(run.state);
  return (
    <Panel title="Security outcome" icon={<IconShieldCheck size={16} />}>
      {!finished ? (
        <p className="flex items-center gap-2 text-sm text-slate-400">
          {run.state === "waiting" ? <IconHand size={16} className="text-amber-300" /> : <Spinner />}
          {run.state === "waiting" ? "Waiting for your decision before the outcome is known." : "Outcome is computed when the run finishes."}
        </p>
      ) : (
        <div className="space-y-4">
          <div>
            <p className="text-xs font-semibold uppercase tracking-[0.12em] text-slate-500">Attack</p>
            <div className="mt-1.5">
              <VerdictBadge kind="attack" applicable={run.attack.applicable} result={run.attack.result} />
            </div>
            <p className="mt-1 text-sm text-slate-400">{run.attack.check}</p>
          </div>
          <div>
            <p className="text-xs font-semibold uppercase tracking-[0.12em] text-slate-500">Legitimate task</p>
            <div className="mt-1.5">
              <VerdictBadge kind="legit" applicable={run.legitimate.applicable} result={run.legitimate.result} />
            </div>
            <p className="mt-1 text-sm text-slate-400">{run.legitimate.check}</p>
          </div>
          <div>
            <p className="text-xs font-semibold uppercase tracking-[0.12em] text-slate-500">Expected outcome</p>
            <div className="mt-1.5">{run.expectationsMet ? <Badge tone="good">Matched</Badge> : <Badge tone="warn">Not matched</Badge>}</div>
            {run.expectationNote && <p className="mt-1 text-sm text-slate-400">{run.expectationNote}</p>}
          </div>
          {run.haltReason && <ErrorNote error={run.haltReason} />}
          <p className="text-xs text-slate-500">Verdicts come from the sandbox end state and the gateway audit log — never from what the agent claims.</p>
        </div>
      )}
    </Panel>
  );
}

function EvidencePanel({ run }: { run: Run }) {
  return (
    <Panel title="Sandbox evidence" icon={<IconDatabase size={16} />} subtitle="Synthetic sandbox — nothing real was sent or deleted">
      <p className="text-xs font-semibold uppercase tracking-[0.12em] text-slate-500">Outbox</p>
      {run.outbox.length === 0 ? (
        <p className="mt-1 text-sm text-slate-400">Empty — no email was sent.</p>
      ) : (
        <ul className="mt-2 space-y-1.5">
          {run.outbox.map((m) => (
            <li key={m.id} className="flex flex-wrap items-center gap-2 text-sm">
              <IconMail size={15} className={m.recipient === "external" ? "text-rose-300" : "text-emerald-300"} />
              {m.recipient === "external" ? <Badge tone="bad">External recipient</Badge> : <Badge tone="good">Requesting user</Badge>}
              <span className="text-xs text-slate-500">
                {m.bodyChars} chars{m.generatedSummary ? " · generated summary" : ""}
              </span>
            </li>
          ))}
        </ul>
      )}
      {run.protectedFiles.length > 0 && (
        <>
          <p className="mt-4 text-xs font-semibold uppercase tracking-[0.12em] text-slate-500">Protected files</p>
          <ul className="mt-2 space-y-1.5">
            {run.protectedFiles.map((f) => (
              <li key={f.path} className="flex flex-wrap items-center gap-2 text-sm">
                <IconFile size={15} className="text-slate-400" />
                <code className="font-mono text-slate-300">{f.path}</code>
                {f.present ? <Badge tone="good">Intact</Badge> : <Badge tone="bad">Deleted</Badge>}
              </li>
            ))}
          </ul>
        </>
      )}
      <p className="mt-4 text-xs text-slate-500">Email bodies and subjects are withheld: they can contain leaked or attacker-controlled text.</p>
    </Panel>
  );
}

function ContextPanel({ run }: { run: Run }) {
  const latest = [...run.decisions].reverse().find((d) => d.context)?.context ?? null;
  return (
    <Panel title="Run context provenance" icon={<IconLayers size={16} />} subtitle="Everything the agent has read so far">
      {latest ? (
        <div className="space-y-2">
          <LabelInline label={latest} />
          <SourceChips sources={latest.sources} />
          <p className="pt-1 text-xs text-slate-500">The context only ever becomes less trusted and more confidential — the agent cannot launder what it read.</p>
        </div>
      ) : (
        <p className="text-sm text-slate-400">No decisions yet.</p>
      )}
    </Panel>
  );
}

// ---- page ---------------------------------------------------------------------------------------------------------

const TABS = [
  { key: "timeline", label: "Agent activity", icon: IconActivity },
  { key: "content", label: "Untrusted content", icon: IconBug },
  { key: "decisions", label: "Policy decisions", icon: IconShield },
  { key: "audit", label: "Audit trail", icon: IconList },
] as const;

export function RunPage({ runId, onRunAgain }: { runId: string; onRunAgain: (scenarioId: string, mode: "on" | "off") => void }) {
  const live = useRunStream(runId);
  const content = useRunContent(runId);
  const [tab, setTab] = useState<(typeof TABS)[number]["key"]>("timeline");
  const refreshed = useRef(false);
  const run = live.run;

  useEffect(() => {
    if (live.finished && !refreshed.current) {
      refreshed.current = true;
      void live.refresh();
    }
  }, [live.finished, live.refresh]);

  if (!run) {
    return (
      <Panel>
        {live.error ? (
          <ErrorNote error={live.error} />
        ) : (
          <p className="flex items-center gap-3 text-sm text-slate-400">
            <Spinner /> Connecting to the live run…
          </p>
        )}
      </Panel>
    );
  }

  const busy = run.state === "running" || run.state === "created" || run.state === "waiting";
  const otherMode = run.mode === "on" ? "off" : "on";
  const counts = {
    allow: run.decisions.filter((d) => decisionKind(d.decision) === "ALLOW").length,
    deny: run.decisions.filter((d) => decisionKind(d.decision) === "DENY").length,
    approval: run.decisions.filter((d) => decisionKind(d.decision) === "REQUIRE_APPROVAL").length,
  };

  return (
    <div className="space-y-5">
      <section className="relative overflow-hidden rounded-2xl border border-line bg-gradient-to-br from-ink-850 via-ink-900 to-ink-950 p-6">
        <div className="pointer-events-none absolute -right-24 -top-24 h-64 w-64 rounded-full bg-cyan-400/10 blur-3xl" aria-hidden />
        <div className="relative flex flex-wrap items-start justify-between gap-6">
          <div className="min-w-0 max-w-3xl">
            <div className="flex flex-wrap items-center gap-2">
              <Badge tone="brand" className="font-mono">
                {run.scenario.id}
              </Badge>
              <ModeBadge mode={run.mode} size="md" />
              <Badge tone={statusTone(run.state)} className="px-3 py-1.5 text-sm">
                {busy && run.state !== "waiting" && <Spinner className="h-3.5 w-3.5" />}
                {STATE_LABEL[run.state] ?? run.state}
              </Badge>
              {live.connected && (
                <span className="inline-flex items-center gap-1.5 text-xs font-medium text-cyan-300">
                  <span className="h-2 w-2 rounded-full bg-cyan-400 animate-pulse" /> live
                </span>
              )}
            </div>
            <h1 className="mt-3 text-2xl font-semibold tracking-tight text-slate-50 sm:text-[28px]">{run.scenario.title}</h1>
            <p className="mt-2 text-[15px] leading-relaxed text-slate-300">{run.scenario.description}</p>
            <p className="mt-3 text-sm text-slate-400">
              Task: <span className="text-slate-200">“{run.scenario.goal}”</span>
            </p>
          </div>
          <div className="flex flex-col items-start gap-3 sm:items-end">
            {!isLabRun(run) && (
              <Button variant="secondary" onClick={() => onRunAgain(run.scenario.id, otherMode)} disabled={busy}>
                Run again with Shield {otherMode.toUpperCase()}
              </Button>
            )}
            <div className="flex gap-2 text-sm">
              <Badge tone="good">{counts.allow} allowed</Badge>
              <Badge tone="bad">{counts.deny} denied</Badge>
              <Badge tone="warn">{counts.approval} approval</Badge>
            </div>
          </div>
        </div>
        <div className="relative mt-5 flex flex-wrap items-center justify-between gap-4 border-t border-line pt-4">
          <PhaseStepper run={run} />
          <p className="font-mono text-xs text-slate-500">
            {run.runId} · {run.policyId} · {run.scenario.userId} · {run.scenario.agentId} · deterministic simulated agent, not an LLM
          </p>
        </div>
      </section>

      {run.state === "waiting" && <ApprovalPanel runId={runId} />}
      <AttackSummary run={run} />

      <div className="grid gap-5 xl:grid-cols-[minmax(0,1fr)_380px]">
        <Panel padded={false}>
          <div role="tablist" aria-label="Run details" className="flex flex-wrap gap-1 border-b border-line px-3 pt-3">
            {TABS.map((t) => (
              <button
                key={t.key}
                role="tab"
                aria-selected={tab === t.key}
                onClick={() => setTab(t.key)}
                className={cx(
                  "-mb-px inline-flex items-center gap-2 rounded-t-lg border-b-2 px-4 py-2.5 text-sm font-medium transition-colors",
                  tab === t.key ? "border-cyan-400 text-slate-50" : "border-transparent text-slate-400 hover:text-slate-200",
                )}
              >
                <t.icon size={15} />
                {t.label}
                {t.key === "decisions" && <span className="rounded bg-white/[0.06] px-1.5 text-xs">{run.decisions.length}</span>}
                {t.key === "audit" && <span className="rounded bg-white/[0.06] px-1.5 text-xs">{run.audit.length}</span>}
              </button>
            ))}
          </div>
          <div className="p-5">
            {tab === "timeline" && <Timeline run={run} />}
            {tab === "content" && <ContentInspector content={content.content} run={run} compact />}
            {tab === "decisions" && (
              <div className="space-y-5">
                <ProvenanceLegend />
                <Decisions run={run} />
              </div>
            )}
            {tab === "audit" && <AuditTimeline run={run} />}
          </div>
        </Panel>
        <div className="space-y-5">
          <ResultPanel run={run} />
          <ContextPanel run={run} />
          <EvidencePanel run={run} />
          {run.approvals.length > 0 && (
            <Panel title="Approval history" icon={<IconHand size={16} />}>
              <ul className="space-y-3">
                {run.approvals.map((a) => (
                  <li key={a.approvalId} className="space-y-1.5 text-sm">
                    <div className="flex flex-wrap items-center gap-2">
                      <Badge tone={a.actor === "human" ? "brand" : "warn"}>{a.actor === "human" ? "Human operator" : "Scripted operator"}</Badge>
                      <span className="text-slate-300">
                        {a.operator} chose <b className="text-slate-100">{a.action}</b>
                      </span>
                    </div>
                    <div className="flex flex-wrap items-center gap-2">
                      {a.reDecision && <DecisionChip decision={a.reDecision.decision} ruleId={a.reDecision.ruleId} />}
                      <Badge tone={a.executed ? "info" : "neutral"}>{a.executed ? "Executed once" : "Not executed"}</Badge>
                    </div>
                    <p className="font-mono text-xs text-slate-500">{a.approvalId}</p>
                  </li>
                ))}
              </ul>
            </Panel>
          )}
        </div>
      </div>
      <p className="text-xs text-slate-500">{run.operatorNote}</p>
    </div>
  );
}
