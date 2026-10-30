import { useCallback, useEffect, useRef, useState } from "react";
import { api, ApiError } from "./api";
import type { AuditEvent, Decision, PendingApproval, Run, Step } from "./types";
import { Badge, Button, Card, cx, decisionTone, Empty, ErrorNote, fmtTime, LabelChip, ModeBadge, shortId, Spinner, statusTone, VerdictBadge } from "./ui";

// Live run view. The run executes on the server one gateway call at a time; this page follows it over SSE
// (GET /api/runs/:id/events) and renders only the sanitised projections the API sends.

type Live = { run: Run | null; connected: boolean; finished: boolean; error: string | null };

function useRunStream(runId: string) {
  const [live, setLive] = useState<Live>({ run: null, connected: false, finished: false, error: null });

  useEffect(() => {
    let closed = false;
    const es = new EventSource(`/api/runs/${runId}/events`);
    const update = (fn: (r: Run) => Run) => setLive((l) => (l.run ? { ...l, run: fn(l.run) } : l));
    const on = (name: string, fn: (data: any) => void) => es.addEventListener(name, (e) => fn(JSON.parse((e as MessageEvent).data)));

    es.onopen = () => setLive((l) => ({ ...l, connected: true, error: null }));
    es.onerror = () => {
      if (!closed) setLive((l) => ({ ...l, connected: false }));
      // EventSource reconnects by itself and sends Last-Event-ID; the server resumes from there.
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

  // A finished run's full view (outbox, verdicts, approvals) arrives with "done"; refresh once more to be safe.
  const refresh = useCallback(async () => {
    try {
      const run = await api.run(runId);
      setLive((l) => ({ ...l, run }));
    } catch (e) {
      setLive((l) => ({ ...l, error: e instanceof Error ? e.message : String(e) }));
    }
  }, [runId]);

  return { ...live, refresh };
}

function ApprovalPanel({ runId, onDecided }: { runId: string; onDecided: () => void }) {
  const [approval, setApproval] = useState<PendingApproval | null>(null);
  const [busy, setBusy] = useState<"approve" | "reject" | null>(null);
  const [error, setError] = useState<string | null>(null);
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

  if (!approval) return null;
  const secondsLeft = Math.max(0, Math.round((approval.expiresAt - now) / 1000));

  const decide = async (verdict: "approve" | "reject") => {
    setBusy(verdict);
    setError(null);
    try {
      await api.decide(approval.approvalId, verdict);
      setApproval(null);
      onDecided();
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Decision failed");
    } finally {
      setBusy(null);
    }
  };

  return (
    <section aria-live="polite" className="rounded-xl border border-amber-500/40 bg-amber-500/5 p-4 shadow-lg shadow-amber-950/20">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <p className="text-xs font-semibold uppercase tracking-wider text-amber-300">Human approval required</p>
          <h3 className="mt-1 text-lg font-semibold text-slate-100">
            The agent wants to run <code className="rounded bg-slate-800 px-1.5 py-0.5 text-amber-200">{approval.tool}</code>
          </h3>
          <p className="mt-1 text-xs text-slate-400">
            Approval <code>{approval.approvalId}</code> · rule <Badge tone="warn">{approval.ruleId}</Badge> · risk {approval.risk} · expires in {secondsLeft}s
          </p>
        </div>
        <div className="flex gap-2">
          <Button variant="good" busy={busy === "approve"} disabled={busy !== null} onClick={() => decide("approve")}>
            Approve
          </Button>
          <Button variant="danger" busy={busy === "reject"} disabled={busy !== null} onClick={() => decide("reject")}>
            Reject
          </Button>
        </div>
      </div>
      <div className="mt-4 grid gap-4 md:grid-cols-2">
        <div>
          <p className="text-xs font-semibold uppercase tracking-wider text-slate-400">Why the policy paused this call</p>
          <ul className="mt-2 space-y-1 text-sm text-slate-300">
            {approval.reasons.map((r) => (
              <li key={r}>• {r}</li>
            ))}
          </ul>
          {approval.recipient && (
            <p className="mt-3 text-sm text-slate-300">
              Recipient:{" "}
              {approval.recipient === "requesting_user" ? (
                <Badge tone="good">the requesting user's own address (trusted profile value)</Badge>
              ) : (
                <Badge tone="bad">external recipient</Badge>
              )}
            </p>
          )}
        </div>
        <div>
          <p className="text-xs font-semibold uppercase tracking-wider text-slate-400">Argument provenance (values are never shown)</p>
          <table className="mt-2 w-full text-sm">
            <tbody>
              {approval.arguments.map((a) => (
                <tr key={a.name} className="border-t border-slate-800">
                  <td className="py-1.5 pr-2 font-mono text-slate-300">{a.name}</td>
                  <td className="py-1.5 pr-2">
                    <LabelChip label={a} />
                  </td>
                  <td className="py-1.5 text-xs text-slate-500">{a.sources.join(", ")}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
      <p className="mt-3 text-xs text-slate-500">
        Approving lets the PEP re-evaluate this exact call (same tool, arguments, provenance, run, agent, user and policy version). DENY rules
        are re-checked and can never be overridden; the approval is single-use.
      </p>
      <ErrorNote error={error} />
    </section>
  );
}

function Timeline({ run }: { run: Run }) {
  if (run.steps.length === 0) return <Empty>Waiting for the agent's first tool call…</Empty>;
  return (
    <ol className="relative space-y-3 border-l border-slate-800 pl-5">
      {run.steps.map((s) => {
        const d = matchDecision(run, s);
        return (
          <li key={`${s.call}-${s.step}`} className="relative">
            <span className={cx("absolute -left-[27px] top-1.5 h-3 w-3 rounded-full ring-4 ring-slate-950", dotColor(s.status))} />
            <div className="flex flex-wrap items-center gap-2">
              <span className="text-xs text-slate-500">#{s.step}</span>
              <code className="text-sm font-semibold text-slate-100">{s.tool}</code>
              {s.call === "resume" && <Badge tone="info">resumed after approval</Badge>}
              {s.origin === "injected" ? <Badge tone="bad">injected instruction</Badge> : <Badge>task step</Badge>}
              <Badge tone={statusTone(s.status)}>{s.status}</Badge>
              {s.ruleId && <Badge tone={decisionTone(d?.decision ?? null)}>{s.ruleId}</Badge>}
            </div>
            {s.source && <p className="mt-1 text-xs text-rose-300/80">instruction came from {s.source}</p>}
            {d && d.reasons.length > 0 && <p className="mt-1 text-xs text-slate-400">{d.reasons[0]}</p>}
          </li>
        );
      })}
    </ol>
  );
}

const dotColor = (status: string) =>
  ({ ok: "bg-emerald-400", denied: "bg-rose-500", rejected: "bg-rose-500", approval_required: "bg-amber-400", approval_pending: "bg-amber-400" })[status] ?? "bg-slate-500";

/** The decision belonging to a step: steps and decision rows appear in the same order per call kind. */
function matchDecision(run: Run, s: Step): Decision | undefined {
  const kind = s.call === "resume" ? "re_decision" : "decision";
  const sameKindSteps = run.steps.filter((x) => (x.call === "resume" ? "re_decision" : "decision") === kind && x.status !== "rejected");
  const idx = sameKindSteps.indexOf(s);
  return idx >= 0 ? run.decisions.filter((d) => d.kind === kind)[idx] : undefined;
}

function Decisions({ run }: { run: Run }) {
  if (run.decisions.length === 0) return <Empty>No policy decisions yet.</Empty>;
  return (
    <div className="space-y-3">
      {run.decisions.map((d) => (
        <article key={d.seq} className="rounded-lg border border-slate-800 bg-slate-950/40 p-3">
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-xs text-slate-500">audit #{d.seq}</span>
            <code className="text-sm font-semibold text-slate-100">{d.tool}</code>
            <Badge tone={decisionTone(d.decision)}>{d.decision}</Badge>
            <Badge tone={decisionTone(d.decision)}>{d.ruleId}</Badge>
            {d.kind === "re_decision" && <Badge tone="info">re-evaluated after approval</Badge>}
            <span className="ml-auto text-xs text-slate-500">risk {d.risk}</span>
          </div>
          <ul className="mt-2 space-y-0.5 text-sm text-slate-300">
            {d.reasons.map((r, i) => (
              <li key={i}>• {r}</li>
            ))}
          </ul>
          <div className="mt-2 grid gap-2 text-xs sm:grid-cols-2">
            <div>
              <p className="font-semibold text-slate-400">Arguments</p>
              {d.arguments.length === 0 && <p className="text-slate-500">none</p>}
              {d.arguments.map((a) => (
                <p key={a.name} className="mt-1 flex flex-wrap items-center gap-1">
                  <code className="text-slate-300">{a.name}</code> <LabelChip label={a} /> <span className="text-slate-500">{a.sources.join(", ")}</span>
                </p>
              ))}
            </div>
            <div>
              <p className="font-semibold text-slate-400">Run context at decision time</p>
              <p className="mt-1">
                <LabelChip label={d.context} /> <span className="text-slate-500">{d.context?.sources.join(", ")}</span>
              </p>
            </div>
          </div>
        </article>
      ))}
    </div>
  );
}

export function AuditTable({ run }: { run: Run }) {
  const reasons = new Map(run.decisions.map((d) => [d.seq, d.reasons[0] ?? ""]));
  if (run.audit.length === 0) return <Empty>No audit events yet.</Empty>;
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-left text-sm">
        <thead className="text-xs uppercase tracking-wider text-slate-500">
          <tr>
            <th className="py-2 pr-3">#</th>
            <th className="py-2 pr-3">Time</th>
            <th className="py-2 pr-3">Event</th>
            <th className="py-2 pr-3">Tool</th>
            <th className="py-2 pr-3">Decision</th>
            <th className="py-2 pr-3">Outcome</th>
            <th className="py-2">Reason</th>
          </tr>
        </thead>
        <tbody>
          {run.audit.map((e) => (
            <tr key={e.seq} className="border-t border-slate-800 align-top">
              <td className="py-1.5 pr-3 text-slate-500">{e.seq}</td>
              <td className="py-1.5 pr-3 whitespace-nowrap text-slate-400">{fmtTime(e.ts)}</td>
              <td className="py-1.5 pr-3 font-mono text-xs text-slate-300">{e.kind}</td>
              <td className="py-1.5 pr-3 font-mono text-xs">{e.tool ?? "—"}</td>
              <td className="py-1.5 pr-3">{e.decision ? <Badge tone={decisionTone(e.decision === "APPROVED" ? "ALLOW" : e.decision === "REJECTED" ? "DENY" : e.decision)}>{[e.decision, e.ruleId].filter(Boolean).join(" ")}</Badge> : "—"}</td>
              <td className="py-1.5 pr-3">{e.outcome ? <Badge tone={e.outcome === "executed" ? "info" : "bad"}>{e.outcome}</Badge> : "—"}</td>
              <td className="py-1.5 text-xs text-slate-400">{reasons.get(e.seq) ?? ""}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function Evidence({ run }: { run: Run }) {
  return (
    <div className="grid gap-4 md:grid-cols-2">
      <div>
        <p className="text-xs font-semibold uppercase tracking-wider text-slate-400">Sandbox outbox (no email was really sent)</p>
        {run.outbox.length === 0 ? (
          <p className="mt-2 text-sm text-slate-500">Empty — nothing was sent.</p>
        ) : (
          <ul className="mt-2 space-y-1 text-sm">
            {run.outbox.map((m) => (
              <li key={m.id} className="flex flex-wrap items-center gap-2">
                <code className="text-slate-400">{m.id}</code>
                {m.recipient === "external" ? <Badge tone="bad">to an external recipient</Badge> : <Badge tone="good">to the requesting user</Badge>}
                <span className="text-xs text-slate-500">
                  {m.bodyChars} chars{m.generatedSummary ? " · generated summary" : ""}
                </span>
              </li>
            ))}
          </ul>
        )}
        <p className="mt-2 text-xs text-slate-500">Bodies and subjects are withheld: they may contain leaked or untrusted text.</p>
      </div>
      <div>
        <p className="text-xs font-semibold uppercase tracking-wider text-slate-400">Protected files in the run sandbox</p>
        {run.protectedFiles.length === 0 ? (
          <p className="mt-2 text-sm text-slate-500">This scenario does not target files.</p>
        ) : (
          <ul className="mt-2 space-y-1 text-sm">
            {run.protectedFiles.map((f) => (
              <li key={f.path} className="flex items-center gap-2">
                <code className="text-slate-300">{f.path}</code>
                {f.present ? <Badge tone="good">present</Badge> : <Badge tone="bad">missing / deleted</Badge>}
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}

const TABS = ["Timeline", "Policy decisions", "Audit trail", "Evidence"] as const;

export function RunPage({ runId, onRunAgain }: { runId: string; onRunAgain: (scenarioId: string, mode: "on" | "off") => void }) {
  const live = useRunStream(runId);
  const [tab, setTab] = useState<(typeof TABS)[number]>("Timeline");
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
      <Card>
        <p className="flex items-center gap-2 text-sm text-slate-400">
          <Spinner /> Connecting to run {shortId(runId)}…
        </p>
        <ErrorNote error={live.error} />
      </Card>
    );
  }

  const running = run.state === "running" || run.state === "created";
  const otherMode = run.mode === "on" ? "off" : "on";

  return (
    <div className="space-y-4">
      <Card>
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-2">
              <Badge tone="info">{run.scenario.id}</Badge>
              <ModeBadge mode={run.mode} />
              <Badge tone={statusTone(run.state)}>
                {running && <Spinner />}
                {run.state === "waiting" ? "waiting for approval" : run.state}
              </Badge>
              {live.connected && <Badge tone="info">● live</Badge>}
            </div>
            <h2 className="mt-2 text-xl font-semibold text-slate-100">{run.scenario.title}</h2>
            <p className="mt-1 max-w-3xl text-sm text-slate-400">{run.scenario.description}</p>
            <p className="mt-2 text-xs text-slate-500">
              Run <code>{run.runId}</code> · policy <code>{run.policyId}</code> · user <code>{run.scenario.userId}</code> · agent <code>{run.scenario.agentId}</code> (deterministic simulated agent, not an LLM)
            </p>
          </div>
          <Button variant="secondary" onClick={() => onRunAgain(run.scenario.id, otherMode)} disabled={running || run.state === "waiting"}>
            Run again with Shield {otherMode.toUpperCase()}
          </Button>
        </div>
        {!running && run.state !== "waiting" && (
          <div className="mt-4 grid gap-3 sm:grid-cols-3">
            <div className="rounded-lg border border-slate-800 p-3">
              <p className="text-xs uppercase tracking-wider text-slate-500">Attack</p>
              <div className="mt-1">
                <VerdictBadge kind="attack" applicable={run.attack.applicable} result={run.attack.result} />
              </div>
              <p className="mt-1 text-xs text-slate-500">{run.attack.check}</p>
            </div>
            <div className="rounded-lg border border-slate-800 p-3">
              <p className="text-xs uppercase tracking-wider text-slate-500">Legitimate task</p>
              <div className="mt-1">
                <VerdictBadge kind="legit" applicable={run.legitimate.applicable} result={run.legitimate.result} />
              </div>
              <p className="mt-1 text-xs text-slate-500">{run.legitimate.check}</p>
            </div>
            <div className="rounded-lg border border-slate-800 p-3">
              <p className="text-xs uppercase tracking-wider text-slate-500">Expected outcome</p>
              <div className="mt-1">{run.expectationsMet ? <Badge tone="good">matched</Badge> : <Badge tone="warn">not matched</Badge>}</div>
              {run.haltReason && <p className="mt-1 text-xs text-rose-300">{run.haltReason}</p>}
              {run.expectationNote && <p className="mt-1 text-xs text-slate-400">{run.expectationNote}</p>}
            </div>
          </div>
        )}
      </Card>

      {run.state === "waiting" && <ApprovalPanel runId={runId} onDecided={() => {}} />}

      <Card
        title={
          <div role="tablist" aria-label="Run details" className="flex flex-wrap gap-1">
            {TABS.map((t) => (
              <button
                key={t}
                role="tab"
                aria-selected={tab === t}
                onClick={() => setTab(t)}
                className={cx("rounded-md px-3 py-1.5 text-sm", tab === t ? "bg-slate-800 text-slate-100" : "text-slate-400 hover:text-slate-200")}
              >
                {t}
                {t === "Policy decisions" && ` (${run.decisions.length})`}
                {t === "Audit trail" && ` (${run.audit.length})`}
              </button>
            ))}
          </div>
        }
      >
        {tab === "Timeline" && <Timeline run={run} />}
        {tab === "Policy decisions" && <Decisions run={run} />}
        {tab === "Audit trail" && <AuditTable run={run} />}
        {tab === "Evidence" && <Evidence run={run} />}
      </Card>

      {run.approvals.length > 0 && (
        <Card title="Approval history">
          <ul className="space-y-1 text-sm">
            {run.approvals.map((a) => (
              <li key={a.approvalId} className="flex flex-wrap items-center gap-2">
                <code className="text-xs text-slate-500">{a.approvalId}</code>
                <Badge tone={a.actor === "human" ? "info" : "warn"}>{a.actor === "human" ? "human operator" : "SCRIPTED operator"}</Badge>
                <span className="text-slate-300">
                  {a.operator} chose <b>{a.action}</b> for <code>{a.tool}</code>
                </span>
                {a.reDecision && <Badge tone={decisionTone(a.reDecision.decision)}>{`re-decision ${a.reDecision.decision} ${a.reDecision.ruleId}`}</Badge>}
                <Badge tone={a.executed ? "info" : "neutral"}>{a.executed ? "executed once" : "not executed"}</Badge>
              </li>
            ))}
          </ul>
        </Card>
      )}
      <p className="text-xs text-slate-500">{run.operatorNote}</p>
    </div>
  );
}
