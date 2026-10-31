import { useEffect, useRef, type ReactNode } from "react";
import { IconArrowRight, IconCompare, IconShieldCheck, IconShieldOff, ToolIcon } from "./icons";
import { ContentInspector, useRunContent } from "./Inspector";
import { ApprovalPanel, useRunStream } from "./RunPage";
import { matchDecision } from "./runUtil";
import type { LabPlan, Run, Step } from "./types";
import { Badge, Button, cx, DecisionChip, decisionKind, Panel, Spinner, STATE_LABEL, statusTone, VerdictBadge } from "./ui";

// Results of a lab launch (Interactive Attack Lab / Email Security Lab): one or two isolated runs with the same task and
// content, followed live over SSE. Every cell below is computed from the real run views returned by the API.

function useLive(runId: string | null) {
  const live = useRunStream(runId);
  const refreshed = useRef(false);
  useEffect(() => {
    if (live.finished && !refreshed.current) {
      refreshed.current = true;
      void live.refresh();
    }
  }, [live.finished, live.refresh]);
  return live;
}

const injectedSteps = (run: Run, tool: string) => run.steps.filter((s) => s.origin === "injected" && s.tool === tool);

function StepOutcome({ run, steps, none }: { run: Run; steps: Step[]; none: string }) {
  if (steps.length === 0) return <span className="text-sm text-slate-500">{run.state === "running" || run.state === "created" ? "…" : none}</span>;
  return (
    <span className="flex flex-wrap gap-1.5">
      {steps.map((s) => {
        const d = matchDecision(run, s);
        return (
          <span key={s.step} className="inline-flex items-center gap-1.5">
            <DecisionChip decision={d?.decision ?? (s.status === "ok" ? "ALLOW" : null)} ruleId={s.ruleId} />
            <span className={cx("text-xs", s.status === "ok" ? "text-rose-300" : "text-slate-400")}>{s.status === "ok" ? "executed" : s.status}</span>
          </span>
        );
      })}
    </span>
  );
}

function Row({ label, off, on }: { label: string; off: ReactNode; on: ReactNode }) {
  return (
    <tr className="border-t border-line align-top">
      <th scope="row" className="py-3 pr-4 text-left text-sm font-medium text-slate-300">
        {label}
      </th>
      <td className="py-3 pr-4">{off}</td>
      <td className="py-3">{on}</td>
    </tr>
  );
}

function Comparison({ off, on }: { off: Run; on: Run }) {
  const counts = (r: Run, k: string) => r.decisions.filter((d) => d.kind === "decision" && decisionKind(d.decision) === k).length;
  const pending = (r: Run) => r.state === "running" || r.state === "created" || r.state === "waiting";
  const verdict = (r: Run, kind: "legit" | "attack") =>
    pending(r) ? <Badge tone={statusTone(r.state)}>{STATE_LABEL[r.state] ?? r.state}</Badge> : <VerdictBadge kind={kind} applicable={kind === "legit" ? r.legitimate.applicable : r.attack.applicable} result={kind === "legit" ? r.legitimate.result : r.attack.result} />;
  return (
    <Panel title="Shield OFF vs Shield ON — same task, same content" subtitle="Generated from the two actual run records" icon={<IconCompare size={16} />}>
      <div className="overflow-x-auto">
        <table className="w-full min-w-[640px]">
          <thead>
            <tr className="text-left text-xs uppercase tracking-[0.12em]">
              <th className="pb-2 font-semibold text-slate-500">Dimension</th>
              <th className="pb-2 font-semibold text-rose-300">
                <span className="inline-flex items-center gap-1.5">
                  <IconShieldOff size={14} /> Shield OFF
                </span>
              </th>
              <th className="pb-2 font-semibold text-emerald-300">
                <span className="inline-flex items-center gap-1.5">
                  <IconShieldCheck size={14} /> Shield ON
                </span>
              </th>
            </tr>
          </thead>
          <tbody>
            <Row label="Attack outcome (sandbox evidence)" off={verdict(off, "attack")} on={verdict(on, "attack")} />
            <Row label="Legitimate task" off={verdict(off, "legit")} on={verdict(on, "legit")} />
            <Row label="Sensitive-data access (injected read)" off={<StepOutcome run={off} steps={injectedSteps(off, "read_file")} none="not attempted" />} on={<StepOutcome run={on} steps={injectedSteps(on, "read_file")} none="not attempted" />} />
            <Row
              label="External disclosure (injected email)"
              off={<StepOutcome run={off} steps={injectedSteps(off, "send_email")} none="not attempted" />}
              on={<StepOutcome run={on} steps={injectedSteps(on, "send_email")} none="not attempted" />}
            />
            <Row label="Destructive operation (injected delete)" off={<StepOutcome run={off} steps={injectedSteps(off, "delete_file")} none="not attempted" />} on={<StepOutcome run={on} steps={injectedSteps(on, "delete_file")} none="not attempted" />} />
            <Row
              label="Emails to external recipients"
              off={<Badge tone={off.outbox.some((m) => m.recipient === "external") ? "bad" : "good"}>{off.outbox.filter((m) => m.recipient === "external").length}</Badge>}
              on={<Badge tone={on.outbox.some((m) => m.recipient === "external") ? "bad" : "good"}>{on.outbox.filter((m) => m.recipient === "external").length}</Badge>}
            />
            <Row
              label="Protected files deleted"
              off={<Badge tone={off.protectedFiles.some((f) => !f.present) ? "bad" : "good"}>{off.protectedFiles.filter((f) => !f.present).length}</Badge>}
              on={<Badge tone={on.protectedFiles.some((f) => !f.present) ? "bad" : "good"}>{on.protectedFiles.filter((f) => !f.present).length}</Badge>}
            />
            <Row
              label="PEP decisions"
              off={<span className="text-sm text-slate-300">{counts(off, "ALLOW")} allow · {counts(off, "DENY")} deny · {counts(off, "REQUIRE_APPROVAL")} approval</span>}
              on={<span className="text-sm text-slate-300">{counts(on, "ALLOW")} allow · {counts(on, "DENY")} deny · {counts(on, "REQUIRE_APPROVAL")} approval</span>}
            />
            <Row label="Audit events recorded" off={<span className="text-sm text-slate-300">{off.audit.length}</span>} on={<span className="text-sm text-slate-300">{on.audit.length}</span>} />
          </tbody>
        </table>
      </div>
    </Panel>
  );
}

function RunColumn({ run, onOpen }: { run: Run; onOpen: (id: string) => void }) {
  const off = run.mode === "off";
  const busy = run.state === "running" || run.state === "created";
  return (
    <section className={cx("flex flex-col rounded-2xl border p-4", off ? "border-rose-400/30 bg-rose-500/[0.04]" : "border-emerald-400/25 bg-emerald-400/[0.03]")}>
      <div className="flex flex-wrap items-center justify-between gap-2">
        <span className={cx("inline-flex items-center gap-1.5 text-sm font-semibold", off ? "text-rose-300" : "text-emerald-300")}>
          {off ? <IconShieldOff size={16} /> : <IconShieldCheck size={16} />} Shield {run.mode.toUpperCase()}
        </span>
        <Badge tone={statusTone(run.state)}>
          {busy && <Spinner className="h-3 w-3" />}
          {STATE_LABEL[run.state] ?? run.state}
        </Badge>
      </div>
      <ol className="mt-3 flex-1 space-y-2">
        {run.steps.map((s) => {
          const d = matchDecision(run, s);
          return (
            <li key={`${s.call}-${s.step}`} className={cx("flex flex-wrap items-center gap-2 rounded-lg px-2.5 py-2 text-sm ring-1 ring-inset animate-fade-in", s.origin === "injected" ? "bg-rose-500/[0.06] ring-rose-400/25" : "bg-white/[0.02] ring-white/10")}>
              <ToolIcon tool={s.tool} size={14} />
              <code className="font-mono text-slate-100">{s.tool}</code>
              {s.origin === "injected" && <Badge tone="bad">injected</Badge>}
              {s.call === "resume" && <Badge tone="brand">resumed</Badge>}
              <span className="ml-auto">
                <DecisionChip decision={d?.decision ?? (s.status === "ok" ? "ALLOW" : null)} ruleId={s.ruleId} />
              </span>
            </li>
          );
        })}
        {busy && (
          <li className="flex items-center gap-2 px-2.5 py-2 text-sm text-cyan-200">
            <Spinner className="h-3.5 w-3.5" /> executing…
          </li>
        )}
      </ol>
      <Button variant="ghost" size="sm" className="mt-3 self-start" onClick={() => onOpen(run.runId)}>
        Open full run (decisions, provenance, audit) <IconArrowRight size={14} />
      </Button>
    </section>
  );
}

export function LabResults({ runs, plan, onOpenRun }: { runs: Run[]; plan: LabPlan; onOpenRun: (id: string) => void }) {
  const offId = runs.find((r) => r.mode === "off")?.runId ?? null;
  const onId = runs.find((r) => r.mode === "on")?.runId ?? null;
  const off = useLive(offId);
  const on = useLive(onId);
  const offRun = off.run ?? runs.find((r) => r.mode === "off") ?? null;
  const onRun = on.run ?? runs.find((r) => r.mode === "on") ?? null;
  const shown = onRun ?? offRun;
  const content = useRunContent(onId ?? offId, shown ? `${shown.state}:${shown.steps.length}` : "");

  return (
    <div className="space-y-5 animate-fade-in">
      {onRun?.state === "waiting" && <ApprovalPanel runId={onRun.runId} />}
      {offRun?.state === "waiting" && <ApprovalPanel runId={offRun.runId} />}
      <div className={cx("grid gap-4", offRun && onRun && "lg:grid-cols-2")}>
        {offRun && <RunColumn run={offRun} onOpen={onOpenRun} />}
        {onRun && <RunColumn run={onRun} onOpen={onOpenRun} />}
      </div>
      {offRun && onRun && <Comparison off={offRun} on={onRun} />}
      <ContentInspector content={content.content} run={onRun ?? offRun} />
      <p className="text-xs text-slate-500">
        Task plan: {plan.steps.join(" → ")}. Each run has its own sandbox copy; nothing real is sent or deleted. The agent is a deterministic
        simulation, not an LLM.
      </p>
    </div>
  );
}
