import { useEffect, useMemo, useState } from "react";
import { api } from "./api";
import { IconList, ToolIcon } from "./icons";
import type { AuditExplorerEvent } from "./types";
import { Badge, cx, DecisionChip, Empty, ErrorNote, ModeBadge, Panel, Spinner } from "./ui";

// Audit Explorer: every audit event of the runs the API holds (scenarios and labs), newest first. Values come from the
// redacted audit log and the masked policy reasons; nothing here can modify the log.

const EVENT_LABEL: Record<string, string> = {
  run_started: "Run started",
  decision: "Policy decision",
  re_decision: "Re-evaluation",
  outcome: "Tool outcome",
  approval_requested: "Approval requested",
  approval_decided: "Human decision",
  request_rejected: "Request rejected",
  run_halted: "Run halted",
};

const FILTERS = ["all", "ALLOW", "DENY", "REQUIRE_APPROVAL", "approvals", "outcomes"] as const;
type Filter = (typeof FILTERS)[number];

export function AuditExplorer({ onOpenRun }: { onOpenRun: (id: string) => void }) {
  const [events, setEvents] = useState<AuditExplorerEvent[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [filter, setFilter] = useState<Filter>("all");
  const [query, setQuery] = useState("");

  useEffect(() => {
    let stop = false;
    const load = () =>
      api.audit().then(
        (e) => !stop && setEvents(e),
        (e) => !stop && setError(e instanceof Error ? e.message : String(e)),
      );
    load();
    const t = setInterval(load, 3000);
    return () => {
      stop = true;
      clearInterval(t);
    };
  }, []);

  const shown = useMemo(() => {
    const q = query.trim().toLowerCase();
    return (events ?? []).filter((e) => {
      if (filter === "approvals" && !e.kind.startsWith("approval")) return false;
      if (filter === "outcomes" && e.kind !== "outcome") return false;
      if ((filter === "ALLOW" || filter === "DENY" || filter === "REQUIRE_APPROVAL") && !(e.decision ?? "").startsWith(filter)) return false;
      if (q && ![e.runId, e.scenarioId, e.tool ?? "", e.ruleId ?? "", e.reason ?? "", e.kind].some((s) => s.toLowerCase().includes(q))) return false;
      return true;
    });
  }, [events, filter, query]);

  return (
    <div className="space-y-5">
      <header>
        <p className="inline-flex items-center gap-2 text-xs font-semibold uppercase tracking-[0.16em] text-cyan-300">
          <IconList size={14} /> Audit Explorer
        </p>
        <h1 className="mt-2 text-3xl font-semibold tracking-tight text-white">Every decision, before anything ran.</h1>
        <p className="mt-2 max-w-3xl text-base text-slate-300">
          The gateway writes a decision row before any tool executes and an outcome row afterwards; if either write fails the run halts. The log is
          append-only at the application level (no update or delete paths) — it is not OS-level tamper-proof storage.
        </p>
      </header>
      <ErrorNote error={error} />
      <Panel padded={false}>
        <div className="flex flex-wrap items-center gap-2 border-b border-line p-4">
          <div role="radiogroup" aria-label="Filter events" className="flex flex-wrap gap-1.5">
            {FILTERS.map((f) => (
              <button
                key={f}
                role="radio"
                aria-checked={filter === f}
                onClick={() => setFilter(f)}
                className={cx("rounded-full px-3 py-1.5 text-sm ring-1 ring-inset", filter === f ? "bg-cyan-400/15 text-cyan-200 ring-cyan-400/40" : "text-slate-400 ring-white/10 hover:text-slate-200")}
              >
                {f === "all" ? "All events" : f === "REQUIRE_APPROVAL" ? "Needs approval" : f === "approvals" ? "Approvals" : f === "outcomes" ? "Outcomes" : f === "ALLOW" ? "Allowed" : "Denied"}
              </button>
            ))}
          </div>
          <input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search run, tool, rule or reason"
            aria-label="Search audit events"
            className="ml-auto h-9 w-full rounded-lg border border-line-strong bg-ink-950 px-3 text-sm text-slate-100 placeholder:text-slate-600 focus:border-cyan-400 focus:outline-none sm:w-72"
          />
        </div>
        {!events ? (
          <p className="flex items-center gap-2 p-5 text-sm text-slate-400">
            <Spinner /> Loading audit events…
          </p>
        ) : shown.length === 0 ? (
          <div className="p-5">
            <Empty icon={<IconList />} title={events.length === 0 ? "No audit events yet" : "No events match"}>
              {events.length === 0 ? "Run a scenario or a lab to generate audit records." : "Change the filter or search."}
            </Empty>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[920px] text-left text-sm">
              <thead className="text-xs uppercase tracking-[0.12em] text-slate-500">
                <tr>
                  <th className="px-4 py-3 font-semibold">Time</th>
                  <th className="px-4 py-3 font-semibold">Run</th>
                  <th className="px-4 py-3 font-semibold">Event</th>
                  <th className="px-4 py-3 font-semibold">Tool</th>
                  <th className="px-4 py-3 font-semibold">Decision</th>
                  <th className="px-4 py-3 font-semibold">Policy reason</th>
                  <th className="px-4 py-3 font-semibold">Outcome</th>
                </tr>
              </thead>
              <tbody>
                {shown.slice(0, 300).map((e) => (
                  <tr key={`${e.runId}-${e.seq}`} className="border-t border-line align-top hover:bg-white/[0.02]">
                    <td className="whitespace-nowrap px-4 py-2.5 font-mono text-xs tabular-nums text-slate-400">{new Date(e.ts).toLocaleTimeString()}</td>
                    <td className="px-4 py-2.5">
                      <button onClick={() => onOpenRun(e.runId)} className="flex flex-wrap items-center gap-1.5 text-left hover:underline">
                        <Badge tone="brand" className="font-mono">
                          {e.scenarioId}
                        </Badge>
                        <ModeBadge mode={e.mode} />
                        <span className="font-mono text-xs text-slate-500">{e.runId.slice(4, 12)}</span>
                      </button>
                    </td>
                    <td className="px-4 py-2.5 text-slate-200">{EVENT_LABEL[e.kind] ?? e.kind}</td>
                    <td className="px-4 py-2.5">
                      {e.tool ? (
                        <span className="inline-flex items-center gap-1.5 font-mono text-xs text-slate-300">
                          <ToolIcon tool={e.tool} size={13} /> {e.tool}
                        </span>
                      ) : (
                        <span className="text-slate-600">—</span>
                      )}
                    </td>
                    <td className="px-4 py-2.5">{e.decision ? <DecisionChip decision={e.decision} ruleId={e.ruleId} /> : <span className="text-slate-600">—</span>}</td>
                    <td className="max-w-md px-4 py-2.5 text-xs text-slate-400">{e.reason ?? ""}</td>
                    <td className="px-4 py-2.5">{e.outcome ? <Badge tone={e.outcome === "executed" ? "info" : "bad"}>{e.outcome}</Badge> : <span className="text-slate-600">—</span>}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            {shown.length > 300 && <p className="px-4 py-3 text-xs text-slate-500">Showing the newest 300 of {shown.length} events.</p>}
          </div>
        )}
      </Panel>
    </div>
  );
}
