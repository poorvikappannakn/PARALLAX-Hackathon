import { useState } from "react";
import { RunRow } from "./Dashboard";
import { IconActivity } from "./icons";
import type { RunSummary } from "./types";
import { cx, Empty, Panel } from "./ui";

// Recent activity: every interactive run held by the server in this session, newest first, with simple filters.

const FILTERS = [
  { key: "all", label: "All" },
  { key: "waiting", label: "Awaiting approval" },
  { key: "active", label: "Executing" },
  { key: "finished", label: "Finished" },
  { key: "on", label: "Shield ON" },
  { key: "off", label: "Shield OFF" },
] as const;
type Filter = (typeof FILTERS)[number]["key"];

const matches = (r: RunSummary, f: Filter) =>
  f === "all" ||
  (f === "waiting" && r.state === "waiting") ||
  (f === "active" && (r.state === "running" || r.state === "created")) ||
  (f === "finished" && !["running", "created", "waiting"].includes(r.state)) ||
  r.mode === f;

export function Activity({ runs, onOpen }: { runs: RunSummary[]; onOpen: (id: string) => void }) {
  const [filter, setFilter] = useState<Filter>("all");
  const shown = runs.filter((r) => matches(r, filter));
  return (
    <Panel
      title="Recent activity"
      subtitle="Interactive runs kept by the API in this session (most recent first). Restarting the API clears them."
      icon={<IconActivity size={16} />}
    >
      <div role="radiogroup" aria-label="Filter runs" className="mb-4 flex flex-wrap gap-2">
        {FILTERS.map((f) => (
          <button
            key={f.key}
            role="radio"
            aria-checked={filter === f.key}
            onClick={() => setFilter(f.key)}
            className={cx(
              "rounded-full px-3 py-1.5 text-sm font-medium ring-1 ring-inset transition-colors",
              filter === f.key ? "bg-cyan-400/15 text-cyan-200 ring-cyan-400/40" : "text-slate-400 ring-white/10 hover:text-slate-200",
            )}
          >
            {f.label}
            <span className="ml-1.5 text-xs opacity-70">{runs.filter((r) => matches(r, f.key)).length}</span>
          </button>
        ))}
      </div>
      {shown.length === 0 ? (
        <Empty icon={<IconActivity />} title={runs.length === 0 ? "No runs yet" : "No runs match this filter"}>
          {runs.length === 0 ? "Launch a scenario from the dashboard." : "Choose another filter."}
        </Empty>
      ) : (
        <div className="-mx-3 divide-y divide-line">
          {shown.map((r) => (
            <RunRow key={r.runId} r={r} onOpen={onOpen} />
          ))}
        </div>
      )}
    </Panel>
  );
}
