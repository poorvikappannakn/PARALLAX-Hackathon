import { useState } from "react";
import { api, ApiError } from "./api";
import type { SuiteResult, SuiteSide } from "./types";
import { Badge, Button, Card, Empty, ErrorNote, VerdictBadge } from "./ui";

// ON/OFF comparison from POST /api/suite: the deterministic scripted runner executes every scenario in both modes.
// Every number shown is computed by the server from those runs.

function Side({ s, mode }: { s: SuiteSide; mode: "on" | "off" }) {
  return (
    <div className="space-y-1.5 text-sm">
      <VerdictBadge kind="attack" applicable={s.attack.applicable} result={s.attack.result} />
      <div className="flex flex-wrap gap-1">
        {s.denied.length > 0 ? (
          s.denied.map((d, i) => (
            <Badge key={i} tone="good">
              {d.ruleId} denied {d.tool}
            </Badge>
          ))
        ) : (
          <span className="text-xs text-slate-500">{mode === "off" ? "no enforcement (permissive policy)" : "no denials"}</span>
        )}
      </div>
      <p className="text-xs text-slate-400">
        outbox: {s.outbox.total} email(s){s.outbox.external > 0 && <span className="text-rose-300"> · {s.outbox.external} to external recipients</span>}
      </p>
      {s.protectedFiles.length > 0 && (
        <p className="text-xs text-slate-400">
          protected files:{" "}
          {s.protectedFiles.every((f) => f.present) ? <span className="text-emerald-300">all present</span> : <span className="text-rose-300">{s.protectedFiles.filter((f) => !f.present).length} deleted</span>}
        </p>
      )}
      {s.approvals.map((a, i) => (
        <p key={i} className="text-xs text-slate-400">
          approval ({a.tool}): scripted {a.action} → {a.result ?? "—"} {a.executed ? "· executed" : "· not executed"}
        </p>
      ))}
      <p className="text-xs">
        legitimate task: <VerdictBadge kind="legit" applicable={s.legitimate.applicable} result={s.legitimate.result} />
      </p>
    </div>
  );
}

export function SuitePage() {
  const [result, setResult] = useState<SuiteResult | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const run = async () => {
    setBusy(true);
    setError(null);
    try {
      setResult(await api.suite());
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Suite failed");
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="space-y-4">
      <Card
        title="Shield OFF vs Shield ON — full scenario suite"
        actions={
          <Button onClick={run} busy={busy}>
            {result ? "Run suite again" : "Run suite (10 runs)"}
          </Button>
        }
      >
        <p className="text-sm text-slate-400">
          Runs every scenario twice with the same agent, tools and fixtures — once with the permissive policy (Shield OFF) and once with
          enforcement (Shield ON). Verdicts come from the sandbox end state (outbox files, files on disk) and the gateway audit log, never from
          what the agent claims.
        </p>
        <ErrorNote error={error} />
        {result && (
          <div className="mt-4 grid gap-3 sm:grid-cols-4">
            <Stat label="Runs" value={result.totals.runs} />
            <Stat label="Expected outcomes matched" value={`${result.totals.expectationsMet} / ${result.totals.runs}`} tone={result.totals.expectationsMet === result.totals.runs ? "good" : "warn"} />
            <Stat label="Attacks succeeded, Shield OFF" value={result.totals.attacksSucceededOff} tone="bad" />
            <Stat label="Attacks succeeded, Shield ON" value={result.totals.attacksSucceededOn} tone={result.totals.attacksSucceededOn === 0 ? "good" : "bad"} />
          </div>
        )}
      </Card>

      {!result && !busy && <Empty>Run the suite to compare both modes across all five scenarios.</Empty>}

      {result && (
        <Card title="Per-scenario comparison">
          <div className="overflow-x-auto">
            <table className="w-full min-w-[720px] text-left">
              <thead className="text-xs uppercase tracking-wider text-slate-500">
                <tr>
                  <th className="py-2 pr-4">Scenario</th>
                  <th className="py-2 pr-4">Shield OFF</th>
                  <th className="py-2">Shield ON</th>
                </tr>
              </thead>
              <tbody>
                {result.scenarios.map((s) => (
                  <tr key={s.id} className="border-t border-slate-800 align-top">
                    <td className="py-3 pr-4">
                      <Badge tone="info">{s.id}</Badge>
                      <p className="mt-1 max-w-xs text-sm font-medium text-slate-200">{s.title}</p>
                      <p className="mt-1 text-xs text-slate-500">{s.on.attack.check}</p>
                    </td>
                    <td className="py-3 pr-4">
                      <Side s={s.off} mode="off" />
                    </td>
                    <td className="py-3">
                      <Side s={s.on} mode="on" />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <p className="mt-3 text-xs text-slate-500">{result.note}</p>
        </Card>
      )}
    </div>
  );
}

function Stat({ label, value, tone }: { label: string; value: string | number; tone?: "good" | "bad" | "warn" }) {
  const color = tone === "good" ? "text-emerald-300" : tone === "bad" ? "text-rose-300" : tone === "warn" ? "text-amber-300" : "text-slate-100";
  return (
    <div className="rounded-lg border border-slate-800 p-3">
      <p className="text-xs uppercase tracking-wider text-slate-500">{label}</p>
      <p className={`mt-1 text-2xl font-semibold ${color}`}>{value}</p>
    </div>
  );
}
