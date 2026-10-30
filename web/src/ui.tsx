import type { ReactNode } from "react";
import type { Label } from "./types";

// Small shared presentational components. No data fetching here.

export function cx(...c: (string | false | null | undefined)[]) {
  return c.filter(Boolean).join(" ");
}

type Tone = "neutral" | "good" | "bad" | "warn" | "info";
const TONES: Record<Tone, string> = {
  neutral: "bg-slate-800 text-slate-300 ring-slate-700",
  good: "bg-emerald-500/10 text-emerald-300 ring-emerald-500/30",
  bad: "bg-rose-500/10 text-rose-300 ring-rose-500/30",
  warn: "bg-amber-500/10 text-amber-300 ring-amber-500/30",
  info: "bg-sky-500/10 text-sky-300 ring-sky-500/30",
};

export function Badge({ tone = "neutral", children, title }: { tone?: Tone; children: ReactNode; title?: string }) {
  return (
    <span title={title} className={cx("inline-flex items-center gap-1 rounded-md px-2 py-0.5 text-xs font-medium ring-1 ring-inset whitespace-nowrap", TONES[tone])}>
      {children}
    </span>
  );
}

export function Card({ title, actions, children, className }: { title?: ReactNode; actions?: ReactNode; children: ReactNode; className?: string }) {
  return (
    <section className={cx("rounded-xl border border-slate-800 bg-slate-900/60 shadow-sm", className)}>
      {(title || actions) && (
        <header className="flex items-center justify-between gap-3 border-b border-slate-800 px-4 py-3">
          <h2 className="text-sm font-semibold tracking-wide text-slate-200">{title}</h2>
          {actions}
        </header>
      )}
      <div className="p-4">{children}</div>
    </section>
  );
}

export function Button({
  children,
  onClick,
  variant = "primary",
  disabled,
  busy,
  type = "button",
  ariaLabel,
}: {
  children: ReactNode;
  onClick?: () => void;
  variant?: "primary" | "secondary" | "danger" | "good";
  disabled?: boolean;
  busy?: boolean;
  type?: "button" | "submit";
  ariaLabel?: string;
}) {
  const styles = {
    primary: "bg-sky-600 hover:bg-sky-500 text-white",
    secondary: "bg-slate-800 hover:bg-slate-700 text-slate-100 ring-1 ring-inset ring-slate-700",
    danger: "bg-rose-600 hover:bg-rose-500 text-white",
    good: "bg-emerald-600 hover:bg-emerald-500 text-white",
  }[variant];
  return (
    <button
      type={type}
      aria-label={ariaLabel}
      onClick={onClick}
      disabled={disabled || busy}
      className={cx(
        "inline-flex items-center justify-center gap-2 rounded-lg px-3.5 py-2 text-sm font-semibold transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-400 disabled:cursor-not-allowed disabled:opacity-50",
        styles,
      )}
    >
      {busy && <Spinner />}
      {children}
    </button>
  );
}

export function Spinner() {
  return <span aria-hidden className="h-3.5 w-3.5 animate-spin rounded-full border-2 border-current border-t-transparent" />;
}

export function Empty({ children }: { children: ReactNode }) {
  return <p className="rounded-lg border border-dashed border-slate-800 px-4 py-6 text-center text-sm text-slate-500">{children}</p>;
}

export function ErrorNote({ error }: { error: string | null }) {
  if (!error) return null;
  return (
    <p role="alert" className="rounded-lg border border-rose-500/30 bg-rose-500/10 px-3 py-2 text-sm text-rose-200">
      {error}
    </p>
  );
}

export function decisionTone(decision: string | null): Tone {
  if (decision === "DENY") return "bad";
  if (decision === "REQUIRE_APPROVAL") return "warn";
  if (decision === "ALLOW") return "good";
  return "neutral";
}

export function statusTone(status: string): Tone {
  if (status === "ok" || status === "done") return "good";
  if (status === "denied" || status === "rejected" || status === "halted" || status === "failed" || status === "tool_error") return "bad";
  if (status.startsWith("approval") || status === "waiting") return "warn";
  if (status === "running") return "info";
  return "neutral";
}

export function LabelChip({ label }: { label: Label | null }) {
  if (!label) return <span className="text-slate-500">—</span>;
  return (
    <span className="inline-flex flex-wrap items-center gap-1">
      <Badge tone={label.integrity === "TRUSTED" ? "good" : label.integrity === "UNTRUSTED" ? "bad" : "neutral"}>{label.integrity}</Badge>
      <Badge tone={label.confidentiality === "SECRET" || label.confidentiality === "CONFIDENTIAL" ? "warn" : "neutral"}>{label.confidentiality}</Badge>
    </span>
  );
}

export function ModeBadge({ mode }: { mode: "on" | "off" }) {
  return mode === "on" ? <Badge tone="good">Shield ON</Badge> : <Badge tone="bad">Shield OFF</Badge>;
}

export function VerdictBadge({ kind, applicable, result }: { kind: "legit" | "attack"; applicable: boolean; result: boolean | null }) {
  if (!applicable || result === null) return <Badge>n/a</Badge>;
  if (kind === "legit") return result ? <Badge tone="good">Completed</Badge> : <Badge tone="warn">Not completed</Badge>;
  return result ? <Badge tone="bad">Attack succeeded</Badge> : <Badge tone="good">Attack blocked</Badge>;
}

export const fmtTime = (iso: string | number) => new Date(iso).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
export const shortId = (id: string) => `${id.slice(0, 13)}…`;
