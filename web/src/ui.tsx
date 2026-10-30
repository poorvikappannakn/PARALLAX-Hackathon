import type { ReactNode } from "react";
import { IconAlert, IconBan, IconCheck, IconClock, IconHand, IconShieldCheck, IconShieldOff } from "./icons";

// Shared presentational primitives. No data fetching here.

export function cx(...c: (string | false | null | undefined)[]) {
  return c.filter(Boolean).join(" ");
}

export type Tone = "neutral" | "good" | "bad" | "warn" | "info" | "brand";
const TONES: Record<Tone, string> = {
  neutral: "bg-white/[0.04] text-slate-300 ring-white/10",
  good: "bg-emerald-400/10 text-emerald-300 ring-emerald-400/25",
  bad: "bg-rose-500/10 text-rose-300 ring-rose-400/30",
  warn: "bg-amber-400/10 text-amber-300 ring-amber-400/30",
  info: "bg-sky-400/10 text-sky-300 ring-sky-400/25",
  brand: "bg-cyan-400/10 text-cyan-300 ring-cyan-400/30",
};

export function Badge({ tone = "neutral", children, title, className }: { tone?: Tone; children: ReactNode; title?: string; className?: string }) {
  return (
    <span
      title={title}
      className={cx("inline-flex items-center gap-1 whitespace-nowrap rounded-md px-2 py-0.5 text-xs font-medium ring-1 ring-inset", TONES[tone], className)}
    >
      {children}
    </span>
  );
}

export function Panel({
  title,
  subtitle,
  icon,
  actions,
  children,
  className,
  padded = true,
}: {
  title?: ReactNode;
  subtitle?: ReactNode;
  icon?: ReactNode;
  actions?: ReactNode;
  children: ReactNode;
  className?: string;
  padded?: boolean;
}) {
  return (
    <section className={cx("rounded-2xl border border-line bg-ink-900/80 shadow-[0_1px_0_rgb(255_255_255/0.03)_inset,0_20px_40px_-24px_rgb(0_0_0/0.6)] backdrop-blur", className)}>
      {(title || actions) && (
        <header className="flex flex-wrap items-center justify-between gap-3 border-b border-line px-5 py-4">
          <div className="flex min-w-0 items-center gap-3">
            {icon && <span className="grid h-8 w-8 shrink-0 place-items-center rounded-lg bg-white/[0.04] text-cyan-300 ring-1 ring-white/10">{icon}</span>}
            <div className="min-w-0">
              <h2 className="text-[15px] font-semibold text-slate-100">{title}</h2>
              {subtitle && <p className="mt-0.5 text-sm text-slate-400">{subtitle}</p>}
            </div>
          </div>
          {actions}
        </header>
      )}
      <div className={padded ? "p-5" : ""}>{children}</div>
    </section>
  );
}

export function Button({
  children,
  onClick,
  variant = "primary",
  size = "md",
  disabled,
  busy,
  type = "button",
  ariaLabel,
  className,
}: {
  children: ReactNode;
  onClick?: () => void;
  variant?: "primary" | "secondary" | "ghost" | "danger" | "good";
  size?: "sm" | "md" | "lg";
  disabled?: boolean;
  busy?: boolean;
  type?: "button" | "submit";
  ariaLabel?: string;
  className?: string;
}) {
  const styles = {
    primary: "bg-gradient-to-b from-cyan-400 to-cyan-500 text-ink-950 shadow-[0_8px_24px_-10px_rgb(34_211_238/0.7)] hover:from-cyan-300 hover:to-cyan-400",
    secondary: "bg-white/[0.05] text-slate-100 ring-1 ring-inset ring-white/12 hover:bg-white/[0.09]",
    ghost: "text-slate-300 hover:bg-white/[0.06] hover:text-white",
    danger: "bg-rose-500 text-white shadow-[0_8px_24px_-12px_rgb(244_63_94/0.8)] hover:bg-rose-400",
    good: "bg-emerald-500 text-ink-950 shadow-[0_8px_24px_-12px_rgb(16_185_129/0.8)] hover:bg-emerald-400",
  }[variant];
  const sizes = { sm: "h-8 px-3 text-sm", md: "h-10 px-4 text-sm", lg: "h-12 px-6 text-base" }[size];
  return (
    <button
      type={type}
      aria-label={ariaLabel}
      aria-busy={busy || undefined}
      onClick={onClick}
      disabled={disabled || busy}
      className={cx(
        "inline-flex items-center justify-center gap-2 rounded-xl font-semibold transition-all duration-150 active:scale-[0.98] disabled:cursor-not-allowed disabled:opacity-45 disabled:active:scale-100",
        styles,
        sizes,
        className,
      )}
    >
      {busy && <Spinner />}
      {children}
    </button>
  );
}

export function Spinner({ className }: { className?: string }) {
  return <span aria-hidden className={cx("h-4 w-4 animate-spin rounded-full border-2 border-current border-t-transparent", className)} />;
}

export function Empty({ icon, title, children }: { icon?: ReactNode; title: string; children?: ReactNode }) {
  return (
    <div className="flex flex-col items-center justify-center rounded-xl border border-dashed border-line-strong/70 px-6 py-10 text-center">
      {icon && <span className="mb-3 grid h-11 w-11 place-items-center rounded-full bg-white/[0.04] text-slate-400 ring-1 ring-white/10">{icon}</span>}
      <p className="text-sm font-semibold text-slate-200">{title}</p>
      {children && <p className="mt-1 max-w-md text-sm text-slate-400">{children}</p>}
    </div>
  );
}

export function ErrorNote({ error }: { error: string | null }) {
  if (!error) return null;
  return (
    <p role="alert" className="flex items-start gap-2 rounded-xl border border-rose-400/30 bg-rose-500/10 px-4 py-3 text-sm text-rose-200">
      <IconAlert size={16} className="mt-0.5 shrink-0" />
      {error}
    </p>
  );
}

export function Stat({ label, value, hint, tone, icon }: { label: string; value: ReactNode; hint?: ReactNode; tone?: "good" | "bad" | "warn" | "brand"; icon?: ReactNode }) {
  const color = { good: "text-emerald-300", bad: "text-rose-300", warn: "text-amber-300", brand: "text-cyan-300" }[tone ?? "brand"] ?? "text-slate-100";
  return (
    <div className="rounded-2xl border border-line bg-ink-900/70 p-5">
      <div className="flex items-center justify-between gap-2">
        <p className="text-xs font-semibold uppercase tracking-[0.12em] text-slate-400">{label}</p>
        {icon && <span className="text-slate-500">{icon}</span>}
      </div>
      <p className={cx("mt-2 text-3xl font-semibold tabular-nums tracking-tight", tone ? color : "text-slate-50")}>{value}</p>
      {hint && <p className="mt-1 text-sm text-slate-400">{hint}</p>}
    </div>
  );
}

// ---- decisions ------------------------------------------------------------------------------------------------------

export type DecisionKind = "ALLOW" | "DENY" | "REQUIRE_APPROVAL" | "OTHER";
export function decisionKind(decision: string | null | undefined): DecisionKind {
  if (decision === "ALLOW" || decision === "APPROVED") return "ALLOW";
  if (decision === "DENY" || decision === "REJECTED") return "DENY";
  if (decision === "REQUIRE_APPROVAL") return "REQUIRE_APPROVAL";
  return "OTHER";
}
export const decisionTone = (d: string | null | undefined): Tone =>
  ({ ALLOW: "good", DENY: "bad", REQUIRE_APPROVAL: "warn", OTHER: "neutral" } as const)[decisionKind(d)];

/** Large, unambiguous decision chip (ALLOW green / DENY red / REQUIRE_APPROVAL amber). */
export function DecisionChip({ decision, ruleId }: { decision: string | null; ruleId?: string | null }) {
  const k = decisionKind(decision);
  const label = k === "REQUIRE_APPROVAL" ? "Needs approval" : k === "ALLOW" ? "Allowed" : k === "DENY" ? "Denied" : (decision ?? "—");
  const Icon = k === "ALLOW" ? IconCheck : k === "DENY" ? IconBan : k === "REQUIRE_APPROVAL" ? IconHand : IconClock;
  return (
    <span className={cx("inline-flex items-center gap-1.5 rounded-lg px-2.5 py-1 text-xs font-semibold ring-1 ring-inset", TONES[decisionTone(decision)])}>
      <Icon size={14} />
      {label}
      {ruleId && <span className="font-mono text-[11px] opacity-80">· {ruleId}</span>}
    </span>
  );
}

export function statusTone(status: string): Tone {
  if (status === "ok" || status === "done") return "good";
  if (["denied", "rejected", "halted", "failed", "tool_error", "step_limit"].includes(status)) return "bad";
  if (status.startsWith("approval") || status === "waiting") return "warn";
  if (status === "running" || status === "created") return "brand";
  return "neutral";
}

export const STATE_LABEL: Record<string, string> = {
  created: "Starting",
  running: "Executing",
  waiting: "Awaiting approval",
  done: "Completed",
  halted: "Halted (fail-closed)",
  step_limit: "Step limit reached",
};

export function ModeBadge({ mode, size = "sm" }: { mode: "on" | "off"; size?: "sm" | "md" }) {
  const md = size === "md";
  return mode === "on" ? (
    <span className={cx("inline-flex items-center gap-1.5 rounded-lg bg-emerald-400/10 font-semibold text-emerald-300 ring-1 ring-inset ring-emerald-400/30", md ? "px-3 py-1.5 text-sm" : "px-2 py-0.5 text-xs")}>
      <IconShieldCheck size={md ? 16 : 13} /> Shield ON
    </span>
  ) : (
    <span className={cx("inline-flex items-center gap-1.5 rounded-lg bg-rose-500/10 font-semibold text-rose-300 ring-1 ring-inset ring-rose-400/30", md ? "px-3 py-1.5 text-sm" : "px-2 py-0.5 text-xs")}>
      <IconShieldOff size={md ? 16 : 13} /> Shield OFF
    </span>
  );
}

export function VerdictBadge({ kind, applicable, result }: { kind: "legit" | "attack"; applicable: boolean; result: boolean | null }) {
  if (!applicable || result === null) return <Badge>Not applicable</Badge>;
  if (kind === "legit")
    return result ? (
      <Badge tone="good">
        <IconCheck size={13} /> Completed
      </Badge>
    ) : (
      <Badge tone="warn">Not completed</Badge>
    );
  return result ? (
    <Badge tone="bad">
      <IconAlert size={13} /> Attack succeeded
    </Badge>
  ) : (
    <Badge tone="good">
      <IconShieldCheck size={13} /> Attack blocked
    </Badge>
  );
}

export const fmtTime = (iso: string | number) => new Date(iso).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
export const shortId = (id: string) => `${id.slice(0, 13)}…`;
