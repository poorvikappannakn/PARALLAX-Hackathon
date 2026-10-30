import type { ReactNode } from "react";
import { IconBan, IconBug, IconCheck, IconKey, IconTrash } from "./icons";

// Presentation metadata per scenario category: icon, threat label and a fixed severity label.
// These are design annotations, not measurements; all results shown elsewhere come from the API.

export interface CategoryMeta {
  label: string;
  threat: string;
  severity: { label: string; tone: "neutral" | "bad" | "warn" | "info" };
  icon: (size?: number) => ReactNode;
  accent: string; // tailwind classes for the icon tile
}

export const CATEGORY_META: Record<string, CategoryMeta> = {
  legitimate: {
    label: "Legitimate task",
    threat: "Baseline — no attack",
    severity: { label: "Baseline", tone: "neutral" },
    icon: (s = 22) => <IconCheck size={s} />,
    accent: "bg-emerald-400/10 text-emerald-300 ring-emerald-400/25",
  },
  prompt_injection: {
    label: "Prompt injection",
    threat: "Indirect prompt injection → data exfiltration",
    severity: { label: "Critical", tone: "bad" },
    icon: (s = 22) => <IconBug size={s} />,
    accent: "bg-rose-500/15 text-rose-300 ring-rose-400/30",
  },
  sensitive_data: {
    label: "Sensitive-data access",
    threat: "Read above the user's clearance",
    severity: { label: "High", tone: "warn" },
    icon: (s = 22) => <IconKey size={s} />,
    accent: "bg-amber-400/10 text-amber-300 ring-amber-400/25",
  },
  excess_permission: {
    label: "Beyond-permission action",
    threat: "Destructive tool outside the agent's profile",
    severity: { label: "High", tone: "warn" },
    icon: (s = 22) => <IconTrash size={s} />,
    accent: "bg-amber-400/10 text-amber-300 ring-amber-400/25",
  },
  fail_closed: {
    label: "Fail-closed edge cases",
    threat: "Malformed, unknown and forged requests",
    severity: { label: "Medium", tone: "info" },
    icon: (s = 22) => <IconBan size={s} />,
    accent: "bg-sky-400/10 text-sky-300 ring-sky-400/25",
  },
};

export const metaFor = (category: string): CategoryMeta =>
  CATEGORY_META[category] ?? { label: category, threat: "", severity: { label: "—", tone: "neutral" }, icon: (s = 22) => <IconCheck size={s} />, accent: "bg-white/5 text-slate-300 ring-white/10" };
