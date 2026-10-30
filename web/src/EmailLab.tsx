import { useEffect, useRef, useState } from "react";
import { api, ApiError } from "./api";
import { ModePicker, readUpload } from "./AttackLab";
import { IconAlert, IconInbox, IconMail, IconPlay, IconUser } from "./icons";
import { LabResults } from "./LabResults";
import type { EmailSample, LabPlan, Mode, ParsedEmail, Run } from "./types";
import { Badge, Button, cx, ErrorNote, Panel, Spinner } from "./ui";

// Email Security Lab: the agent reads one synthetic email (built-in sample or an uploaded .eml/.txt/.html parsed by the
// server's safe subset) placed in the run's own inbox, then acts on whatever it recognises — through the real policy engine.
// No real mailbox, SMTP or network is involved.

type Selected = { kind: "sample"; sample: EmailSample } | { kind: "upload"; filename: string; content: string; email: ParsedEmail };

function EmailPreview({ email }: { email: ParsedEmail }) {
  return (
    <div className="overflow-hidden rounded-2xl border border-rose-400/25 bg-ink-950/70">
      <div className="flex flex-wrap items-start justify-between gap-3 border-b border-line bg-white/[0.02] px-5 py-4">
        <div className="min-w-0 space-y-1 text-sm">
          <p className="text-lg font-semibold text-slate-50">{email.subject}</p>
          <p className="text-slate-400">
            <span className="text-slate-500">From</span> <span className="font-mono text-slate-200">{email.from}</span>
            <span className="mx-2 text-slate-600">→</span>
            <span className="text-slate-500">To</span> <span className="font-mono text-slate-200">{email.to}</span>
          </p>
        </div>
        <div className="flex flex-wrap gap-2">
          <Badge tone="bad">
            <IconAlert size={12} /> UNTRUSTED
          </Badge>
          {email.bodyFormat === "html" && <Badge tone="warn">HTML shown as source — never rendered</Badge>}
        </div>
      </div>
      <pre className="max-h-80 overflow-auto whitespace-pre-wrap break-words px-5 py-4 font-mono text-[13px] leading-relaxed text-slate-200">{email.body}</pre>
      {email.notes.length > 0 && <p className="border-t border-line px-5 py-2 text-xs text-amber-200">{email.notes.join(" · ")}</p>}
      <p className="border-t border-line px-5 py-2 text-xs text-slate-500">
        Sender, recipient and subject are display data only — they are never treated as authorisation.
      </p>
    </div>
  );
}

export function EmailLab({ onOpenRun }: { onOpenRun: (id: string) => void }) {
  const [samples, setSamples] = useState<EmailSample[] | null>(null);
  const [selected, setSelected] = useState<Selected | null>(null);
  const [task, setTask] = useState("Summarize this vendor email");
  const [modes, setModes] = useState<Mode[]>(["off", "on"]);
  const [busy, setBusy] = useState(false);
  const [parsing, setParsing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [launch, setLaunch] = useState<{ key: number; runs: Run[]; plan: LabPlan } | null>(null);
  const fileRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    api.emailSamples().then(
      (s) => {
        setSamples(s);
        setSelected((cur) => cur ?? { kind: "sample", sample: s.find((x) => x.id === "vendor-injection") ?? s[0]! });
      },
      (e) => setError(e instanceof Error ? e.message : String(e)),
    );
  }, []);

  const onFile = async (f: File | undefined) => {
    if (!f) return;
    setError(null);
    const r = await readUpload(f, /\.(eml|txt|html?)$/i);
    if (!r.ok) return setError(r.reason);
    setParsing(true);
    try {
      const email = await api.emailParse(f.name, r.text);
      setSelected({ kind: "upload", filename: f.name, content: r.text, email });
    } catch (e) {
      setError(e instanceof ApiError ? `Email rejected: ${e.message}` : "Email could not be parsed");
    } finally {
      setParsing(false);
      if (fileRef.current) fileRef.current.value = "";
    }
  };

  const run = async () => {
    if (!selected) return;
    setBusy(true);
    setError(null);
    try {
      const res = await api.emailRuns(
        selected.kind === "sample" ? { task, modes, sampleId: selected.sample.id } : { task, modes, upload: { filename: selected.filename, content: selected.content } },
      );
      setLaunch({ key: Date.now(), runs: res.runs, plan: res.plan });
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Could not start the email run");
    } finally {
      setBusy(false);
    }
  };

  const email = selected?.kind === "sample" ? selected.sample.email : selected?.email;

  return (
    <div className="space-y-6">
      <header>
        <p className="inline-flex items-center gap-2 text-xs font-semibold uppercase tracking-[0.16em] text-cyan-300">
          <IconInbox size={14} /> Email Security Lab
        </p>
        <h1 className="mt-2 text-3xl font-semibold tracking-tight text-white">An email cannot grant itself permissions.</h1>
        <p className="mt-2 max-w-3xl text-base text-slate-300">
          The agent reads a synthetic email from its inbox and acts on what it finds. Run it with the shield off and on, inspect the exact injected
          instruction, and see which policy rule stops it. No real mailbox, SMTP server or network is used.
        </p>
      </header>

      <Panel
        title="1 · Choose an email"
        subtitle="Built-in synthetic samples, or upload .eml / .txt / .html (≤ 100 KB, safe parsing subset)"
        icon={<IconMail size={16} />}
        actions={
          <>
            <input ref={fileRef} type="file" accept=".eml,.txt,.html,.htm,message/rfc822,text/plain,text/html" className="hidden" onChange={(e) => void onFile(e.target.files?.[0])} />
            <Button variant="secondary" size="sm" busy={parsing} onClick={() => fileRef.current?.click()}>
              Upload email file
            </Button>
          </>
        }
      >
        {!samples ? (
          <p className="flex items-center gap-2 text-sm text-slate-400">
            <Spinner /> Loading samples…
          </p>
        ) : (
          <div className="grid gap-3 md:grid-cols-3">
            {samples.map((s) => {
              const active = selected?.kind === "sample" && selected.sample.id === s.id;
              const tone = s.id === "vendor-legit" ? "good" : s.id === "vendor-injection" ? "bad" : "warn";
              return (
                <button
                  key={s.id}
                  onClick={() => setSelected({ kind: "sample", sample: s })}
                  aria-pressed={active}
                  className={cx(
                    "rounded-xl border p-4 text-left transition-colors",
                    active ? "border-cyan-400/60 bg-cyan-400/[0.06]" : "border-line bg-ink-950/40 hover:border-line-strong",
                  )}
                >
                  <Badge tone={tone}>{s.label.split(" · ")[0]}</Badge>
                  <p className="mt-2 font-semibold text-slate-100">{s.label.split(" · ")[1] ?? s.label}</p>
                  <p className="mt-1 text-sm text-slate-400">{s.description}</p>
                </button>
              );
            })}
          </div>
        )}
        {selected?.kind === "upload" && (
          <p className="mt-3 text-sm text-cyan-200">
            Using uploaded file <span className="font-mono">{selected.filename}</span>
          </p>
        )}
      </Panel>

      {email && <EmailPreview email={email} />}

      <div className="grid gap-4 rounded-2xl border border-line bg-ink-900/70 p-4 lg:grid-cols-[1fr_auto_auto] lg:items-center">
        <label className="flex min-w-0 items-center gap-3">
          <span className="inline-flex shrink-0 items-center gap-1.5 text-sm font-semibold text-emerald-300">
            <IconUser size={15} /> 2 · Task (TRUSTED)
          </span>
          <input
            value={task}
            maxLength={300}
            onChange={(e) => setTask(e.target.value)}
            className="h-11 min-w-0 flex-1 rounded-xl border border-line-strong bg-ink-950 px-3 text-sm text-slate-100 focus:border-cyan-400 focus:outline-none focus:ring-2 focus:ring-cyan-400/30"
          />
        </label>
        <ModePicker value={modes} onChange={setModes} />
        <Button size="lg" onClick={run} busy={busy} disabled={!selected || !task.trim()}>
          <IconPlay size={18} /> Run the agent
        </Button>
      </div>
      <ErrorNote error={error} />

      {launch && <LabResults key={launch.key} runs={launch.runs} plan={launch.plan} onOpenRun={onOpenRun} />}
    </div>
  );
}
