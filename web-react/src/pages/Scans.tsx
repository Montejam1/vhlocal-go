import { useEffect, useRef, useState } from "react";
import { api } from "@/lib/api";
import { usePoll } from "@/lib/usePoll";
import { useEvents } from "@/lib/useEvents";
import type { Job, PhaseDef } from "@/lib/types";
import { Button } from "@/components/ui/button";
import { StepTracker } from "@/components/StepTracker";
import { cn, fmtDuration, fmtDateTime } from "@/lib/utils";

const DOT: Record<string, string> = {
  running: "bg-accent animate-pulse",
  queued: "bg-warn",
  done: "bg-ok",
  failed: "bg-err",
  cancelled: "bg-err",
  interrupted: "bg-err",
};

export function Scans() {
  const scans = usePoll(() => api.scans(), 4000);
  const cfg = usePoll<{ phases: PhaseDef[] }>(() => api.config(), 0);
  const [sel, setSel] = useState<string | null>(null);

  const jobs = scans.data?.jobs || [];
  useEffect(() => {
    if (sel && jobs.some((j) => j.id === sel)) return;
    const pick = jobs.find((j) => ["running", "queued"].includes(j.status)) || jobs[0];
    if (pick) setSel(pick.id);
  }, [jobs, sel]);

  const job = jobs.find((j) => j.id === sel) || null;

  return (
    <div className="grid grid-cols-1 gap-5 lg:grid-cols-[300px_1fr]">
      <div>
        <div className="mb-3 flex items-center gap-2">
          <h1 className="text-xl font-semibold text-text-1">Scans</h1>
          <span className="rounded-full bg-surface-2 px-2 py-0.5 text-xs text-text-3">{jobs.length}</span>
        </div>
        <div className="flex flex-col gap-1.5">
          {jobs.length === 0 && <div className="text-sm text-text-3">No scans yet.</div>}
          {jobs.map((j) => (
            <button
              key={j.id}
              onClick={() => setSel(j.id)}
              className={cn(
                "flex flex-col gap-1 rounded-lg border px-3 py-2 text-left transition-colors",
                j.id === sel ? "border-accent bg-accent-weak" : "border-line bg-surface-1 hover:border-line-strong",
              )}
            >
              <div className="flex items-center gap-2">
                <span className={cn("h-2 w-2 shrink-0 rounded-full", DOT[j.status] || "bg-text-3")} />
                <span className="truncate text-[13px] font-medium text-text-1">
                  {j.spec?.repo?.split("/").filter(Boolean).pop() || j.id}
                </span>
              </div>
              <div className="flex items-center gap-2 pl-4 text-[11px] text-text-3">
                <span className="truncate font-mono">{j.current_model || j.spec?.model}</span>
                <span className="ml-auto">{fmtDuration(j.elapsed)}</span>
              </div>
            </button>
          ))}
        </div>
      </div>

      <div>
        {!job && <div className="py-16 text-center text-text-3">Select a scan.</div>}
        {job && cfg.data && <ScanDetail job={job} phases={cfg.data.phases} onChange={scans.refresh} />}
      </div>
    </div>
  );
}

function ScanDetail({ job, phases, onChange }: { job: Job; phases: PhaseDef[]; onChange: () => void }) {
  const running = job.status === "running" || job.status === "queued";
  const feed = useEvents(job.id, running);
  const feedRef = useRef<HTMLPreElement>(null);
  useEffect(() => {
    if (feedRef.current) feedRef.current.scrollTop = feedRef.current.scrollHeight;
  }, [feed]);

  const cancel = async () => {
    try {
      await api.cancelScan(job.id);
      onChange();
    } catch (e) {
      alert(String((e as Error).message || e));
    }
  };

  const tiles: [string, string][] = [
    ["Model", job.current_model || job.spec?.model || "—"],
    ["Tokens", `${(job.prompt_tokens / 1e6).toFixed(1)}M in · ${(job.completion_tokens / 1e3).toFixed(0)}K out`],
    ["Findings", String(job.findings_count ?? "—")],
    ["Elapsed", fmtDuration(job.elapsed)],
  ];

  return (
    <div>
      <div className="mb-3 flex flex-wrap items-center gap-2">
        <span className={cn("h-2.5 w-2.5 rounded-full", DOT[job.status] || "bg-text-3")} />
        <b className="font-mono text-text-1">{job.spec?.repo}</b>
        <span className="rounded border border-line bg-surface-2 px-2 py-0.5 text-[11px] uppercase text-text-2">
          {job.status}
        </span>
        <span className="flex-1" />
        {running && (
          <Button variant="danger" size="sm" onClick={cancel}>
            Cancel
          </Button>
        )}
      </div>

      {job.error && (
        <div className="mb-3 rounded-md border border-err/40 bg-err-weak px-3 py-2 text-sm text-err">{job.error}</div>
      )}

      <div className="mb-3 grid grid-cols-2 gap-2 sm:grid-cols-4">
        {tiles.map(([label, val]) => (
          <div key={label} className="rounded-lg border border-line bg-surface-1 px-3 py-2">
            <div className="text-[10px] uppercase tracking-wide text-text-3">{label}</div>
            <div className="mt-0.5 truncate font-mono text-[13px] text-text-1" title={val}>{val}</div>
          </div>
        ))}
      </div>

      <StepTracker job={job} phases={phases} />

      <div className="mt-4">
        <div className="mb-1.5 flex items-center gap-2 text-[11px] font-semibold uppercase tracking-wide text-text-3">
          Live feed
          {running && <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-accent" />}
          {!running && <span className="normal-case text-text-3/70">· scan {job.status}</span>}
        </div>
        <pre
          ref={feedRef}
          className="h-72 overflow-auto rounded-[var(--radius-sm,8px)] border border-line bg-surface-1 p-3 font-mono text-[11.5px] leading-relaxed text-text-2"
        >
          {running && feed.length === 0 ? "Waiting for events…" : ""}
          {!running && feed.length === 0
            ? "This scan is not running — its live feed is closed. See its report for results."
            : ""}
          {feed.map((l, i) => (
            <div key={i} className={cn(l.kind === "error" || l.kind === "budget_halted" ? "text-err" : l.kind === "phase_start" ? "text-accent" : "")}>
              {l.text}
            </div>
          ))}
        </pre>
        <div className="mt-1 text-right text-[11px] text-text-3">Last run at {fmtDateTime(job.created_at)}</div>
      </div>
    </div>
  );
}
