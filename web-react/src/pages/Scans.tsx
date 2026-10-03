import { useEffect, useMemo, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { api, type EvidenceArtifacts, type EvidencePrompts, type EvidenceLog } from "@/lib/api";
import { usePoll } from "@/lib/usePoll";
import { useEvents } from "@/lib/useEvents";
import type { ConfigResp, CoverageAxes, Job, PhaseDef, ReviewUnitsSummary } from "@/lib/types";
import { Button } from "@/components/ui/button";
import { Tabs } from "@/components/ui/tabs";
import { StepTracker } from "@/components/StepTracker";
import { NewScan } from "./NewScan";
import { cn, fmtDuration, fmtDateTime } from "@/lib/utils";

const DOT: Record<string, string> = {
  running: "bg-accent animate-pulse",
  queued: "bg-warn",
  done: "bg-ok",
  failed: "bg-err",
  cancelled: "bg-err",
  interrupted: "bg-err",
};

// The Scans tab leads with launching a scan; History & live is the second sub-tab.
export function Scans() {
  const [tab, setTab] = useState<"new" | "history">("new");
  const [openId, setOpenId] = useState<string | null>(null);

  return (
    <div>
      <div className="mb-4 flex items-center gap-3">
        <h1 className="text-xl font-semibold text-text-1">Scans</h1>
      </div>
      <Tabs
        value={tab}
        onChange={(t) => setTab(t as typeof tab)}
        tabs={[
          { key: "new", label: "New scan" },
          { key: "history", label: "History & live" },
        ]}
      />
      <div className="mt-5">
        {tab === "new" ? (
          <NewScan
            onLaunched={(id) => {
              setOpenId(id);
              setTab("history");
            }}
          />
        ) : (
          <ScanHistory selectId={openId} />
        )}
      </div>
    </div>
  );
}

function ScanHistory({ selectId }: { selectId: string | null }) {
  const scans = usePoll(() => api.scans(), 4000);
  const cfg = usePoll<ConfigResp>(() => api.config(), 0);
  const [sel, setSel] = useState<string | null>(selectId);

  const jobs = scans.data?.jobs || [];
  useEffect(() => {
    if (selectId) setSel(selectId);
  }, [selectId]);
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
          <h2 className="text-[13px] font-semibold uppercase tracking-wide text-text-3">All runs</h2>
          <span className="rounded-full bg-surface-2 px-2 py-0.5 text-xs text-text-3">{jobs.length}</span>
        </div>
        <div className="flex flex-col gap-1.5">
          {scans.error ? (
            <div className="rounded-md border border-err/40 bg-err-weak px-3 py-2 text-sm text-err">
              Couldn’t load scans: {scans.error}
            </div>
          ) : scans.loading && !scans.data ? (
            <div className="text-sm text-text-3">Loading scans…</div>
          ) : (
            jobs.length === 0 && <div className="text-sm text-text-3">No scans yet.</div>
          )}
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

// Intelligence surfaces the explicit availability of the threat model + SBOM with a
// download link when present — never a bare present/absent (feature 007, US4/T029).
function Intelligence({ job }: { job: Job }) {
  const items: { label: string; file: string; m?: { state: string; path?: string } }[] = [
    { label: "Threat model", file: "threat_model.md", m: job.threat_model },
    { label: "SBOM", file: "sbom.cdx.json", m: job.sbom },
  ];
  if (!job.threat_model && !job.sbom) return null;
  return (
    <div className="mb-3 flex flex-wrap gap-2 text-[12px]">
      {items.map(({ label, file, m }) => {
        if (!m) return null;
        const href = `/api/scans/${job.id}/file?path=${encodeURIComponent(m.path || file)}`;
        return (
          <span key={label} className="rounded border border-line bg-surface-1 px-2 py-1 text-text-2">
            {label}:{" "}
            {m.state === "available" ? (
              <a className="text-accent underline" href={href} target="_blank" rel="noreferrer">available ↗</a>
            ) : (
              <span className="text-text-3">{m.state.replace(/_/g, " ")}</span>
            )}
          </span>
        );
      })}
    </div>
  );
}

// Source review (feature 015, FR-015/019): completed vs exposed with the evidence
// standard, and every v2 axis listed — none derived from another. Absent for runs
// without a review-unit record.
const AXES: [keyof CoverageAxes, string][] = [
  ["discovered", "discovered"], ["supported_inventory", "supported inventory"], ["assigned", "assigned"],
  ["attempted", "attempted"], ["source_exposed", "source exposed"], ["completed_review", "completed review"], ["verified", "verified"],
];
function SourceReview({ ru }: { ru?: ReviewUnitsSummary }) {
  const c = ru?.counts;
  if (!ru || !c || !c.total) return null;
  const done = (c.reviewed_with_findings || 0) + (c.reviewed_no_issue || 0);
  return (
    <div className="mb-3 rounded-lg border border-line bg-surface-1 px-3 py-2 text-[12px] text-text-2">
      <div>
        Source review <b className="font-mono text-text-1">{done}/{c.total}</b> completed
        {ru.axes ? <> · <b className="font-mono text-text-1">{ru.axes.source_exposed}</b> exposed</> : <> · exposure = completion</>}
        <span className="text-text-3"> ({ru.semantics_label || "read-overlap evidence (v1)"})</span>
      </div>
      {ru.axes && (
        <div className="mt-1 flex flex-wrap gap-x-3 gap-y-0.5 text-[11px] text-text-3">
          {AXES.map(([k, label]) => (
            <span key={k}>{label}: <span className="font-mono text-text-2">{ru.axes![k]}</span></span>
          ))}
        </div>
      )}
    </div>
  );
}

function ScanDetail({ job, phases, onChange }: { job: Job; phases: PhaseDef[]; onChange: () => void }) {
  const navigate = useNavigate();
  const running = job.status === "running" || job.status === "queued";
  const reportId = job.results_dir ? job.results_dir.split("/").filter(Boolean).pop() || null : null;
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
        {reportId && !running && (
          <Button variant="secondary" size="sm" onClick={() => navigate(`/reports?open=${reportId}`)}>
            View report →
          </Button>
        )}
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

      <Intelligence job={job} />

      <SourceReview ru={job.review_units} />

      <StepTracker job={job} phases={phases} />

      <Evidence jobId={job.id} running={running} status={job.status} />

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

// ---------------------------------------------------------------------------
// Feature 014 — scan evidence (Artifacts / Prompts / Log) for /app (FR-003/004/009).
// Polls while running (and once more on termination), aborts superseded requests,
// ignores stale responses after the job changes, and renders every evidence state
// explicitly — never an empty list or an endless "Loading…".
// ---------------------------------------------------------------------------
const EV_MSG: Record<string, string> = {
  unknown: "This scan is unknown to the server.",
  not_started: "Queued — the engine has not started this scan yet.",
  running_no_files: "Scan is running — nothing has been written yet. Updates automatically.",
  empty: "This scan finished without writing any files.",
  unavailable: "The results directory is unavailable (missing or unreadable).",
  no_records: "No prompt records were captured for this scan.",
  not_recorded: "Prompts were not recorded by this version of the scanner for this scan.",
  no_lines: "No log lines were recorded for this scan.",
  error: "Could not load this evidence.",
};

function useEvidence<T extends { state: string; reason?: string; error?: string }>(
  jobId: string, running: boolean, load: (signal: AbortSignal) => Promise<T & { httpStatus: number }>,
) {
  const [data, setData] = useState<(T & { httpStatus: number }) | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const seq = useRef(0);
  useEffect(() => {
    let ctl: AbortController | null = null;
    const tick = async () => {
      if (ctl) ctl.abort();
      ctl = new AbortController();
      const my = ++seq.current;
      try {
        const d = await load(ctl.signal);
        if (my !== seq.current) return; // superseded / job changed
        setData(d); setErr(null);
      } catch (e) {
        if ((e as Error).name === "AbortError" || my !== seq.current) return;
        setErr(String((e as Error).message || e));
      }
    };
    tick();
    const iv = running ? window.setInterval(tick, 4000) : 0;
    // One extra refresh when the run just terminated is achieved by the `running`
    // dependency change re-running this effect.
    return () => { if (iv) window.clearInterval(iv); if (ctl) ctl.abort(); seq.current++; };
  }, [jobId, running, load]);
  return { data, err };
}

function StateNote({ state, reason }: { state?: string; reason?: string }) {
  const msg = (state && EV_MSG[state]) || "Unavailable.";
  const bad = state === "unavailable" || state === "error" || state === "unknown";
  return (
    <div className={cn("rounded-md border px-3 py-2 text-sm", bad ? "border-err/40 bg-err-weak text-err" : "border-line bg-surface-1 text-text-3")} data-evstate={state || ""}>
      {msg}{reason ? <span className="ml-1 opacity-70">({reason})</span> : null}
    </div>
  );
}

function Evidence({ jobId, running, status }: { jobId: string; running: boolean; status: string }) {
  const [open, setOpen] = useState<"files" | "prompts" | "log">("files");
  const [follow, setFollow] = useState(true);
  const logRef = useRef<HTMLPreElement>(null);

  const loadFiles = useMemo(() => (s: AbortSignal) => api.scanArtifacts(jobId, 0, 200, s), [jobId]);
  const loadPrompts = useMemo(() => (s: AbortSignal) => api.scanPrompts(jobId, 0, 100, s), [jobId]);
  const loadLog = useMemo(() => (s: AbortSignal) => api.scanLog(jobId, 500, 0, s), [jobId]);
  const files = useEvidence<EvidenceArtifacts>(jobId, running && open === "files", loadFiles);
  const prompts = useEvidence<EvidencePrompts>(jobId, running && open === "prompts", loadPrompts);
  const log = useEvidence<EvidenceLog>(jobId, running && open === "log", loadLog);

  useEffect(() => {
    if (follow && logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight;
  }, [log.data, follow]);

  const tab = (k: "files" | "prompts" | "log", label: string) => (
    <button key={k} onClick={() => setOpen(k)} className={cn("rounded px-2.5 py-1 text-[12px]", open === k ? "bg-accent text-white" : "text-text-2 hover:bg-surface-2")}>{label}</button>
  );

  return (
    <div className="mt-4">
      <div className="mb-1.5 flex items-center gap-2 text-[11px] font-semibold uppercase tracking-wide text-text-3">
        Evidence <span className="normal-case text-text-3/70">· {status}</span>
        <span className="flex-1" />
        {tab("files", "Artifacts")}{tab("prompts", "Prompts")}{tab("log", "Log")}
      </div>
      {open === "files" && (
        files.err ? <StateNote state="error" reason={files.err} /> :
        !files.data ? <div className="text-sm text-text-3">Loading…</div> :
        !files.data.files?.length ? <StateNote state={files.data.state} reason={files.data.reason || files.data.error} /> :
        <div className="rounded-lg border border-line bg-surface-1">
          <table className="w-full text-[12.5px]"><tbody>
            {files.data.files.map((f) => (
              <tr key={f.path} className="border-b border-line/60 last:border-0">
                <td className="px-3 py-1.5"><a className="text-accent hover:underline" href={`/api/scans/${encodeURIComponent(jobId)}/file?path=${encodeURIComponent(f.path)}`} target="_blank" rel="noreferrer">{f.path}</a></td>
                <td className="px-3 py-1.5 text-right text-text-3">{(f.size / 1024).toFixed(1)} KB</td>
              </tr>
            ))}
          </tbody></table>
          {files.data.next_offset != null && <div className="px-3 py-1.5 text-[11px] text-text-3">Showing {files.data.files.length} of {files.data.total} files.</div>}
        </div>
      )}
      {open === "prompts" && (
        prompts.err ? <StateNote state="error" reason={prompts.err} /> :
        !prompts.data ? <div className="text-sm text-text-3">Loading…</div> :
        !prompts.data.records?.length ? <StateNote state={prompts.data.state} reason={prompts.data.reason || prompts.data.error} /> :
        <div className="space-y-1.5">
          <div className="text-[11px] text-text-3">Actual prompts sent, one record per model call ({prompts.data.total} total); repair/canary/repartition calls have their own kind.</div>
          {prompts.data.records.map((r) => (
            <details key={r.seq} className="rounded-lg border border-line bg-surface-1 px-3 py-1.5">
              <summary className="cursor-pointer text-[12.5px]"><b>{r.label}</b> <span className="text-text-3">seq {r.seq} · phase {r.phase} · {r.role}/{r.model} · {r.kind}{r.truncated ? " · stored preview (8 KB clamp); full text not stored" : ""}{r.redactions?.length ? ` · redacted: ${r.redactions.join(", ")}` : ""}</span></summary>
              <div className="mt-1 text-[11px] text-text-3">System</div>
              <pre className="max-h-48 overflow-auto whitespace-pre-wrap font-mono text-[11px] text-text-2">{r.system}</pre>
              <div className="mt-1 text-[11px] text-text-3">Task</div>
              <pre className="max-h-48 overflow-auto whitespace-pre-wrap font-mono text-[11px] text-text-2">{r.task}</pre>
              {r.error && <div className="mt-1 text-[11px] text-err">{r.error}</div>}
            </details>
          ))}
        </div>
      )}
      {open === "log" && (
        log.err ? <StateNote state="error" reason={log.err} /> :
        !log.data ? <div className="text-sm text-text-3">Loading…</div> :
        !log.data.lines?.length ? <StateNote state={log.data.state} reason={log.data.reason || log.data.error} /> :
        <div>
          <label className="mb-1 flex items-center gap-1.5 text-[11px] text-text-3"><input type="checkbox" checked={follow} onChange={(e) => setFollow(e.target.checked)} /> follow</label>
          <pre ref={logRef} className="h-64 overflow-auto rounded-[var(--radius-sm,8px)] border border-line bg-surface-1 p-3 font-mono text-[11px] leading-relaxed text-text-2">{log.data.lines.join("\n")}</pre>
        </div>
      )}
    </div>
  );
}
