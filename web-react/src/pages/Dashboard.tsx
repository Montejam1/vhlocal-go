import { Search, ShieldAlert, Hash, Gauge, Clock } from "lucide-react";
import { useNavigate } from "react-router-dom";
import { api } from "@/lib/api";
import { usePoll } from "@/lib/usePoll";
import type { Job, PhaseDef, Stats } from "@/lib/types";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { StepTracker } from "@/components/StepTracker";
import { fmtDuration, fmtDateTime } from "@/lib/utils";

function compact(n: number): string {
  if (n >= 1e9) return (n / 1e9).toFixed(2) + "B";
  if (n >= 1e6) return (n / 1e6).toFixed(2) + "M";
  if (n >= 1e3) return (n / 1e3).toFixed(1) + "K";
  return String(n);
}

const TILE = [
  { key: "scans", icon: Search, tint: "accent" },
  { key: "vulns", icon: ShieldAlert, tint: "err" },
  { key: "tokens", icon: Hash, tint: "accent" },
  { key: "avg", icon: Gauge, tint: "ok" },
  { key: "time", icon: Clock, tint: "warn" },
] as const;

const TINT: Record<string, string> = {
  accent: "bg-accent-weak text-accent",
  err: "bg-err-weak text-err",
  ok: "bg-ok-weak text-ok",
  warn: "bg-warn-weak text-warn",
};

export function Dashboard() {
  const stats = usePoll<Stats>(() => api.stats(), 0);
  const scans = usePoll(() => api.scans(), 4000);
  const cfg = usePoll<{ phases: PhaseDef[] }>(() => api.config(), 0);
  const s = stats.data;

  const jobs = scans.data?.jobs || [];
  const latest = jobs.find((j) => ["running", "queued"].includes(j.status)) || jobs[0];
  const recent = jobs.filter((j) => j.findings_count >= 0).slice(0, 16).reverse();
  const maxFind = Math.max(1, ...recent.map((j) => j.findings_count || 0));

  const tileData: Record<string, { value: string; label: string; sub?: string }> = s
    ? {
        scans: { value: String(s.scans), label: "Scans run" },
        vulns: { value: String(s.findings), label: "Vulnerabilities found", sub: `${s.avg_findings_per_scan} avg / scan` },
        tokens: {
          value: compact(s.total_tokens),
          label: "Tokens used",
          sub: `${compact(s.prompt_tokens)} in · ${compact(s.completion_tokens)} out`,
        },
        avg: { value: compact(s.avg_tokens_per_scan), label: "Avg tokens / scan", sub: `${s.with_usage} of ${s.scans} recorded` },
        time: { value: fmtDuration(s.total_seconds), label: "Total scan time", sub: `${fmtDuration(s.avg_seconds_per_scan)} avg / scan` },
      }
    : {};

  const byModel = s
    ? Object.entries(s.by_model)
        .map(([m, v]) => ({ model: m, avg: v.scans ? v.findings / v.scans : 0, scans: v.scans }))
        .sort((a, b) => b.avg - a.avg)
    : [];
  const maxAvg = Math.max(1, ...byModel.map((m) => m.avg));

  return (
    <div>
      <div className="flex items-center gap-3">
        <h1 className="text-xl font-semibold text-text-1">Dashboard</h1>
        <span className="flex-1" />
        <Button variant="secondary" size="sm" onClick={() => { stats.refresh(); scans.refresh(); }}>
          Refresh
        </Button>
      </div>

      {/* Metric tiles */}
      <div className="mt-4 grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-5">
        {TILE.map(({ key, icon: Icon, tint }) => {
          const d = tileData[key];
          return (
            <Card key={key} className="flex flex-col gap-2">
              <span className={`grid h-8 w-8 place-items-center rounded-lg ${TINT[tint]}`}>
                <Icon size={16} />
              </span>
              <div className="text-2xl font-bold text-text-1">{d?.value ?? "—"}</div>
              <div className="text-xs text-text-2">{d?.label ?? ""}</div>
              {d?.sub && <div className="text-[11px] text-text-3">{d.sub}</div>}
            </Card>
          );
        })}
      </div>

      {/* Charts */}
      <div className="mt-3 grid grid-cols-1 gap-3 lg:grid-cols-2">
        <Card>
          <h3 className="text-[11px] font-semibold uppercase tracking-wide text-text-3">
            Findings per scan <span className="text-text-3/70">· recent</span>
          </h3>
          <div className="mt-4 flex h-40 items-end gap-1.5">
            {recent.length === 0 && <div className="text-sm text-text-3">No scans yet.</div>}
            {recent.map((j) => (
              <div
                key={j.id}
                className="flex-1 rounded-t bg-accent/80 transition-all hover:bg-accent"
                style={{ height: `${Math.max(3, (100 * (j.findings_count || 0)) / maxFind)}%` }}
                title={`${j.spec?.repo?.split("/").pop() || j.id}: ${j.findings_count} findings`}
              />
            ))}
          </div>
          <div className="mt-2 text-[11px] text-text-3">Last {recent.length} scans · newest at right</div>
        </Card>

        <Card>
          <h3 className="text-[11px] font-semibold uppercase tracking-wide text-text-3">
            By model <span className="text-text-3/70">· avg findings / scan</span>
          </h3>
          <div className="mt-4 flex flex-col gap-2">
            {byModel.slice(0, 9).map((m) => (
              <div key={m.model} className="flex items-center gap-3 text-[12px]">
                <span className="w-40 truncate text-text-2" title={m.model}>{m.model}</span>
                <div className="h-2 flex-1 overflow-hidden rounded-full bg-surface-3">
                  <div className="h-full rounded-full bg-accent" style={{ width: `${(100 * m.avg) / maxAvg}%` }} />
                </div>
                <span className="w-16 text-right font-mono text-text-3">
                  {m.avg.toFixed(1)} · {m.scans}×
                </span>
              </div>
            ))}
          </div>
        </Card>
      </div>

      {/* Latest scan */}
      <h2 className="mt-6 mb-3 text-lg font-semibold text-text-1">Latest scan</h2>
      {latest && cfg.data ? (
        <LatestScan job={latest} phases={cfg.data.phases} />
      ) : (
        <div className="py-6 text-center text-text-3">No scans yet.</div>
      )}
    </div>
  );
}

function LatestScan({ job, phases }: { job: Job; phases: PhaseDef[] }) {
  const navigate = useNavigate();
  const dot: Record<string, string> = {
    running: "bg-accent animate-pulse",
    done: "bg-ok",
    queued: "bg-warn",
    failed: "bg-err",
    cancelled: "bg-err",
    interrupted: "bg-err",
  };
  const tiles: [string, string][] = [
    ["Model", job.current_model || job.spec?.model || "—"],
    ["Tokens", `${(job.prompt_tokens / 1e6).toFixed(1)}M in · ${(job.completion_tokens / 1e3).toFixed(0)}K out`],
    ["Findings", String(job.findings_count ?? "—")],
    ["Elapsed", fmtDuration(job.elapsed)],
  ];
  return (
    <div>
      <div className="mb-3 flex flex-wrap items-center gap-2 text-sm">
        <span className={`h-2 w-2 rounded-full ${dot[job.status] || "bg-text-3"}`} />
        <b className="font-mono text-text-1">{job.spec?.repo || job.id}</b>
        <span className="rounded border border-line bg-surface-2 px-2 py-0.5 text-[11px] uppercase text-text-2">
          {job.status}
        </span>
        <span className="text-text-3">· started {fmtDateTime(job.created_at)}</span>
        <span className="flex-1" />
        <Button variant="secondary" size="sm" onClick={() => navigate("/scans")}>
          Open scan →
        </Button>
      </div>
      <div className="mb-3 grid grid-cols-2 gap-2 sm:grid-cols-4">
        {tiles.map(([label, val]) => (
          <div key={label} className="rounded-lg border border-line bg-surface-1 px-3 py-2">
            <div className="text-[10px] uppercase tracking-wide text-text-3">{label}</div>
            <div className="mt-0.5 truncate font-mono text-[13px] text-text-1" title={val}>
              {val}
            </div>
          </div>
        ))}
      </div>
      <StepTracker job={job} phases={phases} />
    </div>
  );
}
