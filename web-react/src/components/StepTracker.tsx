import type { Job, PhaseDef } from "@/lib/types";
import { cn } from "@/lib/utils";

// Derive the ordered, human-named steps for a job — never the engine's internal
// keys (1t, 2b, 3d). The Threat-model step only appears when the scan runs it.
export function stepsFor(job: Job, allPhases: PhaseDef[]) {
  const short = (p: PhaseDef) => (p.title || p.key).split(" — ")[0].split(",")[0].trim();
  const raw = (job.spec?.phases || "all").trim();
  const keys = raw.split(",").map((s) => s.trim());
  let steps = allPhases.slice();
  if (raw && raw !== "all") {
    const sub = allPhases.filter((p) => keys.includes(p.key));
    if (sub.length) steps = sub;
  }
  const tmOn = !!job.spec?.threat_model || keys.includes("1t");
  if (!tmOn) steps = steps.filter((p) => p.key !== "1t");
  const curKey = job.phase ? job.phase.split(" — ")[0].trim() : null;
  const curIndex = curKey ? steps.findIndex((p) => p.key === curKey) : -1;
  const done = job.status === "done";
  const stopped = ["failed", "interrupted", "cancelled"].includes(job.status);
  return { steps: steps.map(short), curIndex, done, stopped, N: steps.length };
}

export function StepTracker({ job, phases }: { job: Job; phases: PhaseDef[] }) {
  const { steps, curIndex, done, stopped, N } = stepsFor(job, phases);
  const pct = job.agent_total ? Math.round((100 * job.agent_index) / job.agent_total) : 0;

  let caption: string;
  if (done) caption = `All ${N} steps complete`;
  else if (stopped)
    caption = curIndex >= 0 ? `Stopped at step ${curIndex + 1} — ${steps[curIndex]}` : "Stopped";
  else if (curIndex >= 0)
    caption =
      `Step ${curIndex + 1} of ${N} · ${steps[curIndex]}` +
      (job.agent_total ? ` · agent ${job.agent_index}/${job.agent_total}` : "");
  else caption = job.status === "queued" ? "Queued…" : "Starting…";

  return (
    <div className="rounded-[var(--radius,12px)] border border-line bg-surface-1 p-5">
      <div className="flex items-start overflow-x-auto pb-1">
        {steps.map((label, i) => {
          const state = done
            ? "done"
            : curIndex === -1
              ? job.status === "running" && i === 0
                ? "active"
                : "pending"
              : i < curIndex
                ? "done"
                : i === curIndex
                  ? stopped
                    ? "stopped"
                    : "active"
                  : "pending";
          return (
            <div key={i} className="relative flex min-w-[70px] flex-1 flex-col items-center text-center">
              {i > 0 && (
                <span
                  className={cn(
                    "absolute top-[15px] -left-1/2 h-0.5 w-full",
                    state === "done" || state === "active" ? "bg-accent" : "bg-line",
                  )}
                />
              )}
              <span
                className={cn(
                  "z-10 grid h-8 w-8 place-items-center rounded-full border-2 text-[13px] font-semibold",
                  state === "done" && "border-accent bg-accent text-white",
                  state === "active" && "border-accent bg-surface-1 text-accent animate-[nodepulse_1.5s_ease-out_infinite]",
                  state === "stopped" && "border-err bg-surface-1 text-err",
                  state === "pending" && "border-line bg-surface-1 text-text-3",
                )}
              >
                {state === "done" ? "✓" : state === "stopped" ? "!" : i + 1}
              </span>
              <span
                className={cn(
                  "mt-2 text-[11px] font-semibold",
                  state === "active" ? "text-accent" : state === "done" ? "text-text-2" : "text-text-3",
                )}
              >
                {label}
              </span>
            </div>
          );
        })}
      </div>
      <div className="mt-4 text-center text-xs font-medium text-text-2">{caption}</div>
      {!done && !stopped && job.agent_total > 0 && (
        <div className="mt-3 h-1 overflow-hidden rounded-full bg-surface-3">
          <div className="h-full rounded-full bg-accent transition-all" style={{ width: `${pct}%` }} />
        </div>
      )}
    </div>
  );
}
