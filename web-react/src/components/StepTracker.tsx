import type { Job, PhaseDef, PhaseOutcome } from "@/lib/types";
import { cn } from "@/lib/utils";

type Step = { key: string; label: string };

// Derive the ordered, human-named steps for a job — never the engine's internal
// keys (1t, 2b, 3d). The Threat-model step only appears when the scan runs it.
export function stepsFor(job: Job, allPhases: PhaseDef[]): {
  steps: Step[];
  curIndex: number;
  done: boolean;
  stopped: boolean;
  N: number;
} {
  const short = (p: PhaseDef) => (p.title || p.key).split(" — ")[0].split(",")[0].trim();
  const raw = (job.spec?.phases || "all").trim();
  const keys = raw.split(",").map((s) => s.trim());
  let phases = allPhases.slice();
  if (raw && raw !== "all") {
    const sub = allPhases.filter((p) => keys.includes(p.key));
    if (sub.length) phases = sub;
  }
  const tmOn = !!job.spec?.threat_model || keys.includes("1t");
  if (!tmOn) phases = phases.filter((p) => p.key !== "1t");
  const steps: Step[] = phases.map((p) => ({ key: p.key, label: short(p) }));
  const curKey = job.phase ? job.phase.split(" — ")[0].trim() : null;
  const curIndex = curKey ? steps.findIndex((p) => p.key === curKey) : -1;
  const done = job.status === "done";
  const stopped = ["failed", "interrupted", "cancelled"].includes(job.status);
  return { steps, curIndex, done, stopped, N: steps.length };
}

export function StepTracker({ job, phases }: { job: Job; phases: PhaseDef[] }) {
  const { steps, curIndex, stopped, N } = stepsFor(job, phases);
  const pct = job.agent_total ? Math.round((100 * job.agent_index) / job.agent_total) : 0;

  // Prefer validated engine phase outcomes (feature 007, US3): a step is "done"
  // only when the engine actually completed it — a terminated queue status is NOT
  // treated as all-complete. Fall back to live progress when outcomes aren't
  // available yet (mid-run, before findings.json exists).
  const outcomes: Record<string, PhaseOutcome> = {};
  for (const o of job.phase_outcomes || []) outcomes[o.phase] = o;
  const haveOutcomes = (job.phase_outcomes?.length || 0) > 0;

  const stateFor = (i: number): "done" | "active" | "incomplete" | "stopped" | "pending" => {
    if (haveOutcomes) {
      const o = outcomes[steps[i].key];
      if (o?.completed) return "done";
      // requested-but-not-completed → incomplete (a truthful "not done"), unless the
      // whole run stopped, in which case the current phase reads as stopped.
      if (stopped && i === curIndex) return "stopped";
      return "incomplete";
    }
    if (curIndex === -1) return job.status === "running" && i === 0 ? "active" : "pending";
    if (i < curIndex) return "done";
    if (i === curIndex) return stopped ? "stopped" : "active";
    return "pending";
  };

  const doneCount = haveOutcomes ? steps.filter((_, i) => stateFor(i) === "done").length : 0;
  const incompleteLabels = haveOutcomes
    ? steps.filter((_, i) => stateFor(i) !== "done").map((s) => s.label)
    : [];

  let caption: string;
  if (haveOutcomes) {
    caption =
      doneCount === N
        ? `All ${N} steps complete`
        : `${doneCount} of ${N} phases complete — ${incompleteLabels.join(", ")} incomplete`;
  } else if (curIndex >= 0) {
    caption =
      `Step ${curIndex + 1} of ${N} · ${steps[curIndex].label}` +
      (job.agent_total ? ` · agent ${job.agent_index}/${job.agent_total}` : "");
  } else {
    caption = job.status === "queued" ? "Queued…" : "Starting…";
  }

  const running = !haveOutcomes && !stopped && job.status !== "done" && job.agent_total > 0;

  return (
    <div className="rounded-[var(--radius,12px)] border border-line bg-surface-1 p-5">
      <div className="flex items-start overflow-x-auto pb-1">
        {steps.map((step, i) => {
          const state = stateFor(i);
          return (
            <div key={step.key} className="relative flex min-w-[70px] flex-1 flex-col items-center text-center">
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
                  state === "incomplete" && "border-warn bg-surface-1 text-warn",
                  state === "pending" && "border-line bg-surface-1 text-text-3",
                )}
                title={outcomes[step.key]?.reason || ""}
              >
                {state === "done" ? "✓" : state === "stopped" ? "!" : state === "incomplete" ? "–" : i + 1}
              </span>
              <span
                className={cn(
                  "mt-2 text-[11px] font-semibold",
                  state === "active" ? "text-accent" : state === "done" ? "text-text-2" : "text-text-3",
                )}
              >
                {step.label}
              </span>
            </div>
          );
        })}
      </div>
      <div className="mt-4 text-center text-xs font-medium text-text-2">{caption}</div>
      {running && (
        <div className="mt-3 h-1 overflow-hidden rounded-full bg-surface-3">
          <div className="h-full rounded-full bg-accent transition-all" style={{ width: `${pct}%` }} />
        </div>
      )}
    </div>
  );
}
