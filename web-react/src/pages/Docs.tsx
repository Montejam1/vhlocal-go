import { Card } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";

const STEPS = [
  {
    n: "1",
    name: "Recon",
    tag: "up to 90 turns",
    lead: "Map the complete attack surface — every input, sink, entry point and trust boundary — and carve the app into subgraph partitions before hunting any specific bug.",
    io: ["the target repo", "phase1_output.md"],
  },
  {
    n: "opt",
    name: "Threat model — PASTA",
    tag: "optional · post-recon",
    lead: "Understand what the application IS and threat-model its archetype so the hunt targets the surfaces that matter — not just web/RPC entry points. Builds the SBOM + a data-flow diagram, and adds hunt partitions for surfaces recon missed.",
    io: ["phase1_output.md + repo", "threat_model.md + sbom.cdx.json"],
  },
  {
    n: "2",
    name: "Hunt",
    tag: "fan-out · up to 80 turns each",
    lead: "Trace every inventoried input forward to a disposition, evaluating it against dangerous sinks by vulnerability class (injection · access-control · logic/crypto). The only phase that fans out into many parallel agents.",
    io: ["phase1_output.md", "results/ (one file per agent)"],
  },
  {
    n: "3",
    name: "Verify",
    tag: "up to 70 turns",
    lead: "Try to DISPROVE every hunt candidate with full-codebase visibility. Roughly half of raw candidates are false positives; this is where they're cut. A finding is a false positive only with evidence — a specific defense at a file:line. Authentication is a precondition, never that evidence.",
    io: ["results/", "phase2b_output.md + handoff"],
  },
  {
    n: "4",
    name: "Reproduce",
    tag: "up to 80 turns",
    lead: "Prove each confirmed finding end-to-end with a PoC and an exploit test (static data-flow trace when no shell), then document a fix. Anything that can't be proven is downgraded.",
    io: ["phase2b_handoff.md", "phase3_output.md + poc/"],
  },
  {
    n: "5",
    name: "Sweep",
    tag: "deterministic · no model",
    lead: "For each confirmed finding, grep the entire codebase — ignoring partition boundaries — for every other instance of its root cause, so a pattern found once isn't missed elsewhere. Fixed CWE→pattern table + ripgrep: same input, same output.",
    io: ["phase3_output.md", "phase3d_output.md"],
  },
  {
    n: "6",
    name: "Report",
    tag: "up to 50 turns",
    lead: "Compile every confirmed finding, code smell, resolved input and the sweep table into the final human-readable report — one row per exploit-test pass, each with its own data flow, PoC and exploit test.",
    io: ["phase1 + 2b + 3 + 3d", "README.md"],
  },
];

const BEYOND = [
  ["Per-step models", "Recon, Hunt, Verify, Reproduce/Report can each run on a different model — a cheap local model for recon/report, a stronger one for the hunt."],
  ["Application Intelligence", "When the Threat-model step runs, its SBOM, threat model and data-flow diagram are collected per application in the Apps tab."],
  ["Vulnerability Ledger", "A run can merge its confirmed findings into a per-application ledger that tracks findings across runs (open / fixed / regressed) and scores recall."],
  ["Honest coverage", "Every report carries a coverage status. A shallow run — no entry points mapped, or a large codebase hunted in a single partition — is marked degraded, never silently 'complete'."],
];

export function Docs() {
  return (
    <div>
      <h1 className="text-xl font-semibold text-text-1">How VulnHunter works</h1>
      <p className="mt-2 max-w-3xl text-[13px] leading-relaxed text-text-2">
        VulnHunter audits a codebase as a sequence of steps. Each runs in its own LLM agent
        context, reads the previous steps' outputs, and writes exactly one output of its own.
        The agent is <b className="text-text-1">static-only</b> — it reads, greps and globs the
        source and writes findings; it never executes the target's code and never reaches the
        network except to talk to the model server. Six steps always run; the{" "}
        <b className="text-text-1">Threat model</b> step is optional.
      </p>
      <div className="mt-3 flex flex-wrap gap-2 text-[11px]">
        <Badge>Static analysis</Badge>
        <Badge>LLM-driven</Badge>
        <Badge variant="accent">Recon → Hunt → Verify → Reproduce → Sweep → Report</Badge>
        <Badge>Per-step model routing</Badge>
      </div>

      <div className="mt-6 flex flex-col gap-3">
        {STEPS.map((s) => (
          <Card key={s.name} className="flex flex-col gap-2">
            <div className="flex items-center gap-3">
              <span
                className={
                  "grid h-8 w-8 shrink-0 place-items-center rounded-full text-[13px] font-bold " +
                  (s.n === "opt" ? "bg-ok-weak text-ok" : "bg-accent-weak text-accent")
                }
              >
                {s.n === "opt" ? "＋" : s.n}
              </span>
              <h3 className="text-[15px] font-semibold text-text-1">{s.name}</h3>
              <Badge variant={s.n === "opt" ? "ok" : "default"}>{s.tag}</Badge>
            </div>
            <p className="text-[13px] leading-relaxed text-text-2">{s.lead}</p>
            <div className="flex flex-wrap gap-4 text-[11px] text-text-3">
              <span>
                <b className="text-text-2">reads</b> <span className="font-mono">{s.io[0]}</span>
              </span>
              <span>
                <b className="text-text-2">writes</b> <span className="font-mono">{s.io[1]}</span>
              </span>
            </div>
          </Card>
        ))}
      </div>

      <h2 className="mt-8 mb-3 text-lg font-semibold text-text-1">Beyond the steps</h2>
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
        {BEYOND.map(([title, body]) => (
          <Card key={title}>
            <h3 className="text-[13px] font-semibold text-text-1">{title}</h3>
            <p className="mt-1 text-[12.5px] leading-relaxed text-text-2">{body}</p>
          </Card>
        ))}
      </div>
    </div>
  );
}
