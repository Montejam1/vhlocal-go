# vulnhunt-local

Runs VulnHunter's scanning methodology against a **local Ollama model** — no
Claude Code, no `claude` binary, no Anthropic API, no network egress.

Built for `gpt-oss:120b`. Works with any Ollama model that reports the `tools`
capability.

## Go port — command mapping

vhlocal is being ported to Go as a single self-contained binary (`vhlocal`) with
the bundled methodology and web UI embedded — no interpreter to install. The
interface is preserved; only the launch mechanism changes:

| Python (during migration) | Go binary |
|---|---|
| `python3 -m vhlocal.run …` | `vhlocal run …` |
| `python3 -m vhlocal.server …` | `vhlocal server …` |
| `python3 -m vhlocal.report …` | `vhlocal report …` |
| `python3 -m vhlocal.logs …` | `vhlocal logs …` |
| `python3 -m vhlocal.sbom …` | `vhlocal sbom …` |
| `python3 -m vhlocal.bench …` | `vhlocal bench …` |
| `python3 -m vhlocal.batch …` | `vhlocal batch …` |
| `python3 -m vhlocal.{authz,membank,policy_bench} …` | `vhlocal {authz,membank,policy-bench} …` |

The Go port preserves the main command and server interfaces, but complete
behavioral parity is still under assessment. Build with `make build` or
`make release`; run `make ui` first when changing the embedded UI. Test offline
with `go test ./...`. The examples below still use Python invocations during
migration; substitute `vhlocal <cmd>` for `python3 -m vhlocal.<cmd>`.

Scan completion now requires all planned hunt outputs, accepted per-candidate
verification decisions, and (when Phase 3 is selected) validated reproduction
dispositions. Each supported finding must have registered authored material under
`poc/` or `exploit_tests/`, or a specific deferral reason in
`artifact_manifest.json`. Authored material is **not executed** by the scanner.
`phase3_output.md` lists reproduction assignments; Phase 3d enumerates syntactic
leads deterministically, and Phase 4 renders the canonical report without a model.
Missing artifacts or incomplete verification prevent full completion and remain
visible when reports are regenerated.

Rebuilding does not replace an already-running server process. Restart the service
to load the rebuilt binary before evaluating a new scan. Offline regression and
independent Python-reference contract checks are documented in
[`tests/parity/README.md`](tests/parity/README.md). These checks do not establish
scanner-wide detection parity. Full migration detail: `specs/002-golang-port/` and
`CHANGELOG.md`.

## Why this exists

VulnHunter ships as Claude Code skills. The *methodology* — `SKILL.md` plus the
phase prompts, ~165KB of plain markdown — is model-agnostic. Only the *runtime*
(skill loading, subagent dispatch, the tool loop) was Anthropic-bound.

This package replaces the runtime and reuses the phase methodology, which is
**bundled in `skill/`** (Apache-2.0, from VulnHunter — see `NOTICE`). A fresh
clone runs with no external setup on any OS.

## Requirements

- An inference server: **Ollama** (`ollama serve`) with a `tools`-capable model,
  or any **OpenAI-compatible** server (mlx_lm / vLLM / LM Studio) via `--backend openai`
- **Python 3.9+ — stdlib only.** No pip install, no venv, no dependencies.
- `ripgrep` (optional; falls back to a pure-Python scanner)

Deploying to a Linux backend + a remote GPU box? See **[DEPLOY.md](DEPLOY.md)**.

## Quick start

```bash
# The vulnhunt skill is bundled, so nothing to install or point at.
python3 -m vhlocal.run --repo /path/to/target
```

Results land in **`~/vulnhunter-reports/<name>_VULNHUNT_RESULTS_gptoss120b_<timestamp>/`**,
keeping upstream's internal layout: `README.md`, `phase1_output.md`, `results/`,
`poc/`, `exploit_tests/`.

**Reports are deliberately kept out of the scanned repository.** Upstream writes
them into the target, which drops runnable exploit PoCs for that very service
into its working tree — one careless `git add` from being committed and pushed.
A central directory also means every scan you have ever run is browsable in one
place. Override with `--reports-dir`, or pin an exact path with `--out`.

### Common invocations

```bash
# Single phase (fast iteration while tuning)
python3 -m vhlocal.run --repo ~/code/app --phases 1

# Continue an interrupted run — completed phases are skipped
python3 -m vhlocal.run --repo ~/code/app --resume

# Different model / remote Ollama host
python3 -m vhlocal.run --repo ~/code/app \
    --model qwen3.5:122b-a10b --host http://192.168.1.50:11434

# Bound runtime on a large codebase
python3 -m vhlocal.run --repo ~/code/monorepo \
    --max-partitions 4
```

| Flag | Default | Purpose |
|---|---|---|
| `--repo` | *(required)* | Target repository (read-only) |
| `--out` | — | Exact results directory (overrides `--reports-dir`) |
| `--reports-dir` | `~/vulnhunter-reports` | Where reports are written |
| `--model` | `gpt-oss:120b` | Any Ollama model with `tools` |
| `--host` | `$VHLOCAL_OLLAMA_HOST` or localhost | Ollama endpoint |
| `--num-ctx` | `131072` | Context window — see warning below |
| `--phases` | `all` | Subset: `1,2,2b,3,3d,4` |
| `--max-partitions` | `8` | Caps Phase 2 fan-out |
| `--verify-model` | same as `--model` | Stronger model for Phase 2b only — see "Precision" |
| `--verify-host` | same as `--host` | Endpoint for `--verify-model` |
| `--resume` | off | Skip phases that produced a deliverable |
| `-v` / `-vv` | — | Verbosity |

### Precision: the `--verify-model` seam

Phase 2 hunt agents over-produce by design — the methodology expects Phase 2b
to falsify weak candidates. A local model over-produces *more*: during
validation, the two agents assigned to a partition with no bug in their class
both invented findings, including a "High severity" resource-exhaustion claim
for a missing `LIMIT` clause.

Phase 2b is therefore where precision is won or lost. It is also cheap: it reads
the accumulated candidate files, not the codebase, while Phase 2 reads the
codebase three times per partition. Pointing only that phase at a stronger model
buys back most of the precision for a small share of total tokens.

```bash
# Everything local, falsification on the larger-context model
python3 -m vhlocal.run --repo ~/code/app \
    --model gpt-oss:120b --verify-model qwen3.5:122b-a10b

# Or point Phase 2b at a remote endpoint entirely
python3 -m vhlocal.run --repo ~/code/app \
    --verify-model <model> --verify-host http://<host>:11434
```

## Consolidated report

Every scan ends by writing two extra artifacts, generated deterministically in
Python — **no model involved**:

| File | Contents |
|---|---|
| **`SCAN_REPORT.html`** | **Start here.** Designed, self-contained report — hero count, KPI tiles, severity meter, filterable findings, expandable detail, light/dark |
| `SCAN_REPORT.md` | Same content as markdown, for diffing and terminals |
| `findings.json` | Findings machine-readable, for triage tooling |
| `scan_meta.json` | Raw engine record both reports render from |

The HTML report is one file with no external requests — open it from disk, mail
it, or serve it. It prints cleanly (controls hide, sections expand).

The HTML report carries a **Save as PDF** button in the header. It drives the
browser's own print engine against a tuned print stylesheet — no PDF library is
bundled, because inlining one would add ~500KB to every report and break the
self-contained/offline guarantee. The printed output forces the light palette
(dark mode wastes ink and reads badly), keeps severity colours via
`print-color-adjust` (browsers drop backgrounds by default, and severity *is*
the encoding), expands every collapsed section, hides the interactive controls,
and avoids page breaks inside a finding. `<title>` carries the target and date,
so the browser's default filename is already meaningful.

If you export while a severity filter or search is active, the PDF prints what
you see and adds a **"Filtered view — showing N of M findings"** banner. A
filtered security report that looks complete would understate the findings.

Sections: **scan summary** (target, start/finish, duration, models, host),
**checks enabled** (phases with per-phase status and duration, vulnerability
classes with agent counts, context window, tool envelope, token usage),
**findings by severity** with distribution bars, **findings ranked by priority**,
**per-finding detail**, **probable duplicates**, and **scope and limitations**.

Regenerate at any time — useful after editing the renderer, or for runs made
before this existed:

```bash
python3 -m vhlocal.report <results-dir>
python3 -m vhlocal.report --all          # every report in ~/vulnhunter-reports
```

### Why it doesn't ask the model

Run metadata is engine-observed fact. The one time this project trusted the
model's prose about its own run, the report header claimed
`**Model**: claude-opus-4-8` for a scan executed entirely on `gpt-oss:120b` —
copied from the phase-4 template example. Timings, phase status, agent counts,
and token usage all come from `scan_meta.json`, which the engine writes.

The report is also honest about what *didn't* happen. It states that code was
never executed, refuses to claim vulnerability-class coverage when Phase 2 did
not run, flags agents that stopped on `max_turns`, warns when the final report
is missing, and — when `--verify-model` was not used — notes that falsification
ran on the same model that produced the candidates.

### Report design notes

Severity is a **status** encoding, so it uses the reserved status palette rather
than series hues. That palette measures **ΔE 13.6 between Medium (`#fab219`) and
High (`#ec835a`)** — below the 15 floor, meaning those two are hard to separate
*even with full colour vision*. Colour therefore cannot be the only channel:
every badge ships a **glyph + the severity word**, and colour reinforces rather
than carries.

Low and Informational get no status colour at all — green would read as "good",
which a finding never is. They wear muted ink, which also signals lower priority
correctly.

Counts are a KPI row of stat tiles rather than a bar chart (a handful of headline
numbers is a tile job). The severity mix is one stacked meter with 2px surface
gaps and 4px rounded data-ends. Dark mode is *selected* — the OS media query and
an explicit toggle, with the toggle winning both ways — not an automatic flip.

### Duplicates are flagged, not merged

A finding is marked a duplicate only when CWE, sink location **and** data-flow
signature all match. Sink alone is not enough: the `q` and `status` parameters
of one search endpoint both reach the same `execute()` and are two separate
vulnerabilities needing two separate fixes — collapsing them is precisely the
"collapsing findings" failure the methodology warns against. Real duplicates are
listed rather than silently merged, because duplicate reporting is itself a
signal about scan quality.

## Running inference on another machine

vhlocal does not have to run where the GPU is. Point it at a remote Ollama and
the harness, reports, and UI stay local while inference happens elsewhere.

Set it once and every entry point — CLI, engine, and web UI — picks it up:

```bash
export VHLOCAL_OLLAMA_HOST=http://192.168.2.50:11434
```

Or per invocation / per scan:

```bash
python3 -m vhlocal.run --repo ~/code/app \
    --host http://192.168.2.50:11434

python3 -m vhlocal.server \
    --ollama-host http://192.168.2.50:11434
```

In the web UI it lives in **Settings**, pinned to the bottom of the left rail —
it is engine configuration, not a per-scan parameter, so it doesn't scroll away
with the job list. The panel holds the Ollama host with a **Check** button that
re-queries that host's model list, a **Reset to engine default**, and read-only
engine facts (skill dir, reports dir, scan roots, default model, context size).
A dot on the Settings header shows connection state at a glance.

A host set here is saved in the browser (`localStorage`) and **overrides the
engine default**, so one engine can be pointed at different inference boxes
without restarting it; Reset clears the override. An unreachable host fails fast
with a clear message and auto-opens Settings rather than hanging.

`--verify-host` still works independently, so the falsification pass can run on
a different machine from the hunt phase.

> **Two things to get right on the remote box.** Ollama binds `127.0.0.1` by
> default, so it needs `OLLAMA_HOST` set to an interface the client can reach —
> but that endpoint has **no authentication**, so bind it to a private/host-only
> interface or firewall the port to the client's address rather than exposing
> `0.0.0.0` to a whole LAN. Second, the model must be pulled **on the machine
> running Ollama**, not the client.

## Engine mode (web UI)

Run vhlocal as a long-lived service with a browser front end instead of a
one-shot script:

```bash
cd vulnhunt-local
python3 -m vhlocal.server
# → http://127.0.0.1:8420
```

The UI lets you start scans, watch the tool-by-tool feed live, cancel a running
scan, and browse the report and artifacts — all served from the same process.
Still stdlib-only; still no network egress beyond Ollama.

| Flag | Default | Purpose |
|---|---|---|
| `--skill-dir` | bundled `skill/` | Phase prompts (bundled — override only if you keep your own) |
| `--port` | `8420` | Listen port |
| `--host` | `127.0.0.1` | Bind address |
| `--reports-dir` | `~/vulnhunter-reports` | Where reports are written and indexed |
| `--ollama-host` | `$VHLOCAL_OLLAMA_HOST` or localhost | Default inference endpoint (overridable per scan in the UI) |
| `--allow-root` | `$HOME` | Directory scans may target (repeatable) |
| `--state` | `~/.vhlocal/jobs.json` | Where the job queue persists |
| `--unsafe-bind` | off | Required to bind a non-loopback address |

### Security posture

This server executes scans against paths the caller names and serves files
back, and it has **no authentication**. Three controls follow from that:

* **Loopback by default.** Binding anything else requires `--unsafe-bind`.
  Don't expose it to a network.
* **Scan roots are allow-listed.** A request cannot point the engine at `/`.
  Both `repo` and `out` are checked.
* **Artifact reads are confined to a job's own results directory**, resolved
  before the prefix comparison so `../` cannot escape. Report ids from the
  browser are matched against the enumerated set rather than joined to a path,
  so traversal is structurally impossible rather than filtered.

### Scans are serialized

One 64GB model occupies the GPU. Two concurrent scans don't run twice as fast,
they thrash — so a single worker drains a FIFO queue. Queue as many as you
like; they run one after another. `busy` in the UI header reflects this.

### API

The UI is a thin client over a plain JSON API, so the engine is scriptable:

| Method | Route | Purpose |
|---|---|---|
| `GET` | `/api/config` | Skill dir, allowed roots, phase list |
| `GET` | `/api/models` | Models available from Ollama |
| `POST` | `/api/scans` | Submit a scan (JSON body mirrors the CLI flags) |
| `GET` | `/api/scans` | List jobs + busy state |
| `GET` | `/api/scans/{id}` | Job detail and live progress |
| `GET` | `/api/scans/{id}/events` | **SSE** event stream (replays backlog, then live) |
| `POST` | `/api/scans/{id}/cancel` | Cancel — stops within one model turn |
| `GET` | `/api/scans/{id}/artifacts` | List result files |
| `GET` | `/api/scans/{id}/file?path=` | Read one result file |
| `GET` | `/api/reports` | Index every report on disk (incl. CLI-run scans) |
| `GET` | `/api/reports/{id}/files` | List a report's files |
| `GET` | `/api/reports/{id}/file?path=` | Read one file from a report (incl. `SCAN_REPORT.md`, `findings.json`) |

```bash
curl -X POST http://127.0.0.1:8420/api/scans \
  -H 'Content-Type: application/json' \
  -d '{"repo":"/path/to/repo","model":"gpt-oss:120b","verify_model":"qwen3.5:122b-a10b"}'
```

### Reports tab

The **Reports** tab indexes `--reports-dir` directly, so it lists every scan on
disk — including ones started from the CLI, by an earlier server process, or by
a job whose record was pruned. Each card shows findings count, model, phases
completed, and whether the run finished; clicking one opens `SCAN_REPORT.md`
first, with the raw artifacts listed beneath.

Two parsing notes, both learned from real output:

* The **model** shown comes from the directory name (engine-generated), not the
  report header. `gpt-oss:120b` was observed writing `**Model**: claude-opus-4-8`
  into its own report, copied verbatim from the phase-4 template example. The
  claimed value is kept as `model_reported` for comparison.
* Header parsing runs through `normalize_text()` for the same U+2011 reason as
  partition parsing, and every field degrades to a fallback rather than dropping
  the report from the list.

### Restart behaviour

The job queue persists to JSON. Jobs that were mid-flight when the process died
are marked `interrupted` on reload — **never silently re-run**, because a scan
is expensive and writes to disk. The in-memory event ring does not survive a
restart, so the durable record of *how* a scan ran is the **central log**
(`~/.vhlocal/vhlocal.log` by default) — every line is tagged with the scan/job
id, so one scan's slice is recoverable with `python3 -m vhlocal.logs <tag>` or
the **Log** tab even after the process is gone. There is no longer a per-scan
log file in the results directory.

## Architecture

```
server.py   HTTP engine: REST + SSE + static UI      (stdlib http.server)
jobs.py     FIFO queue, job store, persistence, cancellation
engine.py   execute_scan() — the phase pipeline as a library call
run.py      Thin CLI over engine.py
phases.py   Phase specs, SKILL.md preamble extraction, partition parsing
agent.py    The tool loop — one isolated agent run, with context pruning
tools.py    Read / Grep / Glob / Write, sandboxed
client.py   Ollama /api/chat client
inventory.py Deterministic entry-point enumerator: partition fallback + coverage ledger
logsetup.py Central logging: one shared config + per-scan line tagging
logs.py     CLI to read the central log / slice it to one scan
web/        Self-contained UI (no CDN, works offline)
```

The CLI and the web UI call the *same* `execute_scan()`. There is one
implementation of the pipeline, so behaviour cannot drift between them.

**Phase 2 runs sequentially, not in parallel.** Upstream dispatches
`(3 x partitions) + 1` concurrent subagents. On a single local GPU that
concurrency is unavailable anyway — they would serialize on the same weights.
Each unit still gets its own fresh context, so the isolation that mattered is
preserved; only wall-clock is lost.

## Three things that will bite you

**1. `num_ctx` is not optional.** Ollama's default context is far smaller than
gpt-oss's 131072, and an over-long prompt is *silently truncated*, not rejected.
A truncated phase prompt yields confident nonsense. `client.py` always sets it
explicitly. Don't lower it below ~32k.

**2. Typographic punctuation breaks parsers.** gpt-oss writes `SG‑1` with
U+2011 NON-BREAKING HYPHEN, not ASCII `-`. This was caught during validation:
the partition parser silently matched nothing and fell back to a single
whole-repo partition, cutting Phase 2 from 16 agents to 3 with no error. Any
regex you add over model output must go through `phases.normalize_text()`.

**3. Tool names drift.** The model calls `glob` for `Glob` and `read_file` for
`Read`. `tools.py` accepts case-insensitive names and common aliases rather
than burning a turn on a rejection.

## Sandboxing

- **Reads** are confined to the target repo, the skill directory, and the
  results directory. Paths are `resolve()`d before a prefix check, so `../`
  traversal is caught rather than normalized away.
- **Writes** are confined to the results directory only.
- **No shell execution.** There is no Bash tool. Unlike upstream's
  bash-enabled mode, this harness never runs the target's install hooks or its
  exploit tests — the scan cannot execute the code it is scanning.

That last point is a safety gain and a fidelity loss: exploit tests are written
but never run, so a finding is confirmed by reasoning, not execution. See
"Known gaps".

## Known gaps

| Gap | Impact |
|---|---|
| No Bash tool | Exploit tests are written, never executed. No dependency install. |
| No `/vulnhunter-fix` | Remediation still needs the Claude Code skill (`gh`, worktrees, PRs). |
| No `/vulnhunt-fix-verify` | Independent fix verification not ported. |
| Sequential Phase 2 | Slower wall-clock; no quality impact on one GPU. |
| Markdown parsing is tolerant, not strict | Phase 1 output shape varies run to run; partition parsing degrades rather than fails. |

## Calibration

`gpt-oss:120b` is markedly weaker than Opus at long multi-hop tracing, which is
what VulnHunter's differentiated value rests on. Expect good recall on shallow
bugs, weaker recall on deep ones, and looser precision because the Phase 2b
falsification pass degrades too.

Two mitigations worth considering:

- **`qwen3.5:122b-a10b`** is also pulled on this machine: 256k context (2x) and
  MoE with ~10B active params, so likely faster. Worth benchmarking head to head
  via `--model`.
- **Hybrid.** Phase 2b reads only the accumulated candidate files, not the
  codebase, so it is a small fraction of total tokens but carries the entire
  precision load. Running it against a frontier model while everything else
  stays local preserves the falsification discipline cheaply.

Before trusting output, establish a baseline with
`harness/local_harness/benchmark/` against a known-vulnerable corpus. A scanner
that reports fluent, wrong findings is worse than no scanner.

## Resilience: repair and handoff

Local models degrade deep into a long agentic session — they keep reasoning
coherently but stop emitting valid tool-call JSON, which Ollama rejects with
HTTP 500. Two mechanisms keep that from wrecking a run:

**Fresh-context tool-call repair.** When a tool call fails to parse, the client
does *not* re-send the large context that produced the garbage — replaying it
reproduces it. Instead it repairs in a minimal fresh context containing only the
schema, the parser's error, and the model's intended action (its own malformed
output, which carries the file path and content it meant to write). A grounding
hint supplies the writable root so a truncated path can be reconstructed. Two
attempts; if both fail, the agent ends gracefully (it does not crash the scan).

**Compact Phase 2b → Phase 3 handoff.** Phase 3 was where the degradation
surfaced, because it inherited Phase 2b's full falsification transcript. Now,
after 2b, the engine distils its verdict table into `phase2b_handoff.md` — one
row per confirmed, non-duplicate finding (VULN-NNN, severity, CWE, entry point,
and a pointer to the per-class source file with the detail). Phase 3 reads that
(~1-2KB, ~13% of the transcript) and pulls only the specific source files it
needs, so it starts from a small context instead of a bloated one. If the
handoff can't be built, Phase 3 falls back to the raw 2b output.

## Validating a change

A self-contained fixture ships in `testdata/` — a small Flask app with five
planted vulnerabilities across three files (two SQLi sharing a sink, path
traversal, command injection, broken object-level authorization) plus one
**negative control**: a correctly parameterized query that must not be reported.

Entry-to-sink distances are 2–3 hops deliberately, because multi-hop tracing is
what degrades first on a local model.

```bash
python3 -m unittest discover -s tests            # 29 tests, ~0.01s

python3 -m vhlocal.run --repo testdata/vulnapp
python3 testdata/score.py <results-dir>          # recall + decoy check
```

`testdata/ground_truth/vulnapp.json` describes each planted bug in the same
schema `harness/local_harness/benchmark/ground_truth/` uses, so the fixture can
be folded into the benchmark harness alongside real corpora.
