# Runbook — running VulnHunter locally on gpt-oss:120b

Copy-pasteable. Assumes Ollama is running with `gpt-oss:120b` pulled and Python 3.9+.
Runs the same on Linux and macOS; for a remote-GPU deploy see [DEPLOY.md](DEPLOY.md).

There is **nothing to install.** No `install.sh`, no Python 3.11, no `gh`, no
Claude Code, no pip packages. Stock system Python plus a running Ollama is the
entire dependency list.

---

## 0. Before you start

Only one scan can use the model at a time. If another scan is running, Ollama
will queue your requests behind it and everything will crawl. Check first:

```bash
pgrep -fl vhlocal.run          # should print nothing
ollama ps                      # shows what's loaded
```

If a scan is running and you want the GPU back:

```bash
pkill -f vhlocal.run
```

---

## 1. Verify the environment (10 seconds)

```bash
cd /path/to/vhlocal        # your clone

curl -s http://localhost:11434/api/tags >/dev/null && echo "ollama: up" || echo "ollama: DOWN — run 'ollama serve'"
ollama show gpt-oss:120b | grep -E 'context length|tools'
python3 -m unittest discover -s tests 2>&1 | tail -3
```

Expect: `ollama: up`, `context length 131072`, `tools`, and `OK` (74 tests).

---

## 1b. Web UI (engine mode)

Prefer a browser to a terminal? Same scans, same outputs:

```bash
cd /path/to/vhlocal        # your clone
python3 -m vhlocal.server
```

Open **http://127.0.0.1:8420**. Paste a repo path, pick a model, hit Start, and
watch the live feed. Cancel works mid-scan.

Two views, top right:
* **Scans** — start scans, watch progress, browse the current run's artifacts.
* **Reports** — every scan ever run, newest first, with findings count and
  completion state. Reads the reports directory directly, so CLI-run scans
  show up here too. **Open full report ↗** launches the styled HTML report;
  markdown artifacts render properly rather than as raw text. The **🗑** on a
  report card deletes it (with confirmation) — a scan still running can't be
  deleted. From the CLI: `python3 -m vhlocal.report --delete <results-dir>`
  (add `--yes` to skip the prompt). Both refuse to delete anything outside the
  reports directory.

By default only paths under `$HOME` may be scanned. To scan elsewhere:

```bash
python3 -m vhlocal.server --allow-root /path/to/code
```

The server binds loopback only and has no authentication — keep it that way
unless you know what you're doing (`--unsafe-bind` is required to override).

Leave it running; it queues scans and runs them one at a time.

---

## 2. The demo — scan the bundled vulnerable app

A small Flask app with **five planted bugs and one decoy** ships in
`testdata/vulnapp`.

```bash
cd /path/to/vhlocal        # your clone

python3 -m vhlocal.run --repo testdata/vulnapp --out /tmp/vh-demo
```

The vulnhunt skill is **bundled** (`skill/`), so no `--skill-dir` and no
install step is needed. Progress streams to your terminal and to the
central log (`~/.vhlocal/vhlocal.log` by default; override with `--log-file` or
`$VHLOCAL_LOG_FILE`). To read just this scan's lines:
`python3 -m vhlocal.logs <scan-tag>` (the tag is the trailing timestamp of the
results dir, e.g. `2026-08-17-115632`).

**Runtime: roughly 30–40 minutes.** Phase 1 takes ~1.5 min, then Phase 2 runs
16 agents at ~2 min each, then four more phases. It is not hung — watch the
`[n/15]` counter.

### Want a 2-minute taste instead?

```bash
python3 -m vhlocal.run --repo testdata/vulnapp \
    --out /tmp/vh-quick --phases 1
cat /tmp/vh-quick/phase1_output.md
```

Phase 1 alone produces the full attack-surface map: input inventory, threat
model, trust boundaries, and the partition table. It's the fastest way to see
whether the model is behaving.

---

## 3. Score it against ground truth

```bash
python3 testdata/score.py /tmp/vh-demo
```

Prints per-bug recall and whether the decoy (a correctly parameterized query at
`/api/users`) was wrongly reported.

The planted bugs, for reference:

| ID | Type | Path | Hops |
|---|---|---|---|
| VULN-A | SQL injection | `/api/search?q=` → `find_orders` → `build_search_query` → `execute` | 3 |
| VULN-B | SQL injection | `/api/search?status=` — same sink, second injection point | 3 |
| VULN-C | Path traversal | `/api/invoice?name=` → `fetch_invoice` → `_invoice_path` → `open` | 3 |
| VULN-D | Command injection | `/api/invoice/render?src=` → `render_invoice` → `os.system` | 2 |
| VULN-E | Broken authorization | `/api/orders/<id>` — session check but no ownership check | 1 |
| DECOY | **Not a bug** | `/api/users?email=` — parameterized query. Reporting it is a false positive. | — |

---

## 4. Read the output

```bash
ls /tmp/vh-demo
open /tmp/vh-demo/SCAN_REPORT.html  # designed report — start here
# (SCAN_REPORT.md has the same content as markdown)
```

Regenerate it any time (e.g. for older runs):

```bash
python3 -m vhlocal.report /tmp/vh-demo
python3 -m vhlocal.report --all
```

Without `--out`, reports go to `~/vulnhunter-reports/` and are browsable in the
web UI's **Reports** tab.

| File | What it is |
|---|---|
| `SCAN_REPORT.html` | **Start here.** Designed report — open in a browser; filter by severity, expand findings, **Save as PDF** button in the header |
| `SCAN_REPORT.md` | Same content as markdown; **Save as Markdown** / **Save as PDF** buttons |
| `findings.json` | Machine-readable findings + `run_status`, `attribution`, per-finding validation state, `root_cause_key`, and per-CWE `description` / `exploitability` / `reference` / `cve` (always N/A — first-party findings have no product CVE; see below) |
| `coverage_ledger.json` | Harness-enumerated entry points and their disposition (reviewed / finding / **not reviewed**) — the coverage denominator |
| `scan_meta.json` | Engine record: timings, phases, agents, token usage, partition source/fallback |
| `README.md` | Scanner's own report: summary table, per-finding detail, resolved input inventory |
| `phase1_output.md` | Attack surface: inputs, threat model, partitions |
| `results/*.md` | Raw per-agent hunt output — **pre-falsification, expect false positives here** |
| `phase2b_output.md` | Post-falsification survivors — the findings to actually trust |
| `phase3_output.md` | PoCs and fix strategies |
| `phase3d_output.md` | Deterministic root-cause instance sweep — every location matching each confirmed finding's sink pattern, NEW instances flagged |

Run logs no longer live in the results directory. Every entry point (CLI,
server, worker) writes to one **central log** — `~/.vhlocal/vhlocal.log` by
default — with each line tagged by scan id. Pull one scan's slice with
`python3 -m vhlocal.logs <scan-tag>` (or the **Log** tab in the web UI).
`scan_meta.json` records the tag as `scan_tag`.

The important distinction: `results/` is where agents **over-produce on purpose**.
`phase2b_output.md` is the filtered set. Judge quality on 2b, not on `results/`.

---

## 4b. Using a remote GPU box

Inference does not have to be local. Export the endpoint once:

```bash
export VHLOCAL_OLLAMA_HOST=http://<gpu-box>:11434
```

Everything — `vhlocal.run`, `vhlocal.server`, and the web UI — defaults to it.
Override per invocation with `--host`, or in the UI under **Settings** (pinned
to the bottom of the left rail): set the host, hit **Check** to re-list that
host's models. That choice is saved in the browser and beats the engine default;
**Reset to engine default** clears it.

On the GPU box: `OLLAMA_HOST` must point at an interface the client can reach,
and the model must be pulled there. That endpoint is unauthenticated — bind it
to a private interface or firewall the port to the client, never `0.0.0.0` on an
untrusted network.

## 4c. Alternate inference backend (MLX / vLLM / LM Studio)

vhlocal speaks two backends. Default is **Ollama** (native `/api/chat`). The
other is any **OpenAI-compatible** server — `mlx_lm.server` on Apple Silicon
(often faster prefill on M-series), vLLM on the RTX 6000, or LM Studio:

```bash
# Serve gpt-oss via MLX on Apple Silicon (separate terminal)
mlx_lm.server --model mlx-community/gpt-oss-120b-... --port 8080

# Point vhlocal at it
python3 -m vhlocal.run --repo <target> --backend openai --host http://localhost:8080
```

The backend is a config, not a fork — the agent loop is identical; only the
transport/format differs. In the web UI it's the **Inference backend** dropdown.

**Before trusting MLX, measure it** — it may be faster, but tool-calling
reliability (the linchpin of the agentic loop) is engine-specific:

```bash
# Head-to-head throughput, same M5 (run against an idle server)
python3 -m vhlocal.bench                                   # Ollama
python3 -m vhlocal.bench --backend openai --host http://localhost:8080  # MLX
```

Then do a small scan on both and diff the findings — a faster engine that drops
more tool calls is a net loss for accuracy.

---

## 5. Scan your own code

```bash
python3 -m vhlocal.run --repo ~/path/to/your/repo
```

Results land in **`~/vulnhunter-reports/`**, never inside the repo — so your
working tree stays clean and there is no risk of committing exploit PoCs for
your own service. Change the location with `--reports-dir`.

Useful flags:

```bash
# Bound runtime on a big codebase (Phase 2 = (3 x partitions) + 1 agents)
--max-partitions 4

# Resume after Ctrl-C — completed phases are skipped
--resume

# Try the other 120B you have pulled: 256k context, MoE, likely faster
--model qwen3.5:122b-a10b

# Run falsification on a different/stronger model (biggest precision lever)
--verify-model qwen3.5:122b-a10b

# Re-run a single phase while tuning prompts
--phases 2b
```

### Runtime & efficiency

Phase 2 (the hunt fan-out) is ~80% of wall-clock, because vhlocal runs agents
**sequentially** (one local GPU) where upstream VulnHunter parallelizes them. So
runtime ≈ agent count, and agent count = `(classes x partitions) + 1`. Levers,
in order of impact:

**Quality-neutral levers** (same findings, just faster):

```bash
# Overlap Phase-2 agents. Needs OLLAMA_NUM_PARALLEL>=N on the Ollama server, else
# requests just queue. Agents are independent — identical findings.
#   Linux (systemd):  sudo systemctl edit ollama  → add under [Service]:
#                     Environment="OLLAMA_NUM_PARALLEL=2"  then daemon-reload+restart
#   macOS (app):      launchctl setenv OLLAMA_NUM_PARALLEL 2, then restart Ollama
--concurrency 2

# Fewer partitions → fewer agents (coverage may report more 'not reviewed').
--max-partitions 4

# Phase 3d (root-cause sweep) is now DETERMINISTIC by default — the harness
# greps each confirmed sink pattern directly (~sub-second, complete) instead of
# the model grepping iteratively. Revert to the old model sweep with:
--sweep-mode model
```

**Quality-uncertain levers** (change what the model does — A/B before trusting):

```bash
# One agent per partition covering ALL classes instead of three separate
# INJ/NAV/LOG agents. ~3x fewer Phase-2 agents, but untested for depth.
--phase2-mode combined

# gpt-oss reasoning level. Lower = fewer reasoning tokens (faster generation)
# but weaker analysis. Unset (default) leaves the model unchanged.
--reasoning-effort medium

# Accept the model's own (fewer) partitions instead of enforced full coverage
--no-enforce-coverage
```

Before trusting a quality-uncertain lever, run it once and diff its findings
against a default run on the same commit (`python3 -m vhlocal.bench` also helps
you measure the speed side empirically).

Harness-enforced coverage (on by default) makes Phase 2 trace every enumerated
route, which raises breadth but adds agents. Coverage partitioning is
deterministic and non-overlapping — it will not re-scan a file already covered.

---

## 5b. Cross-run memory & standardized labels

**Standardized labels (always on).** Every finding now carries a deterministic
layer alongside the model's own labels:

- **Normalized CWE / family** — sibling CWEs roll up to one canonical CWE (e.g.
  CWE-639/862/863/285 → CWE-284 "Broken Access Control"). The model's reported
  CWE is preserved and shown; the normalized CWE is what cross-run matching uses.
- **Deterministic severity** — a fixed per-family baseline (e.g. deserialization
  = High+, SQLi = High, XSS = Medium), dropped exactly one tier when the finding
  requires a precondition such as authentication. This is what ranking, the
  severity meter, and the counts use, so the run-to-run "same bug ranked lower"
  swings are gone. The model's own tier is shown beside it when it differed
  ("scanner-assessed: …").

**Mode A — finding lifecycle (always on).** After each scan, the report is
reconciled against the most recent prior report of the *same repo*: every finding
is labelled **new / persisting / regressed**, and findings that were present
before and are gone now are listed as **fixed**. Matching is by a line-number-free
root-cause fingerprint (family-normalized), so a finding survives small line
drift and sibling-CWE relabels. Regression detection works from the second scan
onward (each report records the keys it saw fixed). The scanned git commit is
recorded in `scan_meta.json` for provenance. Reconciliation is deterministic and
post-hoc — it never calls the model, so **run independence is preserved** and
benchmark validity is untouched. See the "Change since previous scan" section in
the report and the `lifecycle` block in `findings.json`.

**Mode B — seed the hunt from a prior report (opt-in, off by default).**

```bash
# Hand Phase 1 the prior report's findings as hot spots to INDEPENDENTLY
# re-verify. Good for production regression tracking; it correlates this run with
# the prior one, so DO NOT use it for union-recall benchmarking (it breaks the
# run independence that measurement assumes). The run is flagged 'seeded' in
# scan_meta.json and the report so it is never mistaken for an independent sample.
--seed-prior
```

Mode A is how you *track* findings across runs without changing what a run finds;
Mode B is how you *bias* a run toward known hot spots when you deliberately want
correlated runs. Keep Mode B off for any benchmarking.

---

## 6. Things that will look like bugs but aren't

- **Long gaps between log lines.** A hunt agent thinks for 1–3 minutes per turn.
  Confirm liveness with `ollama ps` (should show `100% GPU`) rather than the log.
- **`results/` full of dubious findings.** By design — Phase 2b filters them.
- **An occasional Ollama HTTP 500** mentioning `error parsing tool call`. The
  model emitted malformed JSON; the client retries automatically. Harmless
  unless it repeats.
- **Fewer partitions than expected.** If Phase 1's table can't be parsed the
  runner falls back to one whole-repo partition and **logs a warning**. Grep the
  log for `could not parse a partition table` — that silently costs you most of
  Phase 2's coverage.

## 7. Real failure signals

```bash
python3 -m vhlocal.logs <scan-tag> | \
  grep -E 'hit max_turns|no output produced|NOT marking complete|could not parse'
```

Any hit means a phase under-delivered. Re-run that phase with `--phases <key> --resume`.

---

## 8. Calibration — read before trusting results

`gpt-oss:120b` is weaker than Opus at the long multi-hop tracing this
methodology depends on. In validation on this fixture, recall on 2–3 hop bugs
was strong, but agents assigned to a partition with no bug in their class still
invented findings. **Precision, not recall, is the weak point.**

Treat output as a structured code-review aid, not an autonomous scanner. Before
relying on it for real work, build a ground-truth corpus with
`harness/local_harness/benchmark/` and measure. A scanner that reports fluent,
wrong findings is worse than no scanner.
