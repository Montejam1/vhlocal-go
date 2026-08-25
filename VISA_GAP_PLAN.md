# vhlocal ← Visa harness (vvaharness): capability gap analysis & adoption plan

_What the Visa "agentic SAST" harness (`visa-vulnerability-agentic-harness`, pkg
`vvaharness`) does that vhlocal does not — and a phased plan to close the gaps
without breaking vhlocal's constraints (stdlib-only Python 3.9, static-only by
default, local/self-contained, self-contained web UI)._

## The two harnesses at a glance

**vvaharness** — an S0 static pre-stage + a 9-stage LLM pipeline
(`s0 seed → s1 preprocess → s2 threatmodel → s3 decompose → s4 deepdive →
s5 prefilter → s6 verify → s7 dedup → s8 chain → s9 SARIF`), then default-on
`s10 remediate` (writes patches, can edit source) and `s11 validate` (agentic
panel grades the fixes). It has a real static taint/call-graph engine (Python/
Java/C#), CVSS 3.1 + CMDB + CVE/design-control injection, SARIF 2.1.0, secret/PII
redaction, majority-vote FP filtering, exploit-chain analysis, 42 language
lenses, 6 specialist lenses (incl. IaC), 4 backends (Claude CLI/SDK, OpenAI,
DeepAgents), SQLite checkpoints, and multi-repo batch.

**vhlocal** — recon → hunt fan-out (partition × class + sink-driven) → 2b verify
→ 3 reproduce → 3d deterministic sweep → 4 report. Pure LLM + grep (no static
dataflow), Ollama/OpenAI-compat/OpenRouter backends, canonical-CWE labeling,
deterministic entry-point coverage denominator, cross-run **Vulnerability Ledger**
+ lifecycle (regression tracking), cost guards (canary/breaker/streaming), and a
self-contained local web UI.

## What vhlocal already matches or exceeds (do NOT rebuild)

| Capability | vvaharness | vhlocal |
|---|---|---|
| Adversarial verification | s6 verify (TRUE/FP) | Phase 2b falsification (gates §1–§9) |
| CWE taxonomy → name/URL | 77 ids | `knowledge.py` canonical families + MITRE URLs |
| Deterministic dedup | s7 | `flag_duplicates` / root-cause clustering |
| Resume / checkpoints | SQLite | per-phase file state + `--resume` |
| Coverage honesty | Scan Health | deterministic entry-point denominator + "N of M reviewed" |
| **Cross-run finding memory** | — (none) | **Vulnerability Ledger (union + recall) + lifecycle** ← vhlocal is ahead |
| **Transport cost guards** | budget cap | **canary + circuit breaker + streaming** ← vhlocal is ahead |

## Gap inventory (what to add)

Legend — Value: how much it improves results; Fit: alignment with vhlocal's
constraints; Effort: build cost.

| # | Gap | Value | Fit | Effort |
|---|---|---|---|---|
| **Outputs** |
| 1 | **SARIF 2.1.0 export** (rules catalog, CWE taxa, `invocations.executionSuccessful`) | High | High (stdlib json, deterministic) | Low |
| 2 | **run_manifest.json** audit record (version, roles, config hashes, git SHA, args, outcome, timing) | Med | High | Low |
| 3 | **errors.jsonl + "Scan Health" report section** (failed chunks, per-stage error counts) | Med | High (re-surfaces data we already have) | Low |
| 4 | **Secret/PII redaction at write time** (Luhn+IIN cards, SSN, creds/keys) | High (payments context) | High (stdlib regex) | Low-Med |
| **Scoring / enrichment** |
| 5 | **CVSS 3.1** base vector + score + rating per finding | Med | High (deterministic from canonical family) | Med |
| 6 | **Knowledge injection**: CVE feed (raise likelihood), design-controls (downrank, demand bypass proof), CMDB (env scoring) | Med-High | High (prompt-level + scoring) | Med |
| **Detection methods** |
| 7 | **Majority-vote / multi-sample FP filter** (finding must appear in ≥K runs) — directly attacks run-to-run variance | High | High (pairs with the Ledger) | Med |
| 8 | **Static taint/call-graph seed (s0)** — interprocedural source→sink, sanitizer/reflection/route-param taint | High | Partial (stdlib `ast`, Python-first) | High |
| 9 | **Exploit-chain analysis (s8)** — combine confirmed findings into attack chains + re-rank | Med | High (prompt-level phase) | Low-Med |
| 10 | **Specialist lenses** — IaC (Terraform/Docker/K8s/Ansible/Actions) + deserialization; auto-gated by surface | Med | High (reuses class-file mechanism) | Med |
| 11 | **Per-language researcher lenses** (auto-selected hint packs) | Low-Med | High | Low-Med |
| **Remediation / fix verification** |
| 12 | **Remediation agent** — minimal fix per finding as a unified `diff.patch` + DTO (report-only; opt-in fix-apply) | High | Partial (report-only preserves static-only; fix-apply is opt-in, git-guarded) | High |
| 13 | **Agentic validation panel** — security-architect + pen-tester (+ cross-repo) personas grade fixes → Fixed/Partial/Not/Unverifiable | High | Med (depends on #12) | High |
| **Ops / robustness** |
| 14 | **`max_budget_usd` cost cap** (abort when spend exceeds cap) | Med-High (post-$16) | High (extends canary/breaker) | Low |
| 15 | **Config profiles (YAML)** — declarative per-role model/stage presets (default/sdk/full/taint) | Med | High | Low-Med |
| 16 | **Multi-repo batch** (CSV → clone/scan → group-by-AppId → batch_summary.md) | Med | High (build on `bench.py`) | Med |
| 17 | **Anthropic-native backend** (Claude CLI/SDK) + **DeepAgents** option | Low-Med | Med (vhlocal is local-first by design) | Med |

## Phased plan

### Tranche 1 — Quick wins: outputs & hygiene ✅ DONE (2026-08-24)
Ships CI-grade, enterprise-legible artifacts with no change to detection.
_Shipped: `vhlocal/sarif.py`, `vhlocal/manifest.py`, `vhlocal/redact.py`, a
"## Scan Health" report section + `errors.jsonl`, a `redact` opt-in wired through
spec/engine/server, and UI updates (redaction toggle in the scan form; SARIF /
manifest / findings.json download buttons + a Scan Health panel on the report
detail). 360 tests passing._
- **`sarif.py`** — deterministic `findings.json`/`SCAN_REPORT.md` → SARIF 2.1.0.
  `tool.driver.name="vhlocal"`, `rules[]` catalog from emitted CWEs,
  `supportedTaxonomies` = CWE (reuse `knowledge.py`), `invocations[0].executionSuccessful`
  from `run_status`. Wire into `consolidate.write_consolidated`; emit
  `<results>/findings.sarif`. Add UI download + a test mirroring `test_enrich_sarif`.
- **`manifest.py`** — write `run_manifest.json` (engine version, per-role models,
  config hash, git SHA from `lifecycle.git_provenance`, args, outcome, phase
  timings). Most fields already live in `scan_meta.json`; this is the audit view.
- **Scan Health + `errors.jsonl`** — a report section built from the
  `coverage_degraded_reasons` + agent `stopped_reason`s we already compute, plus a
  structured recoverable-error log.
- **`redact.py`** — stdlib regex redactor (Luhn+IIN card numbers, SSN, common
  API-key/cred patterns) applied at write time to `SCAN_REPORT.md`,
  `findings.json`, HTML. Off switch for local trusted use.

### Tranche 2 — Beat the variance ✅ DONE (2026-08-24)
_Shipped: `vhlocal/pricing.py` (`Budget`, per-token cost, keyless OpenRouter price
resolution); `hunt_samples` multi-sample voting in `_run_fan_out` (`_merge_hunt_samples`
unions candidates + dedups with vote counts; each sample budget/cancel/breaker-gated);
`max_budget_usd` cap that halts the fan-out and between phases, preserving partial
results; wired spec→engine→RunRecord→scan_meta→server; manifest `cost` block +
Scan Health spend/samples lines; UI got Hunt-samples + Budget-cap fields and report
health chips. 374 tests passing._

The recurring pain is run-to-run variance concentrated in the authz/logic class.
- **Multi-sample hunt voting** (opt-in) — run each hunt unit N times at T>0 and
  keep candidates appearing in ≥K samples before 2b; surfaces the volatile
  access-control findings a single pass drops. Report vote counts (feeds SARIF
  `properties.votes`).
- **Tie into the Ledger** — treat `confirmed_count`/`cross_family` as the
  cross-run vote; expose a "consensus" confidence in the report. (Ledger already
  exists; this is wiring + a confidence surface.)
- **`max_budget_usd` cap** (#14) — belongs here: multi-sampling multiplies spend,
  so gate it behind a hard budget that the canary/breaker enforce.

### Tranche 3 — Detection breadth ✅ PARTLY DONE (2026-08-24)
_Shipped: **vote-count propagation** (`vhlocal/votes.py` — merge writes `hunt_votes.json`,
consolidate attaches `votes`/`vote_samples` to each finding → findings.json + SARIF
`properties.votes` + report line); **deterministic exploit-chain analysis**
(`vhlocal/chains.py` — authz-amplified-sink + shared-surface rules → "Exploit chains"
report section + findings.json `chains` block + UI chip); **IaC/CI-CD lens**
(`phase2_class_iac.md` + auto-gated repo-wide `p2:iac` agent, `iac_lens` flag wired
through, budget/breaker-gated, no-op when no infra). 385 tests passing. **Deferred:
the static taint seed** (largest lift; see below) — do only if voting+lenses don't
close the recall gap._
- **Exploit-chain phase (#9)** — a post-2b prompt that composes confirmed findings
  into attack chains and re-ranks; add a "Chains" report section. Cheap, high signal.
- **Specialist lenses (#10)** — add an **IaC** class file (Terraform/Dockerfile/
  K8s/Helm/Ansible/GH-Actions) and an opt-in **deserialization** lens; auto-gate
  by file-type presence, reusing the Phase-2 class-group dispatch.
- **Static taint seed (#8), Python-first** — a stdlib-`ast` interprocedural
  source→sink pass that emits "hot" candidate flows to seed Phase 1/2 (like
  `seed_routes`, but dataflow). Scope to Python initially; reuse `inventory.py`.
  Largest lift in this tranche — do it last, and only if voting+lenses don't
  already recover the misses.

### Tranche 4 — Remediation & fix verification ✅ CORE DONE (2026-08-24)
_Shipped (deterministic, static-only, `vhlocal/remediation.py`): **report-only
DTOs** (`build_dtos`/`write_remediation` → `remediation/<VULN>/remediate.json` +
`summary.md` + `index.json`; no source edited), the **patch-safety +
isolated-worktree apply** layer (`patch_confined` refuses traversal/absolute
escapes; `apply_in_worktree` applies only to a throwaway copy), and **validation
scoring** (`score_validation` → Fixed / Partially Fixed / Not Fixed / Unverifiable
from weighted gate votes). Wired `remediate` opt-in through spec/engine/server, a
findings.json `remediation` block + "## Remediation" report section + UI toggle and
🩹 health chip. 397 tests passing. **Deferred to the live-model layer:** the
model-backed unified-diff generation and the adversarial validation personas — the
containers/scoring are ready for them to plug into._
- **Remediation report-only mode (#12)** — extend Phase 3c to emit a per-finding
  unified `diff.patch` + DTO under `remediation/<VULN>/`, **without editing
  source** (keeps vhlocal static-only by default).
- **Fix-apply mode** — explicit opt-in, applied in a throwaway git worktree, never
  the user's tree by default.
- **Validation panel (#13)** — an adversarial pen-tester persona re-attacks the
  patched code + a design reviewer → Fixed / Partially / Not / Unverifiable, folded
  into the finding DTO. Depends on report-only mode landing first.

### Tranche 5 — Ops & scale ✅ CORE DONE (2026-08-24)
_Shipped: **config profiles** (`vhlocal/profiles.py` — JSON presets quick/thorough/
share/benchmark + user `~/.vhlocal/profiles/*.json`; structural knobs only, never a
model; `/api/profiles` + a New-Scan dropdown that fills the form) and **multi-repo
batch** (`vhlocal/batch.py` — CSV → per-repo scan → group-by-AppId → batch_summary.md,
per-repo failure isolation, `python -m vhlocal.batch` CLI). 415 tests passing.
**Skipped: Anthropic-native backend** — Claude is already reachable via OpenRouter,
and a native SDK backend conflicts with vhlocal's stdlib-only / local-first design;
not worth the dependency._
- **Config profiles (#15)** — YAML presets for per-role model/stage knobs
  (`default`, `paid`, `taint`), loadable from the UI and CLI.
- **Multi-repo batch (#16)** — CSV of repos → clone/scan → group-by-AppId →
  `batch_summary.md`, built on `bench.py`.
- **Anthropic-native backend (#17)** — optional, only if local-first is relaxed.

## Recommended starting point
**Tranche 1 (SARIF + manifest + redaction)** for immediate enterprise/CI value at
low risk, then **Tranche 2 (voting + budget cap)** because it targets the exact
variance problem that has driven the recent "worse run" results. Tranches 3–5 are
larger and can follow once 1–2 prove out.
