# Changelog

Notable feature updates to vulnhunt-local. Newest first.

## 2026-08-27 — App Intel by application, reports multi-delete; Phase 1t validated

- **App Intel is now organized by application, not a scan dropdown.** Scanning the
  same folder is the same app, so reports are grouped by target repo; the tab shows
  a list of applications (with Threat model / SBOM badges + scan count), and
  clicking one opens that application's most recent threat model + SBOM. The report
  listing now carries `has_sbom` / `has_threat_model` so grouping needs no per-file
  probing.
- **Reports table: checkbox multi-select + bulk delete.** Per-row and select-all
  checkboxes, a selection bar, and a guarded "Delete selected (N)".
- **Phase 1t validated end-to-end.** A recon+threat-model run on gvisor (2 min,
  local gpt-oss) correctly characterized it as a *container/OS sandbox runtime*,
  produced a data-flow diagram and PASTA threats, and emitted hunt targets for the
  real sandbox surface — `pkg/sentry/platform/systrap` (syscall processing),
  `runsc/cmd/exec.go`, the admission webhook — exactly what recon's web-only
  enumeration missed. (The prompt must live in the skill dir the scan uses; it is
  in `skill/phases/` — point `--skill-dir` there.)

## 2026-08-27 — Application Intelligence tab + coverage-honesty fix

### Application Intelligence tab
- New top-level **App Intel** tab. Pick a scan; view its intelligence in two
  sub-tabs: **SBOM** (rendered from `sbom.cdx.json` — component table + ecosystem
  summary + CycloneDX download) and **Threat model (PASTA)** (the `threat_model.md`
  rendered, including the data-flow diagram). Reuses the existing report-file
  endpoint and client markdown renderer — no new backend. (Live Mermaid diagram
  rendering is a follow-up; the DFD currently renders as a labeled source block.)

### Coverage-honesty fix — a shallow run can no longer report "complete"
- The gvisor scan enumerated **0 entry points across 2,970 source files** yet
  reported `coverage_status: complete`. `compute_run_status` now flags two
  deterministic shallowness signals as **degraded**, regardless of `max_partitions`:
  recon enumerating **no entry points** over a non-trivial codebase, and a large
  codebase (150+ source files) hunted in a **single partition**. The reasons name
  the file count and point at scoping / the PASTA threat model as the fix.
- Suppressed when the threat model already added partitions. 6 new tests.

## 2026-08-27 — Phase 1t: PASTA threat model (opt-in) — coverage fix for non-web targets

- **Root problem it fixes:** recon's attack-surface enumeration is web/RPC-shaped
  (routes → inputs → sinks), so on an unusual target it under-covers. A gvisor scan
  collapsed to one partition (the docs website) and missed the entire sandbox —
  its real attack surface (syscall handlers, packet/9P parsers) was never
  partitioned or hunted, and the run still reported "complete."
- **New Phase 1t (post-recon, pre-hunt), gated on `ScanSpec.threat_model`.** Follows
  **PASTA**: characterize the app + its **archetype**, threat-model *that class* of
  software (a sandbox → guest→host escape; a parser → memory corruption; a crypto
  lib → side channels), produce a **data-flow diagram** (Mermaid) with trust
  boundaries, and emit a `Hunt targets` block mapping threats → concrete code paths.
- **Purely additive to the hunt.** `augment_partitions_from_threat_model` appends a
  partition for each threat target whose code recon didn't already cover
  (existence-checked, priority-ordered, bounded). Web apps are unaffected; unusual
  targets *gain* the syscall/parser partitions they were missing. Also generates the
  SBOM (PASTA Stage II) and feeds the report's Application Intelligence.
- UI: **Build threat model (PASTA)** toggle. CLI: `--threat-model`. Prompt in
  `skill/phases/phase1t_threat_model.md`. 13 new tests.
- Report rendering of the threat model + DFD is the next step (the model + partition
  drive land first).

## 2026-08-26 — Application Intelligence, findings quality, ledger view

Development thread paired with the web-UX effort. All changes are static-only,
stdlib-only (Python 3.9), and covered by tests (`python3 -m unittest discover -s tests`).

### Application Intelligence — SBOM
- **CycloneDX 1.5 Software Bill of Materials**, generated deterministically from
  the target's dependency manifests — no model, no network (`vhlocal/sbom.py`).
  Parses Python (`requirements*.txt`, `pyproject.toml` — PEP 621 + Poetry), npm
  (`package.json`), Go (`go.mod`), Maven (`pom.xml`), Ruby (`Gemfile.lock`),
  Rust (`Cargo.toml`), and PHP (`composer.json`); skips vendored trees; dedups;
  deterministic ordering. Runs standalone: `python -m vhlocal.sbom <repo>`.
- Written per run as `sbom.cdx.json`, surfaced as an **Application Intelligence ›
  Software Bill of Materials** section in the report, an
  `application_intelligence.sbom` block in `findings.json`, and in the UI a
  **SBOM (CycloneDX) ↓** download plus a `📦 N deps` health chip.
- First piece of a planned Application Intelligence area (SBOM → STRIDE threat
  model → architecture diagram → LLM enrichment).

### Findings quality — deterministic hunt-evidence parser
- Reports no longer collapse when the model-authored Phase 4 is thin. The report
  now parses the **raw per-partition hunt evidence** (`results/sg-*.md`) directly
  and makes it authoritative when it yields substantially more *well-formed*
  findings (real CWE + descriptive title) than the Phase 4 / Phase 2b sources.
- Robust to the class agents' format variance: mixed heading styles
  (`### [VULN-001]`, `## 3. VULN-001 —`, `### NAV-01 — … — HIGH`), **header-aware**
  Summary-table parsing (column order differs between files — CWE/Severity swap),
  severity/CWE prefixes baked into title cells, and cross-reference index rows
  that merge into their write-up.
- Impact: on a real run this turned an 11-fragment report (verdict-table cells as
  titles, missing CWEs, wrong locations) into 32 clean, deduplicated findings.

### Vulnerability Ledger view
- New top-level **Ledger** tab: a per-application memory of findings across every
  scan, aligned to the analyzed application. Lists each app with
  tracked / open / fixed / regressed / reliable counts and a severity breakdown;
  selecting one shows the full finding history — title, CWE, location, status,
  cross-run confirmation count (with a cross-model-family marker), and confidence.
- Backend: `membank.list_ledgers()` / `load_ledger(slug)`; server endpoints
  `GET /api/ledgers` and `/api/ledgers/<slug>`. Path-traversal safe (slug matched
  against the enumerated directory, never joined to a path).

### CLI parity with the web UI
- `vhlocal/run.py` now exposes every scan knob the UI has: `--hunt-samples`,
  `--iac-lens/--no-iac-lens`, `--remediate`, `--redact`, `--ledger`,
  `--max-budget-usd`, `--max-output-tokens`, `--backend openrouter`, per-role
  models (`--recon-*`, `--verify-*`, `--reproduce-*`), and `--profile`, with
  correct default < profile < explicit-flag precedence.

## Earlier in this thread (already pushed)
- Visa-harness capability tranches 1–5 (SARIF, run manifest, redaction, scan
  health, multi-sample voting, exploit chains, memory bank, remediation DTOs,
  profiles, batch) + prompt transparency.
- Location/CWE backfill from hunt evidence (unblocks dedup/votes/chains);
  multi-sample near-duplicate merge.
- Retry transient paid-backend resets; opt-in budget cap.
- Skill prompts mirrored into `skill/` so the repo is self-contained.
