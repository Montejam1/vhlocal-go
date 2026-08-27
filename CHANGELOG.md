# Changelog

Notable feature updates to vulnhunt-local. Newest first.

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
