# Contracts — Artifacts, surfacing & compatibility

How multi-language inventory/coverage/support-matrix data is persisted, surfaced, and kept
backward-compatible. All changes are **additive** (no schema-version field exists; compatibility =
additive-only + graceful read + parity contracts). IDs map to requirements/SCs.

## Persisted artifacts

- **C-A1 (coverage_ledger.json, extended)**: Continues to emit for compatibility; `Route`/`LedgerEntry`/
  `CoverageLedger` gain `language`, `application_type`, `surface_kind`, and the evidence-backed
  `CoverageDisposition` (replacing the mention-based one). Existing parity consumers still read it
  (FR-025/029/034).
- **C-A2 (findings.json, additive)**: `application_intelligence` gains an `inventory` + `support_matrix` +
  `coverage_axes` block; `run_status.coverage_degraded_reasons` gains language-scoped reasons; execution/
  coverage/validation remain independent axes (FR-024/027/029/032).
- **C-A3 (scan_meta.json, additive)**: `RunRecord` gains `languages_detected`, `languages_enumerated`,
  `inventory_engine`, and generalized (non-`.py`) source-size fields; additive-only per existing discipline
  (FR-032).
- **C-A4 (support_matrix.json, new)**: A new artifact of `SupportMatrixEntry` per (language, application-type)
  — readability, deterministic recognition (dedicated/limited/unsupported), verification checks, fallback
  review, known unsupported constructs, recognizer mechanism + versions, acceptance status. A cell is
  "supported/dedicated" only when its end-to-end fixture passes (FR-017/018, SC-008). Added to
  `reports.Manifest`.

## Surfacing

- **C-A5 (report render)**: `report.go` `Input`/RenderMarkdown/RenderHTML gain a support-matrix + multi-axis
  coverage section and a Nav entry (`reportNav`); per-finding language/framework/module shown; no broad UI
  redesign (FR-029/030/033).
- **C-A6 (API projection)**: `internal/server/status.go` `scanStatus` re-exposes the new coverage/support
  fields; `reports.Report`/`Load` carry a languages/coverage summary for the dashboard/aggregation;
  `support_matrix.json` reachable via the existing artifact/file endpoints; **existing dashboard values and
  charts are unchanged and additive-only** (FR-030/033, SC-010).
- **C-A7 (exports)**: `sarif.go` and `manifest.go` carry language-scoped coverage/degraded reasons with
  equivalent semantics; `manifest.configHash` updated only if a new config key is introduced (FR-029/032).

## Compatibility & preservation

- **C-A8 (legacy honesty)**: Older reports lacking the new evidence read as **unknown/legacy**, never
  retroactively declared complete; historical reports open without a forced rescan or rewritten evidence;
  resume/regeneration MUST NOT accept stale inventory as valid completion or invent review evidence, and MUST
  NOT silently launch a scan (FR-031/032/034/035, SC-009/010).
- **C-A9 (no regression)**: Features 008–011 behavior (dashboard metrics/charts, application/ledger
  management, analyst review decisions, reports, ledgers, history) is unchanged; parity contracts
  (`tests/parity/reference/contracts.json`, `schema_test.go`, `reference_contract_test.go`) are EXTENDED for
  the new additive fields and stay green (FR-036, SC-010).

## Prompts & integration

- **C-A10 (prompt/denominator reconciliation)**: The deterministic multi-language inventory MUST be fed into
  recon/partition/hunt task inputs so the model hunts the discovered scope; the already-multi-language recon
  prompts (`skill/phases/phase1_recon.md`) are wired to the deterministic denominator rather than only
  re-discovering via Glob (FR-015/016, R6).

## Fixtures & validation

- **C-A11 (per-language end-to-end fixture)**: Each baseline language has an offline fixture
  (`testdata/<lang>app/` + `ground_truth` + `tests/parity/transcript/<name>.json` +
  `golden/<name>.json`) with vulnerable/defended/unresolved examples, driven by `engine.Execute` +
  transcript/fake providers + `Project`/`Compare`, run with no live model/network/target runtime and no CGO
  (FR-016/040, SC-001/005/011).
- **C-A12 (scripted vs empirical)**: Scripted-pipeline fixtures prove the flow; a separate bounded empirical
  evaluation on real repositories is documented (results + limitations) and NOT presented as detection-
  accuracy from the scripted passes (FR-040, SC-012).
