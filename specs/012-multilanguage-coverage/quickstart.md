# Quickstart & Validation Guide: Multi-language scan coverage

This feature is **backend/engine-heavy** and validated entirely **offline**: deterministic recognizers
plus per-language end-to-end scripted scans (controlled model responses) — no live inference, no network,
**no target-language runtimes**, and **no CGO**. Scripted-pipeline validation is kept distinct from a
bounded empirical evaluation. Additive surfacing is browser-checked by the operator; existing dashboards
must not regress.

## Prerequisites

- `export PATH=$PATH:/usr/local/go/bin`
- `CGO_ENABLED=0 go build ./...` (the shipped binary is static; recognition must build with CGO off).
- Fixtures: per baseline language, `testdata/<lang>app/` + `testdata/ground_truth/<name>.json` +
  `tests/parity/transcript/<name>.json` + `tests/parity/golden/<name>.json`, each with a vulnerable
  (supported), a defended (rejected with a real defense), and an unresolved example (research R8).

## Automated offline gate (the increment gate)

```bash
export PATH=$PATH:/usr/local/go/bin
CGO_ENABLED=0 go build ./...
go test ./... -count=1     # recognizers + per-language end-to-end + parity, all green
go vet ./...
gofmt -l internal cmd      # clean
```

Offline Go coverage to add (maps to contracts/SCs):

- `internal/recognize` per language — unit tests against authored expected inventories with negative
  controls (fake routes/commands in strings, dead code): exact match of expected units, inputs, sensitive
  ops, and source locations; determinism (identical ids/ordering on re-run); failure isolation (malformed
  file → Limitation, others intact); fallback for unrecognized surfaces (C-R1..C-U6, SC-003/004).
- `internal/recognize.EnclosingScope` per language — correct containing-function span (Go via go/ast; brace;
  indentation; Ruby def/end) (C-S1).
- verification — ungated per-language function-evidence requirement, per-language sink/auth, checker-absence
  → unresolved (not refutation), exact quotation/identity preserved (C-S2/S3, SC-006).
- coverage — evidence-backed disposition (two-unit file, one with evidence → the other stays unreviewed),
  four distinct axes with denominators, no blended percentage, assignment of all in-scope units (C-C1..C-C3,
  SC-006/007).
- surfacing/compat — additive fields in coverage_ledger/findings/scan_meta/support_matrix; parity contracts
  extended and green; legacy report reads as unknown/legacy; dashboards unchanged (C-A1..C-A9, SC-010).
- static-only — tests assert recognition performs no exec/process/network and requires no target runtime
  (C-R2, SC-011).

## Per-language end-to-end scan-to-report (the core proof)

For each baseline language, mirror `tests/parity/full_pipeline_test.go`
(`TestFullPipelineArtifactsAndDeterministicPhases`):

1. Target = `testdata/<lang>app/`.
2. Load `tests/parity/transcript/<name>.json` (scripted Hunt/Verify tool calls).
3. `engine.Execute(ctx, spec, providers{transcript}, staticSkill{}, nil)` into a temp results dir — the
   **real pipeline** (recognize → partition/assign → hunt → verify → report).
4. `Project(out)` → compare to `tests/parity/golden/<name>.json`; assert the vulnerable candidate is
   supported, the defended one rejected (real defense), the unresolved one unresolved, each reaching the
   published report; assert `Regenerate(out)` is deterministic.
5. Assert coverage is language-scoped (no Python-empty denominator for a non-Python repo) and no unit is
   falsely "reviewed" (C-A11, SC-001/005).

## Staged validation

- **Stage 1 (Python/Go/JS-TS)** — Python regression stays green on its existing tests + fixtures; Go and
  JS/TS each pass their new end-to-end fixture. Stage 1 passing does NOT mark the feature complete (SC-008).
- **Stage 2 (Java/C#/Ruby/PHP)** and **Stage 3 (Kotlin/C/C++/Rust)** — each language passes its recognizer
  tests + end-to-end fixture + support-matrix acceptance.
- **Support matrix** — `support_matrix.json` matches observed behavior for every language; each "supported"
  cell is backed by a passing fixture (SC-008).

## Operator / empirical (owned by operator; documented, not in CI)

- Additive surfacing browser-check: scan detail + report show language/framework/module/unresolved scope and
  the support matrix; existing dashboard metrics/charts, application/ledger management, and analyst review
  decisions are unchanged (SC-010).
- A **bounded empirical evaluation** on representative real repositories is documented (results +
  limitations), reported separately from scripted validation and without an unsolicited paid/long model scan
  (SC-012).

## Standing constraints honored

- No workloads to a live model; recognition/verification proven with controlled responses.
- No target-language toolchains/runtimes required; no target code executed/imported; no CGO.
- Path/symlink confinement preserved; scan evidence and prior features (008–011) untouched; new data additive.

## Success-criteria coverage

SC-001↔per-language e2e fixture; SC-002↔non-HTTP app-type recognizers; SC-003/004↔recognizer unit tests +
negative/robust controls; SC-005↔mixed-language + non-Python denominator; SC-006↔evidence-backed review;
SC-007↔four-axis coverage + consistent counts; SC-008↔staged delivery + support matrix; SC-009↔determinism +
failure/resume; SC-010↔no regression + legacy honesty; SC-011↔offline/no-runtime/no-exec; SC-012↔scripted vs
empirical separation.
