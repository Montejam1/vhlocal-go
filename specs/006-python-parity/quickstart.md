# Quickstart & Validation: Python-reference parity

**Feature**: 006-python-parity | **Date**: 2026-09-16

Prove semantic parity offline, then hand off for live testing. Contracts: [contracts/behavior.md](./contracts/behavior.md); entities/shapes: [data-model.md](./data-model.md); decisions: [research.md](./research.md).

> Live validation is the operator's. Everything here uses recorded transcripts / fakes and never contacts an inference endpoint. Prereqs: Go 1.23+ (`export PATH=$PATH:/usr/local/go/bin`). Shared fixture: `testdata/vulnapp` (byte-identical to the reference copy). Authoritative reference: `../vhlocal/vhlocal/`.

## The default gate (hermetic — no Python, no network)

```bash
go test ./...
```

Expected after the feature: all green, including the parity-behavior test (Go projection vs the committed reference-derived expected projection) and every partition/fidelity/coverage regression. The feature-005 suite stays green.

## The parity-behavior gate (Go-only)

```bash
# Go-only, hermetic: Go engine vs committed reference-derived expected projection
go test ./tests/parity/ -run TestParityBehavior -v
```

Drives the Go engine on `testdata/vulnapp` with the shared transcript and asserts its normalized semantic projection (dispatch scope, candidates by norm_id, dispositions, tiers, coverage, handoffs/artifacts, run status) equals the committed expected projection. No Python is executed.

## Reviewing/authoring the expected golden (documented)

```bash
go run ./tests/parity/projctl <results-dir>   # prints a run's semantic projection to
                                              # author/review tests/parity/golden/*.json
```
The expected golden is authored from the reference code (`../vhlocal/vhlocal/`), documented as reference-derived — not a measured Python diff.

## Targeted offline scenarios (each maps to a contract)

1. **Partition parity (C-1a..d)** — a Phase-1 output with a partition table → hunt dispatches over the parsed partitions × classes; malformed table → one repartition → deterministic fallback, recorded; omitted routes augmented; over-cap → uncovered.
2. **Differential (C-D1..D5)** — the harness passes on the shared fixture; a seeded flipped-verdict/dropped-candidate fails it and names the dimension; incidental noise is normalized; the run needs no Python; a transcript gap fails loudly.
3. **Verification/publication fidelity (C-3a..d)** — incomplete-function evidence and mismatched authz entry point are not accepted supported; each battery class reaches the reference tier; a review record yields `reviewed`.
4. **Coverage/artifacts (C-4a..c)** — denominator matches the reference (prefixes/websocket/method defaults); artifact-manifest validation binds entries to supported candidates + on-disk files; canary/budget halt with a reason.

## Done criteria (→ Success Criteria)
- [ ] SC-001 differential harness passes on the shared fixture (default gate)
- [ ] SC-002 a seeded semantic divergence fails it and names the dimension
- [ ] SC-003 hunt dispatches over the model's partition plan; malformed → repartition → recorded fallback
- [ ] SC-004 each battery class: Go disposition + tier equal the reference's
- [ ] SC-005 coverage denominator matches the reference on the fixture
- [ ] SC-006 every closed divergence has a failing-before offline test; feature-005 stays green; default gate hermetic
- [ ] SC-007 live validation operator-owned, explicitly pending

## Live validation (operator-run, later)
Once the differential gate passes, re-run the live scan against the reference target/model and confirm the Go run's supported/rejected/unresolved dispositions and coverage track the reference's on real output. The harness does not initiate this — you do.
