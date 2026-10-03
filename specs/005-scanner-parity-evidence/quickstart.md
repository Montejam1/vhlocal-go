# Quickstart & Validation: Scanner parity and trustworthy evidence

**Feature**: 005-scanner-parity-evidence | **Date**: 2026-09-15

Reproduce today's gaps and validate the restoration — **entirely offline**. Contracts: [contracts/behavior.md](./contracts/behavior.md); entities/schema: [data-model.md](./data-model.md); decisions: [research.md](./research.md).

> Live validation is the operator's. These scenarios use scripted providers and fakes and never contact an inference endpoint. Prereqs: Go 1.23+ (`export PATH=$PATH:/usr/local/go/bin`). The shared fixture is `testdata/vulnapp` (byte-identical to the Python reference's copy). The authoritative reference is `../vhlocal/vhlocal/`.

## The default gate (hermetic — no Python, no network)

```bash
go test ./...
```

Expected after the feature: all green, including the new differential test (compares Go's normalized semantics to the committed Python-derived goldens) and every FR-039 regression. The feature-004 suite stays green.

## Opt-in live differential (requires python3 + ../vhlocal)

```bash
go test -tags pythonref ./tests/parity/
```

Runs the Go engine and the live Python reference on the same shared transcript and diffs normalized semantics. Not part of `go test ./...`.

## Regenerating the goldens (documented, manual)

```bash
go run ./tests/parity/genref            # subprocesses the Python reference on each transcript,
                                        # writes normalized semantic goldens under tests/parity/golden/
```

## Targeted offline scenarios (each maps to a contract)

1. **File tools (C-1a/b/c)** — `internal/tools`: `Read` with offset/limit returns line-numbered content + a continuation; a citation past the first page resolves; a recursive `**/*.py` glob matches nested files and each returned absolute path round-trips to `Read`/`Grep` from any CWD.
2. **Grounding + config failure (C-1d/f)** — a built phase task contains the absolute repo path, writable results dir, scope with routes, inputs, and deliverable; a missing prompt/SKILL raises an explicit configuration failure (no placeholder run).
3. **Sandbox (C-1e / C-X3)** — a write via a symlinked results parent is confined; a model write to `scan_meta.json`/`candidate_manifest.json` is refused.
4. **Orchestration (C-2a..f)** — a scripted model partition table is consumed; a malformed one triggers one repartition; omitted routes append coverage partitions and over-cap scope lands in `coverage_uncovered_remaining`; split mode dispatches (partition × INJ/NAV/LOG) + sink pass; `hunt_samples=2` produces merged votes in `hunt_votes.json`; `iac_lens` runs only with IaC present; the manifest `phase2_mode` equals the executed mode.
5. **Verification (C-3a..e, C-C1/C2)** — a candidate manifest exists before 2b; the session captures quote-matched evidence and assigns supported/rejected/unresolved; a zero-survivor pass yields zero supported with no raw resurrection; malformed decisions yield unresolved not confirmed; `phase2b_handoff.md` + phase-3 assignments are written and read.
6. **Publication + artifacts (C-4a..e, C-C3)** — a prose-arrow-only finding is not statically supported; a logic CWE retains uncertainty; all tiers are reachable; `validate_artifacts` binds entries to supported candidates + on-disk files; finalize/regeneration preserve an existing `artifact_manifest.json`.
7. **Truthfulness (C-5a..d, C-C4/C5/C6)** — an empty/wrong-path write neither marks produced nor suppresses the nudge; one hunt unit does not complete the hunt; coverage names the specific entry point; a fully-resumed run counts resumed work (not `incomplete`); a mid-run/final-phase cancellation reports `cancelled`; regeneration preserves the real backend + endpoint-failure reasons.
8. **Differential parity (C-6a/b)** — the differential test fails on a seeded semantic divergence and names the dimension; the filename/key check is labeled a smoke test.

## Done criteria (→ Success Criteria)
- [ ] SC-001 differential semantics match on the shared fixture (default gate)
- [ ] SC-002 all five outcome classes reachable + distinct
- [ ] SC-003 zero-survivor/malformed never yield confirmation
- [ ] SC-004 paged/line-numbered reads + recursive glob round-trip
- [ ] SC-005 no surface-signal static support; uncertainty retained
- [ ] SC-006 regeneration preserves manifest + provenance + reasons
- [ ] SC-007 produced/attribution truthful
- [ ] SC-008 coverage names the specific entry point; faithful denominator
- [ ] SC-009 resume counts resumed work; cancellation stays cancelled
- [ ] SC-010 options change execution; manifest reflects executed mode; cap records uncovered
- [ ] SC-011 every fix has a failing-before offline test; feature-004 stays green
- [ ] SC-012 live validation operator-owned, explicitly pending
- [ ] SC-013 remaining-simplifications resolved/deferred; prior claims corrected

## Live validation (operator-run, later)
When you choose to test live, re-run the reference target/model and confirm the scanner distinguishes supported/unresolved/rejected/incomplete/clean on real output. The harness does not initiate this — you do.
