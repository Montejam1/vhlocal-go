# Contract: Behavioral contracts for scanner parity and trustworthy evidence

Observable behavior contracts, each asserted by an **offline** test with scripted providers / fakes over the shared `testdata/vulnapp` fixture (Principle VII). **No live model.** Grouped by story; C-C* are the correctness-critical Evidence-Integrity fixes. Existing artifact filenames/API paths and feature-004 behaviors are preserved (C-X*).

## Correctness-critical (Evidence Integrity)

- **C-C1**: A verification pass where every candidate is rejected yields **zero** supported findings; `collectFindings` does not fall back to raw `results/*.md`; no rejected candidate is published as supported. *(FR-C1)*
- **C-C2**: Malformed, empty, or schema-invalid verification output publishes **no** confirmed finding; affected candidates are `unresolved`. *(FR-C2)*
- **C-C3**: With an existing non-empty `artifact_manifest.json`, `finalize` and report regeneration leave it intact (not overwritten with `[]`). *(FR-C3)*
- **C-C4**: A Write to an empty file or a path other than the declared deliverable does not set `produced` and does not suppress the deliverable nudge. *(FR-C4)*
- **C-C5**: A run cancelled mid-scan (including during the final phase) reports `execution_status=cancelled`; the cancelled in-flight agent is not recorded as `endpoint_failure` and produces no endpoint-failure degradation reason; artifacts still finalize. *(FR-C5)*
- **C-C6**: Regenerating the report of a run that used backend B and hit an endpoint failure preserves `transport.backend=B` (no fabricated `ollama`) and preserves the endpoint-failure degradation reasons and execution/coverage status. *(FR-C6)*

## US1 — grounding + file tools (`internal/tools`, `internal/engine`)

- **C-1a**: `Read` accepts `offset`/`limit`, returns line-numbered content and a continuation indication; a citation to a line beyond the first page resolves to the correct source line.
- **C-1b**: `Glob` matches nested files for a recursive pattern (reference fnmatch semantics, `*` spans `/`), and every returned path is **absolute** and directly usable by `Read` and `Grep` regardless of process CWD.
- **C-1c**: `Grep` supports path/glob/ignore_case/files_with_matches, excludes skip-dirs on both ripgrep and fallback paths, returns absolute paths, and stays bounded.
- **C-1d**: Every phase task contains the absolute repo path, the writable results dir, the assigned scope (with concrete routes where available), the prior inputs, and the exact deliverable contract.
- **C-1e**: A write via a symlinked results parent is confined and succeeds; a model write to a harness-owned artifact is refused.
- **C-1f**: A missing/unreadable required prompt or SKILL file raises an explicit configuration failure (surfaced + recorded); no placeholder agent run occurs and no phase is marked produced from it.

## US2 — hunt orchestration (`internal/phases`, `internal/engine`, `internal/inventory`)

- **C-2a**: A valid model partition table is used; a malformed one triggers exactly one corrective repartition before deterministic fallback; `partition_source` records which path was taken.
- **C-2b**: Routes omitted from the plan are appended as coverage partitions and recorded; scope beyond the cap appears in `coverage_uncovered_remaining` and is never dropped.
- **C-2c**: Split mode dispatches one unit per (partition × class) using the shared + per-class prompts and runs the sink-driven pass; combined mode concatenates class references; the manifest `phase2_mode` equals the executed mode.
- **C-2d**: `hunt_samples=N` runs N samples per unit and merges by block identity with vote provenance in `hunt_votes.json`; the recorded sample count equals the executed count.
- **C-2e**: `iac_lens` runs the IaC pass only when IaC is present; with no IaC it does not run and the manifest does not claim it did.
- **C-2f**: A hunt canary failure / breaker trip / budget halt records a reason (`hunt_halted_reason`/`budget_halted_reason`) and the run is honestly incomplete; cancellation is excluded from the breaker.

## US3 — verification + handoffs (`internal/verification`, `internal/engine`)

- **C-3a**: A candidate manifest exists before verification, keyed by the line-shift/prose-insensitive identity, and drives the session.
- **C-3b**: `capture_evidence` registers immutable evidence whose quote byte-matches live source and covers the cited location; a non-matching or stale quote is rejected.
- **C-3c**: Every candidate ends `supported`/`rejected`/`unresolved`; a supported verdict requires function/defense context + revision/identity match + the quality battery; a candidate with no valid decision stays `unresolved` with a reason.
- **C-3d**: `verification_decisions.json`, `verification_metrics.json`, and `verification_reconciliation.json` are written; the outcome is harness-owned (a model-authored decisions file is not ingested verbatim).
- **C-3e**: `phase2b_output.md` (dispositions, with the "does not imply confirmation" note), `phase2b_handoff.md` (supported-only), and the phase-3 assignment inputs are written and consumed; phase 3 never reads a non-existent handoff.

## US4 — publication + artifact validation (`internal/consolidate`, `internal/verification`)

- **C-4a**: A finding with a location + prose data-flow arrow but no source corroboration and no supported decision is `hypothesis`/`unresolved`, never `statically_supported`.
- **C-4b**: A logic/authorization CWE, or a class with no checker rule / unreadable checkout, retains explicit uncertainty and cannot reach `statically_supported` on prose.
- **C-4c**: All publication tiers are reachable and distinct: reviewed, statically_supported, unresolved, rejected, hypothesis, incomplete, clean.
- **C-4d**: `validate_artifacts` accepts an entry only if it references a known supported candidate and an existing on-disk file carrying the candidate ID + location; unregistered on-disk artifacts and orphaned entries are flagged.
- **C-4e**: No static path sets `dynamically_confirmed`/reproduced; a positive guard requires executor evidence.

## US5 — completion / coverage / resume / regeneration (`internal/agent`, `internal/engine`, `internal/inventory`)

- **C-5a**: `produced` is true only when the declared deliverable exists and is non-empty; per-unit records carry expected/actual/error/partition/vuln_class.
- **C-5b**: One hunt unit's output does not mark the whole hunt complete; failed units get placeholders and are attributable.
- **C-5c**: Coverage names the specific entry point + disposition + evidence; a bare file mention does not mark every route in that file reviewed; the enumeration denominator matches the reference (prefixes, method defaults, websocket, test-file exclusion, dedup, subsystems); a clean review (zero candidates) stays valid.
- **C-5d**: Resume validates saved-output identity + verification/artifact contract, reruns invalid units, and counts valid resumed work so a fully-resumed run is not `incomplete`.
- **C-5e**: (See C-C5) cancellation stays `cancelled` across all phases; (see C-C6) regeneration preserves status/provenance/decisions/artifact-manifest/endpoint reasons deterministically.

## US6 — differential parity + regression (`tests/parity`)

- **C-6a**: The differential test runs the Go engine on a shared transcript over the shared fixture and compares normalized semantic outputs (dispatch scope, candidate identities/provenance, verification dispositions, publication tiers, coverage, handoffs, artifacts, run status) to the committed Python-derived golden; only timestamps/temp roots/ordering are normalized.
- **C-6b**: A seeded semantic divergence fails the differential test and names the diverging dimension; the filename/key smoke test is labeled a smoke test and does not stand in for parity.
- **C-6c**: The regression suite covers every FR-039 scenario, each with a failing-before/passing-after test; the opt-in `-tags pythonref` variant runs Go vs live Python.

## Preserved invariants (C-X)

- **C-X1**: Existing artifact filenames and API paths/shapes are retained; schema changes are additive-only (new keys/files); no key is removed or renamed.
- **C-X2**: Feature-004 behaviors (tool-parse classification, same-endpoint fresh-context repair, per-phase degrade, completion nudge) and their regression tests still pass.
- **C-X3**: Static-only boundary, sandbox confinement (now incl. harness-owned-artifact guard), loopback/allow-root posture, configured-endpoint-only routing, and the three independent status axes all still hold.

## Acceptance
The full offline suite passes; every C-* above passes after the change and the correctness-critical and regression contracts fail before their fix (SC-011). The differential test (C-6a) is the parity gate; the feature-004 suite stays green.
