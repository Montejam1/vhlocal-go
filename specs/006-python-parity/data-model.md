# Data Model: Meet semantic parity with the Python reference

**Feature**: 006-python-parity | **Date**: 2026-09-16

Entities, the differential-harness data shapes, and additive schema. Schema changes are additive-only (existing filenames/keys retained); the new partition fields already exist on `RunRecord` (feature 005) and are now populated.

## Partition entities (`internal/phases/partition.go`)

- **Partition**: `{ ident (SG-N), description (subsystem + concrete `method path (file:line)` routes) }`. `slug = lower(ident with spaces→-)`.
- **PartitionResolution**: `{ partitions []Partition, source ∈ model_table|model_retry|deterministic|single_fallback, fallback bool, parse_error string, collapsed bool }`.
- **CoverageAugmentation**: `{ partitions (model + appended coverage), added []ident, added_files []file, uncovered_remaining []file }`.
- **Validation**: table parse tolerant (heading + `|`-rows + `SG-N` id); corrective retry accepted only if it yields >1 partition; cap = `max_partitions + len(subsystems)`; over-cap files → `uncovered_remaining` (never dropped).

## Differential-harness entities (`tests/parity/`)

- **Transcript** (JSON): a list of response **rules**, each `{ match: {phase, partition?, class?, candidate_id?}, response: {content?, writes?[], tool_calls?[]} }`. Keyed by the semantic situation both engines expose (R4). Shared by the Go `transcriptProvider` and the Python `ReplayClient`.
- **Semantic projection** (canonical JSON, both engines produce identical shape):
  - `dispatch`: sorted list of `{partition, class}` units + the passes present (sink/iac).
  - `candidates`: sorted list of `{norm_id, cwe, location}`.
  - `dispositions`: `norm_id → supported | rejected | unresolved`.
  - `tiers`: `norm_id → classification (reviewed|statically_supported|hypothesis)`.
  - `coverage`: `entry_point (method path) → disposition (finding_emitted|reviewed_no_issue|not_reviewed)`.
  - `handoffs`: sorted names present (`phase2b_handoff.md`, …); `artifacts`: sorted artifact-manifest entry kinds.
  - `run_status`: `{execution, coverage, validation_mode}` (degraded reasons compared set-wise after normalization).
- **norm_id**: `sha1(normPath + ":" + lineBucket + ":" + CWE)` — stable across the Go-heuristic vs Python-AST identity difference; computed identically by both projectors from the published finding.
- **Differential result**: `pass`, or `{ diverging_dimension, detail (candidate/dimension), go_value, py_value }[]`.

## Verification/publication entities (US3)

- **Function span**: the enclosing handler line-range of a cited location (bracket/indentation scan approximating the reference AST span); a supported verdict requires evidence to cover it.
- **Route guard**: the resolved authorization guard for a location (`internal/authz`); an access-control supported verdict requires the submitted entry point to equal it.
- **Publication tier**: `reviewed > statically_supported > hypothesis` — `reviewed` now reachable via a validated review record; `rejected`/`unresolved` carried from verification.

## Coverage entities (US4)

- **Route** gains faithful enumeration: router/blueprint `prefix` applied to `path`, websocket routes included, method-less `route`/`api_route` → `ROUTE`.
- **Artifact manifest entry**: `{ candidate_id (supported), kind (poc|test), path (under poc/ or exploit_tests/) }`; validated against the candidate + an on-disk file carrying the ID + location.

## Additive schema (persisted)

- `scan_meta.json` — populate already-declared fields: `partition_source`, `partition_fallback`, `partition_parse_error`, `partition_collapsed`, `coverage_partitions_added`, `coverage_files_added`, `coverage_uncovered_remaining`, `threat_model_partitions`. No new keys.
- `artifact_manifest.json` — real validated entries when PoCs/tests are authored (feature-005 clobber guard kept).
- `candidate_manifest.json` — partition descriptions may enrich candidate provenance (additive).

## Preserved
Existing artifact filenames/API paths; the three status-axis field names; feature-005 verification/publication/tools/coverage behaviors and tests; static-only boundary; loopback/allow-root posture.
