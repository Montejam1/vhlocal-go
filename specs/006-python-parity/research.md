# Phase 0 Research: Meet semantic parity with the Python reference

**Feature**: 006-python-parity | **Date**: 2026-09-16

Decisions resolving the plan's choices, grounded in the reference code (`../vhlocal/vhlocal/`) and three live runs. Each: **Decision / Rationale / Alternatives**.

---

## R1. Partition resolution (US1)

- **Decision**: Port `resolve_partitions` into `internal/phases/partition.go`: (1) parse the Phase-1 "Subgraph Partitions" markdown table (`_parse_partition_table_text` — tolerant: find the heading, take `|`-rows, pull an `SG-N` id + a 1–3-cell description); (2) if empty and text exists, one corrective repartition — a fresh-context Chat asking for ONLY the strict JSON array (`parse_partition_json`); (3) else deterministic subsystem partitions from routes (`inventory.deterministic_partitions`), else a single `SG-1` whole-repo partition. Record `source ∈ {model_table, model_retry, deterministic, single_fallback}`, `fallback`, `collapsed`, `parse_error`. Then `augment_partitions_for_coverage` (append coverage partitions for enumerated route files the plan omitted; cap → `uncovered_remaining`) and `augment_partitions_from_threat_model`. Wire the resolved partitions (with their descriptions/routes) into `runHunt` and into each hunt task's assigned scope.
- **Rationale**: This is the largest live-behavior divergence: Go currently ignores the model's plan and hunts one deterministic `backend` partition. Parity requires the reference's model-first resolution + augmentation, with the honest fallback recording.
- **Alternatives**: Keep deterministic-only partitions (the current gap — fails parity). Rejected. Skip the corrective retry (reference does exactly one — keep it).
- **Corrective repartition**: reuse the same-endpoint fresh-context pattern already in `internal/agent` (like `repairFromRaw`): a minimal Chat with `PARTITION_JSON_SCHEMA_HINT`; parse via `parse_partition_json`; accept only if it yields >1 partition (reference rule). Bounded, recorded (Principle V).

## R2. Differential harness architecture (US2)

- **Decision**: Compare **normalized semantic projections**, not raw artifacts. A **projector** reduces a results dir to a canonical JSON: `{dispatch: [{partition, class}...] + passes, candidates: [{norm_id, cwe, location}...], dispositions: {norm_id → supported|rejected|unresolved}, tiers: {norm_id → classification}, coverage: {entry_point → disposition}, handoffs: [names present], artifacts: [names present], run_status: {execution, coverage, validation_mode}}`. A Go projector (`tests/parity/project.go`) reduces a Go run to this shape. The Go `parity_behavior_test.go` runs the Go engine on a shared transcript over `testdata/vulnapp`, projects it, and asserts equality with a committed EXPECTED projection authored from the reference code. No Python is executed.
- **Rationale**: Byte/artifact diffs fail on incidental + intentional-deviation noise; a semantic projection captures exactly the parity the operator cares about (scope, verdicts, tiers, coverage, status).
- **Alternatives**: Diff `findings.json`/`scan_meta.json` directly (drowns in incidental + ID differences). Rejected.
- **normalized identity** (`norm_id`): `sha1(normalized-path + ":" + line-bucket + ":" + CWE)` where line-bucket rounds to the cited line (or the containing route line) — stable across the Go-heuristic vs Python-AST identity difference. Both projectors compute `norm_id` the same way from the published finding's location + CWE, so candidates align for comparison even though raw `CAND-` ids differ.

## R3. Authoring the expected golden from the reference code (US2)

- **Decision**: Do NOT execute Python. The committed EXPECTED projection (`tests/parity/golden/vulnapp.json`) is authored by reading the reference methodology (`../vhlocal/vhlocal/`) and encoding the dispatch/candidates/dispositions/tiers/coverage/run-status it would produce for the transcript over `testdata/vulnapp`. Its provenance is documented in `tests/parity/README.md` as "reference-derived, not a measured Python diff". The `tests/parity/projctl` helper prints the Go run's projection to aid authoring/reviewing the golden.
- **Rationale**: The operator has run the Python reference many times and judges parity by recognition; they explicitly do not want Python involved. The Go gate still pins behavior and prevents regressions; the operator is the final parity judge on a live run.
- **Alternatives**: Run the Python reference (via a replay hook) to measure the golden — rejected per the operator's constraint. Rely only on the operator's recognition with no gate — rejected: a pinned regression gate still has value.
- **Honest limit**: a mistaken reading of the reference would pass the Go gate but be caught by the operator's recognition on a live run. Documented in the golden's provenance.

## R4. Transcript format + cross-engine matching (US2)

- **Decision**: The transcript is a set of **semantic response rules** keyed by the semantic situation the grounded prompts expose (robust to exact prompt wording, so the fixture stays valid as prompts evolve):
  - **hunt**: key `(phase=2, partition-ident, class-code)` → an assistant response emitting the scripted candidate write for that unit.
  - **verify**: key `(phase=2b, candidate normalized-identity)` → the scripted `capture_evidence` + `submit_verification` calls (verdict + evidence lines).
  - **recon/threat/report** (phases 1/1t/3/3d/4): key `(phase)` → the scripted deliverable write (incl. the partition table for phase 1, so US1's parse is exercised).
  The Go replay provider extracts the key from the request (regex over the grounded prompt: partition name, class code, `file:line`/CWE) and return the matched rule's response; a matched rule with sub-steps (capture then submit) advances by call count within that candidate's session.
- **Rationale**: Semantic keys keep the transcript stable regardless of exact prompt wording; the fixture data (partition names, candidate locations) appears verbatim in the grounded prompts.
- **Alternatives**: Exact-prompt-hash replay (diverges — different wording). Turn-index replay (diverges — different turn counts). Rejected.
- **Risk (documented)**: the transcript encodes the intended evidence + verdict per candidate; building it to exercise every phase is the gate's main complexity and is done incrementally (dispatch + dispositions + tiers first, then coverage + artifacts).

## R5. Verification & publication fidelity (US3)

- **Decision**: (a) Require evidence to cover the **complete containing function** — approximate the reference AST span with a bracket/indentation-scan of the cited file to find the enclosing `def`/handler range, and require the union of evidence line-ranges to cover it (tighten the current "covers the cited line" rule). (b) For access-control verdicts, require the submitted `entry_point` to equal the resolved route guard (reuse `internal/authz`). (c) Extend the quality battery: SSTI constant-template refutation, access-control NA handling, and class-primary evidence beyond CORS as the reference defines. (d) Add the distinct `reviewed` classification tier when a validated review record is present.
- **Rationale**: Once dispatch scope matches (US1), these are the fidelity gaps the harness will flag on verdicts/tiers.
- **Alternatives**: Keep the line-window function approximation (misses the reference's function-coverage requirement → tier divergence). Rejected.

## R6. Coverage denominator + corpus (US4)

- **Decision**: In `inventory`, resolve `APIRouter(prefix=…)`/`Blueprint` prefixes onto route paths, add websocket routes, and default a method-less `route`/`api_route` to `ROUTE` (not `GET`) — matching the reference enumeration. Keep the feature-003 narrowed review corpus (results/*.md only) as a **justified, recorded divergence** unless the harness shows it changes a coverage disposition on the fixture, in which case reconcile to the reference corpus.
- **Rationale**: The denominator drives the coverage numbers the harness compares; the corpus divergence was a deliberate honesty choice (feature 003) and is kept unless it breaks parity.
- **Alternatives**: Reconcile the corpus unconditionally (would undo a deliberate honesty fix). Deferred to what the harness actually flags.

## R7. Artifact validation + orchestration (US4)

- **Decision**: `internal/verification/artifacts.go`: validate each `artifact_manifest.json` entry references a known **supported** candidate and an existing on-disk file (under `poc/`/`exploit_tests/`) carrying the candidate ID + location; flag unregistered on-disk artifacts and orphaned entries; never overwrite a real manifest (feature-005 guard kept). Port the hunt **canary** (a cheap preflight Chat proving transport before fan-out) and the **budget cap** (where a paid backend is configured), recording halt reasons.
- **Rationale**: Completes the reference's artifact honesty + safety controls; the canary would also have surfaced the transport issue earlier in the live runs.
- **Alternatives**: Leave artifact manifests as presence-only placeholders (fails artifact-dimension parity). Rejected.

---

## Resolved unknowns

- Expected golden without Python → R3 (authored from the reference code; `projctl` aids review).
- Cross-engine transcript matching → R4 (semantic response rules).
- Candidate-identity mismatch → R2 (`norm_id` normalized identity).
- Hermetic Go-only gate → R2 (committed reference-derived expected projection; no Python).
- No new runtime dependency; additive-only schema (populate already-declared partition fields). No `NEEDS CLARIFICATION` remains.
