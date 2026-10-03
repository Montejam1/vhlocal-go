# Contract: Behavioral contracts for Python-reference parity

Observable behavior contracts, each asserted by an **offline** test (Principle VII). **No live model.** Grouped by story. C-D* are the Go-only parity-behavior gate dimensions. Feature-005 behaviors and existing artifact filenames/API paths are preserved (C-X*).

## US1 — Partition parity (`internal/phases`, `internal/engine`, `internal/inventory`)

- **C-1a**: A valid Phase-1 Subgraph-Partitions table is parsed into its partitions and the hunt dispatches over them (each × the class split); `partition_source = model_table`.
- **C-1b**: An unparseable table triggers exactly one corrective strict-JSON repartition; if it yields >1 partition, those are used (`partition_source = model_retry`, `fallback = true`); otherwise deterministic subsystem partitions are used (`deterministic`) or a single whole-repo partition (`single_fallback`, `collapsed = true`) — the parse error recorded.
- **C-1c**: Enumerated route files absent from the plan are appended as coverage partitions (`coverage_partitions_added`/`_files_added`); additive threat-model partitions are added; over-cap files land in `coverage_uncovered_remaining` (never dropped).
- **C-1d**: Each hunt task's assigned scope carries the partition's concrete routes (method path file:line) from the resolved plan/augmentation.

## US2 — Parity behavior gate (Go-only) (`tests/parity`)

- **C-D1**: A single offline run executes the Go engine on a shared transcript over `testdata/vulnapp`, projects it to the canonical semantic JSON, and asserts equality with the committed reference-derived expected projection; it passes only on full agreement across dispatch, candidates (norm_id), dispositions, tiers, coverage, handoffs/artifacts, and run status.
- **C-D2**: A seeded semantic divergence (flip a verdict / drop a candidate / change a tier in the scripted responses) fails the gate and names the diverging dimension and candidate.
- **C-D3**: Only-incidental differences (timestamps, temp/abs paths, ordering, raw `CAND-` ids) do NOT fail the gate (normalized away).
- **C-D4**: The gate is Go-only and needs no Python interpreter (it compares to the committed reference-derived expected projection); `go test ./...` stays hermetic.
- **C-D5**: A transcript that lacks a rule for a request one engine issues fails loudly (no silent divergence).

## US3 — Verification & publication fidelity (`internal/verification`, `internal/consolidate`)

- **C-3a**: A supported submission whose evidence does not cover the complete containing function is NOT accepted supported (stays unresolved with a reason).
- **C-3b**: A supported access-control verdict whose stated entry point ≠ the resolved route guard is NOT accepted.
- **C-3c**: For each represented class (SQLi, XSS-into-JSON vs HTML, CORS credentialed-wildcard vs safe, weak-random consumer vs none, SSTI constant-template, access-control), the Go publication tier equals the reference tier on identical evidence.
- **C-3d**: A validated review record yields the distinct `reviewed` tier (above `statically_supported`).

## US4 — Coverage, artifacts, orchestration (`internal/inventory`, `internal/verification`, `internal/engine`)

- **C-4a**: The coverage entry-point denominator on `testdata/vulnapp` matches the reference: router/blueprint prefixes applied, websocket routes included, method-less routes as `ROUTE`.
- **C-4b**: `validate_artifacts` accepts an entry only if it references a known supported candidate and an existing on-disk file carrying the candidate ID + location; unregistered on-disk artifacts and orphaned entries are flagged; a real manifest is never clobbered (feature-005 guard).
- **C-4c**: A hunt canary failure / budget-cap trip (where configured) halts with a recorded reason.

## Preserved invariants (C-X)

- **C-X1**: Existing artifact filenames and API paths/shapes retained; schema changes additive-only (populate declared fields; no key removed/renamed).
- **C-X2**: Feature-005 behaviors (verification sessions, source-grounded support + veto, honest reporting, coverage/resume, tools) and their tests still pass.
- **C-X3**: Static-only boundary, configured-endpoint-only routing (the corrective repartition and canary are same-endpoint), loopback/allow-root posture, and the three independent status axes all still hold; the parity gate is Go-only and test-only.

## Acceptance
The full offline suite passes; C-D1 (the Go-only parity-behavior gate) is the parity gate and passes on the shared fixture; each closed divergence's regression test fails before its fix (SC-006); the feature-005 suite stays green; the default gate needs no Python.
