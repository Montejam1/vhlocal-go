# Feature Specification: Meet semantic parity with the Python reference (vhlocal)

**Feature Branch**: `006-python-parity`

**Created**: 2026-09-16

**Status**: Draft

**Input**: User description: "meet parity with vhlocal and then I'll test"

## Overview

Feature 005 restored the scanner's methodology, verification engine, source-grounded publication, and honest reporting, and a live run now produces real results (11 confirmed findings + 46 candidates). But the Go scanner is **not yet at parity** with the authoritative Python reference (`../vhlocal/vhlocal/`): specific behaviors still diverge, and — critically — parity has only been *asserted from reading the reference*, never *pinned* by a mechanical gate against the reference methodology. The operator has been clear: they will not test again until the Go application is at parity with the Python one.

This feature closes the remaining behavioral divergences and, decisively, builds a **Go-only parity-behavior gate** that pins the Go engine's normalized semantic output (on scripted inputs) to a committed expected projection authored from the reference code — so behavior is mechanically checked. No Python is executed; the operator judges final parity by recognition. The divergences were identified by auditing the code and by inspecting three live runs; they are enumerated concretely below and each maps to a requirement.

### What "parity" means here (and its one honest limit)

Because both engines drive the *same stochastic local model*, two live runs are not even self-identical, so byte-identical live output is not the target. **Parity = semantic equivalence on identical scripted model/tool inputs**: given the same source fixture and the same recorded sequence of model responses, the Go engine must produce (matching the reference methodology) the same **dispatch scope** (partitions × classes + passes), the same **candidate set** (by normalized identity), the same **verification dispositions** (supported / rejected / unresolved per candidate), the same **publication tiers**, the same **coverage dispositions**, the same **handoffs/artifacts presence**, and the same **run-status axes** — after normalizing incidental differences (timestamps, temporary paths, ordering, and opaque identifiers). One documented limit: candidate *identity* is computed by a Go heuristic (function-owner + cited line + CWE) versus the reference's language-AST statement digest, so raw candidate IDs are not expected to match byte-for-byte; the harness compares candidates by a **normalized identity** (location + CWE + normalized statement), and the disposition/tier/coverage semantics must match the reference.

### Known divergences to close (audit basis)

1. **Partition source** — the largest live-behavior gap. Go hunts a single deterministic subsystem partition (e.g. `backend`) instead of parsing the model's Phase-1 Subgraph-Partitions table into multiple partitions, with a corrective JSON repartition retry and coverage/threat-model augmentation.
2. **Verification fidelity** — "containing function context" is approximated by a line window rather than the parsed function span; the authorization route-guard entry-point match is not enforced on a supported verdict.
3. **Quality battery coverage** — Go ports source corroboration + logic-class exclusion + XSS/CORS/weak-random veto, but not the full reference battery (e.g. SSTI constant-template, access-control specifics, class-primary evidence beyond CORS).
4. **Publication taxonomy** — the distinct `reviewed` tier (a validated review record) and full artifact-manifest *validation* (entries bound to supported candidates + on-disk files) are not implemented.
5. **Coverage denominator/corpus** — router/blueprint prefixes, websocket routes, and `ROUTE`-vs-`GET` method defaulting are not resolved; the review corpus is intentionally narrower than the reference (a feature-003 honesty choice) and must be reconciled or the divergence justified.
6. **Orchestration extras** — the hunt canary preflight and budget cap are not ported.
7. **No parity-behavior gate** — nothing mechanically pins the Go behavior to the reference methodology, so regressions go uncaught.

This serves constitution Principles I (evidence integrity), II (orthogonal status), VI (resumable/idempotent), and VII (testable, offline).

## User Scenarios & Testing *(mandatory)*

Ordered by impact on what a live run actually does. US1 changes hunt behavior the most; US2 is the proof mechanism the operator is waiting for; US3–US5 close the remaining fidelity gaps the harness will otherwise flag.

### User Story 1 - The hunt covers the model's partition plan (Priority: P1)

An operator runs a scan; recon (Phase 1) emits a Subgraph-Partitions plan describing the security-relevant subsystems. The operator expects the hunt to fan out over that plan (as the reference does), not collapse to one coarse directory partition — so the attack surface the model identified is actually hunted.

**Why this priority**: This is the biggest behavioral divergence and directly affects detection breadth. In the live run, Go hunted one `backend` partition while the reference would fan out over the model's plan across multiple subsystems.

**Independent Test**: Offline, feed a recon output containing a partition table; assert the hunt dispatches over the parsed partitions (with class split); feed a malformed table and assert one corrective JSON repartition is attempted before the deterministic fallback; assert omitted routes are augmented and over-cap scope is recorded as uncovered.

**Acceptance Scenarios**:

1. **Given** a Phase-1 output with a valid partition table, **When** the hunt starts, **Then** it dispatches over those partitions (each × the class split) and records the partition source as the model plan.
2. **Given** a malformed/unparseable partition table, **When** the hunt starts, **Then** exactly one corrective repartition (strict-JSON) is attempted, and only on its failure does it fall back to deterministic subsystem partitions — the source and any parse error being recorded.
3. **Given** enumerated routes the plan omitted, **When** partitions are finalized, **Then** they are appended as coverage partitions, additive threat-model partitions are added, and scope beyond the cap is recorded as uncovered — never dropped.

---

### User Story 2 - Parity behavior is pinned by a Go-only gate (Priority: P1)

The operator will not test live until the Go behavior is pinned to the reference methodology. **No Python is executed** — the operator has run the Python reference many times and judges parity by recognition. So a single offline **Go** command drives the Go engine on a shared source fixture with a recorded sequence of model responses, projects the run to a normalized semantic output, and asserts it equals a committed EXPECTED projection authored from the reference code — naming any dimension that diverges — so regressions are caught mechanically.

**Why this priority**: This is the mechanical gate that keeps the Go behavior aligned with the reference methodology as the other stories land. It is Go-only; the operator remains the final parity judge on a live run.

**Independent Test**: Run the Go gate on the shared fixture with a scripted transcript; it drives the Go engine deterministically (no live model, no Python), normalizes incidental differences, and passes only when dispatch scope, candidate set (normalized identity), dispositions, tiers, coverage, handoffs/artifacts, and run status all equal the expected projection; a deliberately seeded divergence fails it and names the diverging dimension.

**Acceptance Scenarios**:

1. **Given** the shared fixture and a recorded model transcript, **When** the Go gate runs, **Then** it projects the Go run and asserts equality with the committed reference-derived expected projection, passing only on full semantic agreement.
2. **Given** a real semantic divergence (e.g. a candidate flipped from rejected to supported), **When** the gate runs, **Then** it fails and names the diverging dimension and candidate.
3. **Given** only incidental differences (timestamps, temp paths, ordering, opaque IDs), **When** the gate runs, **Then** it passes (those are normalized).

---

### User Story 3 - Verification and publication fidelity match the reference (Priority: P2)

For each candidate, the operator expects the Go verifier and publisher to reach the same verdict and tier the reference would, given the same evidence — including the full containing-function requirement, the authorization entry-point check, and the complete quality battery.

**Why this priority**: These are the fidelity gaps the differential harness will flag once dispatch scope matches; closing them is what makes the verdicts themselves parity-equal.

**Independent Test**: Offline, drive verification/publication with scripted evidence for representative classes (SQLi, XSS-into-JSON, CORS, weak-random, SSTI-constant, access-control) and assert the Go disposition/tier equals the reference disposition/tier for each.

**Acceptance Scenarios**:

1. **Given** a supported submission whose evidence does not cover the complete containing function, **When** reconciled, **Then** it is not accepted as supported (parity with the reference's function-context requirement).
2. **Given** a supported access-control submission whose stated entry point does not match the resolved route guard, **When** reconciled, **Then** it is not accepted.
3. **Given** representative findings for each battery class, **When** published, **Then** the Go tier equals the reference tier (including the distinct `reviewed` tier for a validated review record).

---

### User Story 4 - Orchestration, coverage, and artifacts match the reference (Priority: P3)

The operator expects the remaining orchestration and accounting to match: the coverage denominator (router prefixes, websocket, method defaults), the review corpus (or a justified divergence), reproduction/artifact-manifest validation, and the hunt safety controls (canary, budget) where applicable.

**Why this priority**: These affect the coverage numbers and artifact honesty the harness compares, but are lower-impact than dispatch scope and verdicts.

**Independent Test**: Offline, assert the coverage denominator matches the reference on the shared fixture (prefixes/websocket/method defaults resolved); assert artifact-manifest validation binds entries to supported candidates and on-disk files; assert the canary/budget controls behave as the reference where configured.

**Acceptance Scenarios**:

1. **Given** the shared fixture, **When** coverage is computed, **Then** the entry-point denominator (with prefixes, websocket, and method defaults resolved) matches the reference, and any remaining corpus-scope divergence is explicit and justified.
2. **Given** an authored reproduction/artifact manifest, **When** validated, **Then** each entry references a known supported candidate and an existing on-disk artifact carrying the candidate ID + location; unregistered or orphaned entries are flagged.
3. **Given** a hunt canary that fails or a budget cap that trips (where configured), **When** the hunt runs, **Then** it halts with a recorded reason, matching the reference control behavior.

---

### Edge Cases

- **Recon emits no partition table**: fall back to deterministic subsystem partitions (recorded as fallback), never a silent single-partition collapse without recording it.
- **The scripted transcript drifts** (a prompt one engine issues that the transcript lacks): the harness fails loudly rather than silently diverging.
- **Candidate identity differs by construction** (Go heuristic vs reference AST): compared by normalized identity, not raw ID; a true semantic divergence (different candidate set) still fails.
- **The Python reference is unavailable** (no interpreter / sibling repo): the differential run is skipped with a clear message; the default offline gate stays hermetic against committed goldens.
- **A class the Go battery does not cover**: the finding retains uncertainty (hypothesis) exactly as the reference would, so the tiers still match.
- **Reference and Go legitimately both find nothing** on a partition: both report a clean, produced unit — distinct from a failed one.

## Requirements *(mandatory)*

### US1 — Partition parity

- **FR-001**: The hunt MUST parse the model's Phase-1 partition table into partitions and dispatch over them (each × the class split), recording the partition source (model plan / retry / deterministic / single-fallback).
- **FR-002**: On an unparseable partition table, the system MUST attempt exactly one corrective strict-JSON repartition before falling back to deterministic subsystem partitions, recording the parse error and fallback.
- **FR-003**: The system MUST augment partitions with coverage partitions for enumerated routes the plan omitted, add additive threat-model partitions, and record scope beyond the cap as uncovered — never silently dropped.

### US2 — Differential parity harness

- **FR-004**: A single offline **Go** command MUST drive the Go engine against a shared source fixture with a recorded model transcript (no live model, **no Python**) and project the run to the normalized semantic output.
- **FR-005**: The gate MUST assert the projection equals a committed EXPECTED projection — dispatch scope, candidate set (by normalized identity), verification dispositions, publication tiers, coverage dispositions, handoffs/artifacts presence, and run-status axes — passing only on full agreement. The expected projection MUST be authored from the reference code and documented as reference-derived (not a measured Python diff).
- **FR-006**: Normalization MUST strip only incidental differences: timestamps, temporary/absolute paths, ordering, and opaque identifiers; it MUST NOT mask a semantic difference.
- **FR-007**: A seeded semantic divergence MUST fail the gate and name the diverging dimension (and candidate where applicable).
- **FR-008**: The gate MUST be Go-only and hermetic (no live model, no network, no Python). The operator remains the final parity judge via their own live run.

### US3 — Verification & publication fidelity

- **FR-009**: A supported verdict MUST require evidence covering the complete containing function (including decorators/defenses), matching the reference's function-context requirement.
- **FR-010**: A supported access-control/authorization verdict MUST require the stated entry point to match the resolved route guard.
- **FR-011**: The publication quality battery MUST reach the same tier the reference reaches for each represented class (SQLi, XSS-into-JSON vs HTML, CORS, weak-random, SSTI-constant, access-control), and MUST expose the distinct `reviewed` tier for a validated review record.

### US4 — Orchestration, coverage, artifacts

- **FR-012**: The coverage entry-point denominator MUST resolve router/blueprint prefixes, websocket routes, and method defaults (`ROUTE` vs `GET`) as the reference does; any remaining review-corpus-scope divergence MUST be explicit and justified.
- **FR-013**: Reproduction/artifact manifests MUST be validated against supported-candidate identities and actual on-disk artifacts; unregistered and orphaned entries MUST be flagged.
- **FR-014**: The hunt canary preflight and budget cap MUST behave as the reference where configured, halting with a recorded reason.

### Cross-cutting

- **FR-015**: Every closed divergence MUST ship an offline regression test that fails before the fix; the differential harness MUST cover the enumerated dimensions.
- **FR-016**: Feature-005 behaviors and tests, the static-only boundary, configured-endpoint routing, loopback/allow-root posture, and the three status axes MUST be preserved. Implementation stays in Go; Python is a test/reference dependency only.
- **FR-017**: Additive schema changes MUST be documented; existing artifact filenames and API paths MUST NOT break.
- **FR-018**: All validation is offline; live validation is operator-owned and remains explicitly pending until the operator reports it.

### Key Entities

- **Partition plan**: the parsed model Subgraph-Partitions, plus augmentation and uncovered accounting, with a recorded source.
- **Recorded transcript**: an ordered, replayable set of model-response rules keyed to the semantic situation, replayed by the Go provider.
- **Normalized semantic output**: the comparable projection of a run — dispatch scope, candidate set (normalized identity), dispositions, tiers, coverage, handoffs/artifacts, run status — with incidental fields stripped.
- **Differential result**: pass, or the list of diverging dimensions/candidates.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: On the shared fixture with a recorded transcript, the Go and Python engines produce matching normalized semantic outputs across every enumerated dimension; the differential harness passes.
- **SC-002**: A seeded semantic divergence (a flipped verdict, a dropped candidate, a changed tier) fails the harness and names the dimension.
- **SC-003**: Given a valid model partition table, the hunt dispatches over the parsed partitions (multiple, per the plan), not a single collapsed partition; a malformed table triggers exactly one repartition then deterministic fallback, recorded.
- **SC-004**: For each represented battery class, the Go verification disposition and publication tier equal the reference's on identical evidence.
- **SC-005**: The coverage entry-point denominator matches the reference on the shared fixture (prefixes/websocket/method defaults resolved).
- **SC-006**: Every divergence closed ships an offline regression test that failed before the fix; feature-005 tests still pass; the default `go test ./...` stays hermetic.
- **SC-007**: Live validation remains operator-owned and explicitly pending; parity is demonstrated offline before any live test.

## Assumptions

- **Authoritative reference**: `../vhlocal/vhlocal/*.py`; the shared fixture is `testdata/vulnapp` (byte-identical across repos).
- **Parity is semantic, not byte-identical** on live runs (stochastic model); the gate uses recorded transcripts and normalized identity. Candidate raw IDs are not expected to match (Go heuristic vs reference AST) — a documented deviation.
- **No Python is executed** anywhere (operator's explicit constraint): the reference code is read for behavior, and the expected projection is authored from it and documented as reference-derived. The operator, who has run the Python reference many times, is the final parity judge on a live run.
- **The delivered product is the Go binary**; `go test ./...` stays hermetic and Python-free.
- **Out of scope**: changing models/prompts/methodology; per-agent parallelism; eliminating the model's prose+JSON behavior; UI/auxiliary-command expansion.
