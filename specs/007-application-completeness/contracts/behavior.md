# Behavior Contracts — status, recovery, report, options

Testable invariants beyond raw endpoint shapes. IDs are referenced by tasks and map to the spec's success criteria. All are verifiable offline with seeded fixtures / recorded transcripts; browser items run against a live Go server with seeded on-disk data.

## Truthful status (US3 / FR-012..016 / SC-003)

- **CB-1 (queue ≠ execution)**: A run that finishes some but not all requested phases yields queue `status=done` (it terminated) but `execution_status=partial`; no surface derives one axis from another.
- **CB-2 (no false all-complete)**: The step tracker (legacy `index.html` and, if embedded, React) renders per-phase state from `phase_outcomes`/`phases_completed`, NOT from `status==='done'`. A partial run shows the unfinished phases as not-complete with a reason and never the caption "All N steps complete."
- **CB-3 (degraded ≠ success at the queue)**: The engine surfaces a partial/degraded outcome to the queue rather than an unconditional success; a degraded run is distinguishable from a clean one at the job level (e.g. execution axis + phase_outcomes), without discarding useful partial results.
- **CB-4 (distinct dispositions preserved)**: explicit-unresolved, missing-decision, zero-candidates-after-valid-hunt, failed-hunt, authored-artifact, deferred-artifact, executed-test remain distinct across status, API, and report; none collapses into another.
- **CB-5 (resume/regenerate integrity)**: Restart, resume, and report regeneration preserve these distinctions and invalidate stale downstream completion where upstream inputs changed (no stale success is retained).

## Error vs empty (US1 / FR-003 / SC-001)

- **CB-6 (no error-as-empty)**: When `/api/scans` (or `/api/applications`) fails or returns malformed data, the operator surface shows a distinguishable error/disconnected state — never "No scans/apps yet" and never an indefinite spinner. (Fixes the dropped-`usePoll`-error path and the legacy UI equivalent.)
- **CB-7 (legacy shapes don't crash)**: Persisted jobs/reports from older shapes render or degrade gracefully; no view throws on a missing/unknown field.
- **CB-8 (reconnect coherence)**: Polling/SSE disconnect+reconnect preserves coherent state — no duplicated jobs, no false completion.

## Verification recovery (US5 / FR-022..024 / SC-005)

- **CB-9 (bounded actionable retry)**: A recoverable verification submission failure (tool-parse/schema/validation) yields actionable feedback and a bounded retry within the per-candidate budget; already-accepted work is preserved.
- **CB-10 (honest exhaustion)**: When recovery is exhausted, the candidate is `unresolved` with a useful reason and recorded `attempts`/`failures`; it is never fabricated as supported and retries are not silently increased.
- **CB-11 (authz/logic on evidence)**: An authorization/logic candidate with substantive evidence but no injection-style syntactic sink can be supported, while attacker-control/preconditions/defenses/impact/matching-revision/exact-evidence remain required.

## Reproduction per-candidate loop (US5 / FR-025..027 / SC-005)

- **CB-12 (supported-only)**: Reproduction assigns only supported candidates; each ends with registered valid material or a specific deferral.
- **CB-13 (bounded correction)**: An invalid submission (wrong candidate/location, missing file, bad header/registration) receives bounded corrective feedback with stable candidate IDs; unresolved failures are explained and the failing output is preserved as regression evidence.
- **CB-14 (never executed)**: Authored material is never described as executed; output-only tests are not accepted as proof; target code/exploits are never run.

## Report usefulness (US6 / FR-028..033 / SC-006)

- **CB-15 (supported-first, separated)**: The report leads with a supported-findings summary and keeps rejected/unresolved candidates in clearly identified separate sections.
- **CB-16 (full review detail)**: Each supported finding presents location + evidence, entry point, attacker control and flow, preconditions, reviewed defenses, security impact, rationale, remediation, and reproduction status/links or deferral — with missing items marked explicit.
- **CB-17 (no conflation)**: Candidate totals are never presented as confirmed-vulnerability totals; syntactic sweep leads are never presented as confirmed findings.
- **CB-18 (navigation + agreement)**: The report links threat analysis, SBOM, coverage, and sweep leads; Markdown, HTML, and machine-readable outputs agree on findings/outcomes/counts. Rendering stays deterministic (no model-authored consolidation).

## Honest options & limits (US7 / FR-034..036 / SC-007)

- **CB-19 (honored or rejected)**: Every supported option (threat model, ledger, role model/provider, hunt sampling, partition/coverage) is traceable request→effective-config→metadata as honored or explicitly rejected; none is silently ignored.
- **CB-20 (partition transparency)**: The requested `max_partitions`, the actual resolved partition count, and whether the control is a cap or a coverage-driven starting point are visible and explained; workload and bounded recovery are visible so a run cannot silently expand.

## Preservation & non-regression (cross-cutting / FR-037..039 / SC-008/009)

- **CB-21 (preservation)**: No existing scan, report, application name, or tracking record is lost or overwritten; pre-fix reports remain readable.
- **CB-22 (audit protections retained)**: The prior audit-protection tests still pass — distinct candidate sites, exact source/revision checks, complete reasoning, path containment, no empty-output completion, supported-only reproduction, independent reference contracts, deterministic sweep/reporting, resume/regeneration validity.
- **CB-23 (offline-first, reference read-only)**: Acceptance runs offline from fixtures/transcripts; the reference is compared by reading it (no Python executed); any live-model validation is a bounded, operator-approved plan that does not auto-launch a long scan or execute exploit material.
