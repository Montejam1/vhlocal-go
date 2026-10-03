# replay-audit — sanitized replay of the audited run (feature 014, T004)

This fixture reproduces, **offline and deterministically**, every failure category
the 2026-09-28 scan-reliability audit observed on a real run — without storing any
prompt, model output, repository content or operator path from that run.

It is not a directory of hand-authored records. Hand-written `findings.json` /
`review_units.json` files would drift from the engine's real schema and could
never prove that the *engine* produces an honest completion block. Instead,
`scenario.json` names the failure shapes, and `internal/engine/outcome_test.go`
assembles a provider double that induces exactly those shapes while the real
engine runs against `testdata/coverage100` (100 entry points, Python + Go). The
records the test then inspects (`scan_meta.json`, `findings.json`,
`review_units.json`, `hunt_execution.json`, `verification_sessions.json`,
`verification_reconciliation.json`, `artifact_manifest.json`, `SCAN_REPORT.*`)
are therefore always the engine's own, at the current schema.

## Audited category → replay

| Audited observation | Replay | Record that must show it |
|---|---|---|
| A hunt unit stopped "complete" and wrote nothing (silently missing deliverable) | `silent_hunt_unit` = `svc05`: the double answers "done" without a Write, on the first run **and** on the bounded re-run | `hunt_execution.json.detail[*].status = missing`, `attempts = 2`; `run_status.outcome.failed_assignments` lists all three files with their unit ids. With coverage enforcement on (the default) the ONE bounded follow-up unit (`hunt:sg-N:followup`) re-reads the routes, so they end `reviewed_no_issue` and `review_units.json.follow_up_ran = true` — the failed assignments stay listed regardless: recovery never hides the failure |
| Candidates left unresolved with no diagnosable cause | `exhausted_candidate` (svc03): the session issues valid Reads until the turn limit and never submits | `verification_sessions.json.failures_by_class.turn_exhaustion > 0`; reconciliation reason cites the dominant class; `run_status.outcome.failed_candidates[].class = turn_exhaustion` |
| A supported finding whose reproduction phase produced no disposition | `supported_candidate` (svc02) is verified through the real evidence contract; phase 3 runs with a double that authors nothing | `artifact_errors` / `run_status.outcome.missing_artifacts` contains `no reproduction disposition for <id>`; phase 3 not completed |
| Unregistered artifact files on disk | `orphan_artifact` = `poc/stray_test.py` planted before the run | `missing_artifacts` contains `unregistered artifact: poc/stray_test.py`; the file is never deleted |
| `phases=all` reported as if 1t had failed when the threat model was simply off | `threat_model: false` with `1t` requested | `phases_skipped` contains `1t`; `run_status.outcome.disabled_optional_phases = ["1t (threat_model=false)"]`; execution status is not penalised for it |
| Execution and coverage collapsed into one status | — | `execution_status = partial` **and** `coverage_status = degraded` with reasons, as independent axes; the queue job status is a separate field on the server (never inside `run_status`) |

## What the test proves (SC-009, FR-021..023)

1. `run_status.outcome` in `findings.json` is **byte-identical** to `scan_meta.json.outcome`
   and to the record returned by `Execute`.
2. `SCAN_REPORT.md` and `SCAN_REPORT.html` render a `Completion` section whose counts
   are the same numbers (units, candidates, failed assignments/candidates, missing
   artifacts, disabled phases, recovery steps) — no report-only arithmetic.
3. `vhlocal report` regeneration (`engine.Regenerate`) reproduces the identical
   block from the persisted records alone, and alters **no** finding evidence
   (`verification_decisions.json`, `candidate_manifest.json`,
   `verification_sessions.json`, `artifact_manifest.json`, `hunt_execution.json`,
   `results/*.md`, `phase*_output.md`) and no human review decision.

## Rules

- Never store model prompts/outputs here (the live scan's prompt evidence lives in
  `prompts.jsonl` under the results directory and is redacted).
- Everything runs offline; no inference endpoint is contacted.
- Storage is fully isolated (`internal/engine/main_test.go` redirects every
  operator store to a temp root).
