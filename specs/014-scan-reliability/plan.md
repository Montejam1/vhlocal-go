# Implementation Plan: Reliable scan evidence and review completion

**Branch**: `014-scan-reliability` | **Date**: 2026-09-28 | **Spec**: [spec.md](./spec.md)

**Input**: Feature specification from `/specs/014-scan-reliability/spec.md`

## Summary

Make a scan's evidence real and reachable: bind a job to its results directory the moment the engine
announces it; produce actual prompt records and a scan-tagged operational log at the model-call and
engine-event boundaries; make Artifacts/Prompts/Log update live with distinguishable states and no
cross-scan bleed; record **evidence-backed per-unit review dispositions** (so "reviewed, no issue" exists
and coverage is honest in both directions); treat agent stop and assignment success separately with
bounded recovery of missing hunt deliverables; diagnose verification failures per candidate and per failed
operation with durable checkpoints; surface honest counts and recovery steps consistently across every
surface; make application details visibly reachable with correct historical artifact selection; isolate
all tests from operator stores and provide an explicit, backed-up cleanup of the already-polluted registry.

**Current state (verified against source this planning pass — see spec Overview table for the full
recheck):**
- `internal/jobs/jobs.go` assigns `ResultsDir` only after `run` returns; `onEvent` has no `scan_start`
  case although that event carries `results_dir`; live progress is not persisted; event ring is
  runtime-only. `jobResultsDir` collapses unknown-id and unbound to `""`, so Artifacts (`200 {files:[]}`)
  and File (`404 "no results directory"`) are indistinguishable for those cases; Log validates the id.
- **No** Go writer of `prompts.jsonl` exists; the UI fetches it via the File handler and shows "No prompts
  captured yet" on any non-success. **No** production `logsetup.New`; the Log handler returns a sentinel
  the UI renders verbatim.
- Main UI loads Artifacts/Log once per (scan, tab); only Prompts refreshes live; no abort/sequence guard;
  `loadFiles` re-queries the pane after `await`. Classic/legacy re-fetch unconditionally every 4 s; legacy
  has no Prompts tab. React `/app` has no Artifacts/Prompts/Log. Applications detail renders below the
  list with no route/scroll/keyboard/deep-link; React detail error → permanent "Loading…"; intel fetches
  treat 404 and 5xx alike.
- `inventory.BuildLedger` marks `finding_emitted` only for an in-span finding, else `not_reviewed`;
  `reviewed_no_issue`/`covered_by_parent_analysis`/`excluded_with_reason` have **zero producers**.
- Hunt: a unit counts only if `deliverableValid`, but `AgentRecord` has no `Produced` field
  (`stopped_reason: complete` beside an absent file); `hunt_execution.json` has no per-file status; there is
  **no** bounded re-run of a unit whose model said "done" and wrote nothing.
- Verification: `Reconcile` is fail-closed and `EnrichReasons` names stop/turns/failures, but tool-envelope
  parse errors and invalid evidence/decision submissions share one `failures` counter and one `tool_repair`
  stop; invalid tool *arguments* never increment `failures`; decision-less sessions flush only at the next
  accepted decision or run end, and both cancellation paths return without flushing.
- Reproduction is healthy (orphans reported never deleted; harness-written manifest; `authored`/not-executed
  labeled everywhere) — preserve and fixture-test it.
- `finalize` registers the repo unconditionally (incl. cancelled/aborted runs and regeneration) into
  `~/.vhlocal/applications.json`; the engine test package has **zero** `t.Setenv` across 40+ `Execute`
  sites; the operator's real registry holds ~100 KB of `/tmp/Test…/001` entries.

**Approach (staged, all P1):** (1) observability plumbing — binding, prompt recorder, scan log, state
contract, UI live refresh + guards, React parity; (2) evidence-backed unit dispositions + assignments +
bounded follow-up feeding `BuildLedger`; (3) hunt/verify/repro completion integrity; (4) outcome counts +
report; (5) applications UX + artifact selection + test isolation + registry cleanup. Coordinate with 013's
option contract (enforce_coverage, concurrency, budget, resume compatibility, threat-model/SBOM coupling)
and 012's inventory; extend existing code in place.

## Technical Context

**Language/Version**: Go 1.23+ (module `vhlocal`), single static binary (`CGO_ENABLED=0`). Front-end:
served `vhlocal/web/*.html` (vanilla JS, embedded) + React `web-react/` (operator-built, `/app`).

**Primary Dependencies**: standard library only — `encoding/json` (JSONL records), `sync`/`sync/atomic`
(concurrent record writers), `os`/`filepath` (append-only files, atomic renames), `net/http`. **No new
runtime dependency** (constitution Runtime budget stays at zero). Existing `internal/logsetup` is
reused for the scan-tagged log; existing `internal/redact` for redaction.

**Storage**: files, all **additive**: `prompts.jsonl` (append-only, one record per line) in the results
dir; scan-tagged lines in the existing central log (`config.LogFile()`); `review_units.json` (per-unit
dispositions + assignments); `hunt_execution.json` gains per-file status; `verification_sessions.json`
gains per-operation failure classes; `AgentRecord` gains `produced`; `RunRecord`/`findings.json`
`run_status` gains outcome counts; `jobs.json` gains the early `results_dir` binding; a registry cleanup
writes a timestamped backup before any apply. No schema-version field (additive + graceful read).

**Testing**: offline Go suite with fake/recording/barrier providers (from 013), a **delayed** fake
provider (for the 5-second live-evidence proof), a **silent** provider (stops without writing — exists as
`silentProvider`), verification fixtures per failure class, a deterministic **100-entry-point
multi-language fixture** (Python/Go/JS-TS, sibling handlers, duplicate route names) with a paired
"only-8-reviewed" variant, a sanitized replay fixture of the audited run's failure categories,
`-race` for concurrent writers, and **fully isolated storage** (TestMain sets `VHLOCAL_LEDGER_DIR`,
reports dir, log file, jobs path to temp). Browser workflow tests against a freshly built binary's
embedded assets are operator-run and recorded with build identity + tested URLs (SC-012). No live model,
no target execution, `../vhlocal` read-only.

**Target Platform**: loopback single-binary server + CLI; browser UIs (root, classic, legacy, `/app`).

**Performance Goals**: new evidence visible ≤5 s on a healthy local connection (poll interval ≤4 s
already exists; add same-tab refresh for Artifacts/Log); bounded retrieval (paged artifacts, tailed log,
capped prompt content) for large runs; record writers never block model calls beyond a mutex append.

**Constraints**: static-only; no egress beyond configured endpoints; path confinement/ownership preserved
for early binding; credentials never persisted; redaction applied before exposure; concurrent records well
formed (mutex + whole-line writes); restart preserves evidence, no auto-resume; regeneration invents no
evidence; nothing deleted except by explicit operator action (backup first); preserve features 008–013
and dashboards; coordinate with 013 contracts (no new options, no SBOM decoupling).

**Scale/Scope**: touches `jobs`, `server`, `engine` (hunt/parallel/verify/reproduction/record/resume/
regenerate/finalize), `agent`, `logsetup`, `inventory`, `verification`, `consolidate`, `report`, `apps`,
`cli`, the three HTML entrypoints, and React (`Scans.tsx`, `Applications.tsx`, `api.ts`).

## Constitution Check

*GATE: must pass before Phase 0 and re-checked after Phase 1. Constitution v1.1.0.*

- **I. Evidence Integrity** — unit dispositions are derived from observed tool evidence (reads inside the
  handler span by a unit whose deliverable validated and whose assigned scope includes the route), never
  from prose claims, path mentions, or agent stops (FR-012/014); agent stop and assignment success are
  recorded separately (FR-017); prompt records are captured at call time, never reconstructed (FR-005);
  regeneration invents nothing (FR-016/023); a no-issue review is never "proof of absence" (FR-013). PASS.
- **II. Orthogonal Status** — job termination, execution, coverage, verification, artifacts, validation mode
  stay distinct and are surfaced with counts/reasons on every surface (FR-021/022); new coverage measures
  are separate axes with explicit aggregation (FR-010/013). PASS.
- **III. Static-Only Safety** — no target execution; PoCs/tests remain `authored`/not executed (FR-020/030);
  early results-dir binding preserves confinement/ownership (FR-001); evidence reads stay confined to the
  owning results dir. PASS.
- **IV. Provenance** — prompt records carry role/model/phase/agent/order/timestamp with redactions
  labeled; build identity + tested URLs recorded (FR-005, SC-012); credentials never persisted (FR-007).
  PASS.
- **V. Explicit Failure / No Silent Fallback** — distinguishable evidence states (FR-002); per-candidate,
  per-operation failure classes (FR-018); missing deliverables become explicit failed assignments (FR-017);
  errors never hidden behind empty lists or spinners (FR-009/025); server errors never read as absence. PASS.
- **VI. Resumable / Idempotent** — bounded retry under existing cancel/budget/breaker (FR-015/017);
  decisions **and** failed sessions checkpointed incl. on cancel (FR-018); restart preserves interrupted
  status/evidence, no duplication, no auto-resume (FR-008); resume avoids duplicate candidates under 013's
  compatibility rules (FR-019). PASS.
- **VII. Testable offline** — every FR has an offline fixture/regression; `-race` for writers; isolated
  storage regression for the real-registry leak (FR-027). PASS.
- **Safety & Technical Constraints** — Runtime budget: stdlib only, no new dependency. Network: no egress.
  Server posture: confinement unchanged. Untrusted inputs: prompt/log content is model/target-derived and is
  rendered as text (never executed in the page). Determinism: dispositions, counts, and reconciliation are
  deterministic code. Data: cleanup is previewable, backed up, explicit (FR-028). **PASS.**

**Gate result: PASS.** No violations → no Complexity Tracking rows. Re-check after Phase 1: still PASS
(additive records, decorators/hooks around existing calls, no new dependency, no boundary widening).

## Project Structure

### Documentation (this feature)

```text
specs/014-scan-reliability/
├── plan.md          # this file
├── research.md      # Phase 0 (R0 verified state; R1–R13 decisions)
├── data-model.md    # Phase 1 (records: binding, prompt, log, review unit, assignment outcome, failure class, counts)
├── quickstart.md    # Phase 1 (offline gate + fixtures + isolation + build-provenance run)
├── contracts/
│   ├── evidence-api.md   # /api/scans/{id}/{artifacts,file,prompts,log} state contract; applications cleanup
│   └── records.md        # persisted record formats (prompts.jsonl, review_units.json, hunt_execution, sessions)
└── tasks.md         # /speckit-tasks (not created here)
```

### Source Code (repository root)

```text
internal/jobs/jobs.go               # bind results_dir on scan_start (persist); expose not-started vs running-no-files
internal/server/handlers.go         # distinguishable evidence states; /prompts (paged) + /log (tail, follow) handlers;
                                    #   applications cleanup preview/apply; 404-vs-5xx preserved for intel files
internal/engine/prompts.go          # NEW: prompt recorder — per-unit provider decorator → mutex JSONL sink (redacted)
internal/engine/scanlog.go          # NEW: engine/agent events → scan-tagged logsetup lines (bounded, redacted)
internal/logsetup/logsetup.go       # production init (server + CLI); tag filter unchanged
internal/agent/agent.go             # Result.Produced; Reads trace (file + line span); failure-class hooks
internal/engine/hunt.go             # per-file status; Produced on AgentRecord; bounded re-run of missing deliverable
internal/engine/hunt_parallel.go    # same for the pool (fold per-file status deterministically)
internal/engine/review_units.go     # NEW: assignments (route → unit) + per-unit dispositions from read-span evidence
internal/inventory/inventory.go     # BuildLedger consumes review-unit evidence → reviewed_no_issue / excluded_with_reason
internal/engine/verify.go           # per-operation failure classes; checkpoint after EVERY session incl. cancel
internal/verification/sessions.go   # SessionOutcome gains FailureClass + Operation; reasons name the failed contract
internal/engine/reproduction.go     # unchanged behavior; fixture tests only
internal/engine/engine.go           # finalize: outcome counts + recovery steps; follow-up scheduling under 013 options
internal/consolidate/status.go      # run_status additive counts (reviewed/total units, s/r/u, failed, missing, disabled)
internal/report/report.go           # report sections: counts, failed assignments/candidates, missing artifacts, steps
internal/apps/cleanup.go            # NEW: synthetic-entry preview + backup + explicit apply
internal/cli/apps.go                # NEW cmd: applications cleanup --preview | --apply
vhlocal/web/index.html              # live refresh for Artifacts/Log; abort+sequence guards; state messages;
                                    #   apps: hash deep-link, scrollIntoView, tabindex/keydown, stale guard, bounded list
vhlocal/web/index.classic.html, index.legacy.html   # inventory + preserve API behavior; state messages (no redesign)
web-react/src/pages/Scans.tsx, Applications.tsx, lib/api.ts  # Artifacts/Prompts/Log views; error/retry; 404≠5xx; stale guard
internal/engine/*_test.go           # TestMain isolation; leak regression; fixtures (delayed/silent/failure-class);
                                    #   100-entry-point + paired-8 fixture; sanitized replay; -race writers
testdata/coverage100/               # NEW deterministic multi-language 100-entry-point fixture (+ paired variant)
```

**Structure Decision**: extend the existing pipeline in place. Prompt capture is a per-unit provider
decorator (race-free under 013 concurrency) feeding one mutex-guarded JSONL sink; the scan log reuses
`logsetup` driven by engine events (plus new fine-grained events); review dispositions are a new engine
record consumed by the existing `BuildLedger`; all persistence is additive; cleanup is a new, explicit,
backed-up operation — never a side effect.

## Complexity Tracking

No constitution violations to justify. Concurrency-safe recording uses the standard library (mutex
around whole-line appends); no `x/sync` or third-party logging/JSONL library is introduced.
