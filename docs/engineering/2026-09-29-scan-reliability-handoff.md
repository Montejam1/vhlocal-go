# Engineering handoff: feature 014 (scan reliability) — delivery and first live run

Prepared 2026-09-29. Target: `vhlocal-go`; reference: `../vhlocal` (read-only).

Feature 014 is implemented (64/64 tasks, `specs/014-scan-reliability/`). This note records what the
offline gate proves, what the operator's first live run on the new binary showed, the three defects that
run exposed (all fixed the same morning), and the follow-ups it uncovered. Observations below come from
read-only inspection of the saved results directory and the running server's API; no scan, regeneration,
restart or target-code execution was performed while preparing it.

## What is machine-verified

`gofmt` (clean, excluding the pre-existing 012 fixture `testdata/goapp/api/routes.go`), `go vet ./...`,
`go build ./...`, `CGO_ENABLED=0 go build -o bin/vhlocal ./cmd/vhlocal` (static ELF), `go test ./...`
exit 0, `go test -race` on engine/jobs/server/agent exit 0. A sha256 fingerprint of `~/.vhlocal/*` and
`~/vulnhunter-reports` taken before and after the entire suite is **byte-identical** (SC-011).

That last check found and fixed a real leak during Polish: only the engine package had `TestMain`
isolation; the server/jobs/cli suites appended to the operator's real `~/.vhlocal/vhlocal.log` on every
run. `internal/testisolate.Isolate()` now redirects `HOME` and every `VHLOCAL_*` store for each test
binary (engine, server, jobs, cli, apps, parity, activity, membank, reports, logsetup).

Quickstart scenarios 1–12 map to named passing tests (see `quickstart.md`); the browser half of SC-010 is
operator-attested (all nine checklist items declared complete on build `cc3c1f0-dirty`,
`built_at 2026-09-29T13:58:08Z`, assets hash `ecdfd971…`), not machine-verified.

## The first live run on the 014 binary

```text
~/vulnhunter-reports/vc-claude-code-seeded-v2-logistics-dispatch-fastapi_VULNHUNT_RESULTS_gptoss120b_2026-09-28-221735
```

gpt-oss:120b for every role (no `--verify-model`), phases `1 1t 2 2b 3 3d 4`, `phase2_mode=split`,
`max_partitions=8` → 23 partitions, 208 hunt agents, 4,782 model calls, 53.5 M prompt tokens / 1.56 M
completion tokens, 44 repairs, 10,709 s (≈3 h).

| Record | What it says | Assessment |
|---|---|---|
| `run_status` | `execution_status=partial`, `coverage_status=degraded` with 9 reasons (121 unresolved candidates; 4 missing reproduction dispositions; 4 unregistered `poc/*.py` files) | Correct: 2b and 3 did not complete. Axes stay independent. |
| `review_units.json` | 100 entry points, 100 evidenced dispositions: 7 `reviewed_with_findings`, 93 `reviewed_no_issue`, 0 gaps; `coverage_ledger.json` agrees (7 / 93) | The model did read every handler span. This is the first live 100/100 that is evidence-backed rather than asserted. |
| `hunt_execution.json` | 277 planned deliverables, 277 `valid`, 0 retries | No silent units this run. |
| `verification_sessions.json` | 171 sessions: 58 `complete`, 86 `tool_repair`, 27 `max_turns`; failures by class: `invalid_submission` 283, `invalid_tool_args` 95, `turn_exhaustion` 27, `tool_envelope` 13, `transport` 0 | Per-operation diagnosis works; see the finding below. |
| `verification_reconciliation.json` | 43 supported, 7 rejected, 121 unresolved (113 with no decision, 8 with a submitted `unresolved` verdict) | Fail-closed pipeline held: nothing unresolved became a finding. |
| `prompts.jsonl` | 4,784 records (17 recon, 10 threat-model, 2,218 hunt, 2,103 verify, 434 reproduce, 1 canary, 1 repartition), 63 MB, 99% `truncated:true` at the 8 KB clamp | Complete capture; size dominated by the embedded methodology text. |
| `SCAN_REPORT.md` | `## Completion` and `## Review coverage` present with the same numbers as the records; recovery steps name the turn limit, the tool contract, phase 3 re-run and the log | Consistent with `scan_meta.outcome` and `findings.json.run_status.outcome`. |
| Live evidence (running scan `fb52ee7dc462`) | `/artifacts` → `state:ready, total:5`; `/log?tail=3` → tagged lines within seconds of `phase_start`; `/api/config.build` → `cc3c1f0-dirty`, `ldflags` | SC-001/SC-012 observed on a real run. |

### The operational finding: the verifier model fails the submission contract

Of 113 candidates that ended with no decision, the dominant contract violations were:

| Violation (from `last_contract_violation`) | Sessions |
|---|---|
| `candidate needs an exact source location` | 45 |
| `review entry point does not match the cited source handler` | 29 |
| `evidence must cover the cited primary location (the containing handler/defenses)` | 10 |
| `path must be repo-relative` (at `capture_evidence`) | 5 |
| class-specific refutation / evidence-id / verdict-shape violations | 5 |
| turn budget exhausted with valid reads and no submission | 27 |

The engine is behaving as designed — evidence rules are not weakened and every failure is attributable.
The bottleneck is gpt-oss:120b's compliance with `submit_verification`. Two follow-ups, outside 014's
scope, are recommended:

1. **Prompt coaching, not rule relaxation**: the repair feedback already quotes the contract; consider
   putting the exact-location / entry-point-match requirements and a worked example into the 2b system
   prompt so the first submission is well-formed. Measure by the `invalid_submission` count per session.
2. **Use `--verify-model`** with a model that follows tool contracts more reliably; the recovery steps
   in the completion block already say this. The per-class counts give a direct before/after metric.

## Defects the live run exposed (fixed 2026-09-29 before this note)

| Defect | Evidence | Fix |
|---|---|---|
| Unresolved candidates that **did** receive a submitted `unresolved` verdict were classed by an incidental tool-failure count from earlier in the session (e.g. `CAND-060304a0…` labelled `invalid_tool_args`, reason = the model's own rationale) | 8 of 121 in the live reconciliation had `record.verdict=unresolved` | `engine.buildOutcome`: `record != nil` → class `unresolved_verdict`; failure-class recovery steps no longer count these. Regression: `TestOutcomeClassifiesUnresolvedVerdictSeparately`. |
| `review_units.json.gaps` was `null` on a gap-free run | live record | initialised to `[]`. |
| Contract promised "expand fetches the full prompt record by `seq`"; the clamp is applied at write time and the full text is not stored | 4,745 of 4,784 records truncated | contracts corrected (`records.md`, `evidence-api.md`); no code change — the per-record bound is intentional. |

The scan running at the time of writing (`…_2026-09-29-080013`) started on the binary built at
`13:58:08Z`, before these fixes. Its completion block will label any verdict-unresolved candidates with the
old class. After it finishes: rebuild, then `vhlocal report <results-dir>` regenerates the block from the
records alone — no evidence or decision is touched (FR-023, `TestRegenerationLeavesEvidenceAndReviewsUntouched`).

## Backlog carried out of 014

- 012 Go recognizer: `url.Values.Get("q")` is recognised as a route (false positive); `testdata/coverage100`
  avoids it with `r.FormValue`.
- Verification prompt coaching / `--verify-model` evaluation (above).
- Parity `dispatch` projection intentionally skips class `followup` units (documented divergence from the
  reference, which never dispatches them).
- 322 files are uncommitted since `first commit` (features 012–014); a commit boundary per feature is
  recommended before the next sprint.

## Follow-up delivered in feature 015

The Go receiver recognizer now excludes URL/header/value getters from route
counts, and `coverage100` uses the original `Query().Get` construct again.
Verifier coaching, structured citation repair/amendment, per-call diagnostics,
and a frozen-manifest comparison command are implemented and tested offline.
Summary-first reports, diagram fallback and coverage v2 are also implemented.

The recommended **live** verifier/model evaluation remains **not run**; see
`2026-09-29-efficacy-baseline.md` and `2026-09-29-015-completion.md`. The transcript
baseline is a reproducibility fixture, not evidence that the 113 live sessions
would now submit decisions. No operator results were regenerated, no server was
restarted, and existing uncommitted work was preserved during completion.
