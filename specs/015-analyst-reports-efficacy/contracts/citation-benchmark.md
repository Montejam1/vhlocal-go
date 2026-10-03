# Contract — Citation validation & repair, verifier diagnostics, benchmark (Workstream B, part 2)

## Citation validation at ingestion (FR-025)
- **C-C1**: every extracted hunt finding passes `citation.Parse` + `Resolve` before entering
  `candidate_manifest.json`; the manifest records `citation.status` and, for invalid ones, the error code —
  invalid candidates are counted in `raw_count` and shown in the report appendix, and are never sent to a
  verification session.
- **C-C2**: unambiguous normalizations (backticks, `line N`/`lines N-M`, trailing commentary, en-dash) are
  applied with `normalization[]` provenance and the original text retained; the audited strings
  `confirm_password_reset function, line 224-242 in backend/app/routers/auth.py` → `E_CITATION_AMBIGUOUS`,
  `backend/app/security.py:40 - hash_token uses …` → normalized to `backend/app/security.py:40`,
  `backend/app/routers/customers.py:49-55, 62-64` → primary `49-55` + supplementary `62-64`.
- **C-C3**: a unit whose deliverable contains invalid citations receives exactly one correction turn with
  per-finding `{field, code, received, expected, aids}` feedback; `hunt_execution.detail[].citation` records
  `invalid/repaired/remaining/correction_turns`; the assignment is `valid` only if the rewritten file parses
  (remaining invalid findings stay in the manifest as `invalid_citation`).
- **C-C4**: no helper shifts a citation to nearby code, clamps a range, or guesses a handler; file-only or
  unrelated citations cannot become valid by formatting.

## Verification session contract (FR-025..027)
- **C-C5**: the task text includes the resolved handler span, route guard `METHOD PATH` (identity) with a
  separate display label, file length, and required evidence span when the recognizer resolves them, plus the
  worked example from `skill/phases/phase2b_session.md`; `prompt_hash` and `tool_schema_hash` are recorded on
  every prompt record and in `scan_meta`.
- **C-C6**: `submit_verification` feedback is structured (`code`, `field`, `received`, `expected`,
  `repairable`, `aids`); identical repeated submissions stop after the second with `E_REPEATED_SUBMISSION`;
  malformed JSON / wrong-typed arguments are rejected explicitly (`E_TOOL_ARGS_JSON` / `E_TOOL_ARGS_TYPE`)
  and never coerced to defaults.
- **C-C7**: `amend_candidate` accepts at most one amendment per session; it must resolve and bind; same
  resolved anchor ⇒ identity kept; different anchor ⇒ new candidate id with `supersedes`, old id
  `superseded`, no decision inherited; amendments are replayed idempotently on resume and rejected on
  revision mismatch; regeneration never invokes the model or rewrites citations.
- **C-C8**: a perfect verdict on a candidate whose original citation is invalid and unamended is rejected
  (`invalid_citation` cannot be bypassed); an explicit `unresolved` decision is accepted and counted as
  `unresolved_explicit`, never as a failure.
- **C-C9**: evidence rules are unchanged: byte-matching quotes, span coverage, entry-point identity,
  function evidence — the existing reference-contract parity tests keep passing.

## Failure records and diagnostics (FR-026, FR-029)
- **C-C10**: `verification_calls.jsonl` has one line per tool call/attempt with its own `class/code/message`;
  a session with an argument error then a submission error ending at the turn limit records three distinct
  entries (args, submission, turn exhaustion) and `SessionOutcome.failures_by_class` counts each; aggregates
  report `occurrences_by_class`, `sessions_by_class`, `stop_reasons` and an overlap note; the summary events
  no longer reuse the session's last message for other classes.
- **C-C11**: `diagnostics/<candidate>.json` holds the complete failing submission(s) and exact feedback,
  prompt/tool-schema hashes and source references, sufficient to replay the contract failure offline through
  `verification.Reconcile` without any model; `truncated_fields[]` declares any preview truncation;
  telemetry truncation is never described as model-context truncation; no credentials, no hidden reasoning.
- **C-C12**: `SessionOutcome` carries `model` and per-call `provenance`; `AgentRecord` for 2b carries the
  candidate id.

## Comparison harness (FR-028)
- **C-C13**: `vhlocal verify-compare` re-runs only 2b over a frozen manifest and revision; `comparison.json`
  records per variant the effective role config observed on **every** call (provenance), decisions
  (supported / rejected / unresolved_explicit / missing), repair rate, evidence validity, truth accuracy when
  a truth file is given, cost and seconds, plus `config_diff[]`; `gate.efficacy_improved` is `false` with
  reason `all_unresolved` when a variant's accepted decisions are ≥ 95% `unresolved`; live variants are
  `not_run: true` until executed.
- **C-C14**: offline tests prove the override reaches every verifier call with a fake provider that records
  its own identity per call; no commercial model is required; no source is sent to another provider unless
  the operator names it.

## Go recognizer (FR-030)
- **C-C15**: `r.URL.Query().Get("q")`, `r.Header.Get(...)`, `w.Header().Get(...)`, `values.Get(...)`
  produce no route; Gin/Chi/ServeMux/echo registrations remain recognized with handler refs; unknown
  receivers with a path-like first argument are `ambiguous` (disclosed, outside the denominator);
  `TestGoRecognizerNegativeControls` keeps its count; `coverage100` uses the real construct.

## Benchmark (FR-021..023)
- **C-C16**: `internal/benchmark.Score` counts a truth entry as detected only by a `supported ∧ non-duplicate`
  finding matching an acceptable anchor; duplicates and rejected/unresolved never count; unmatched supported
  findings are FP; hits on `safe_control` entries are FP flagged by language/family; denominators are
  explicit; `cost.usd` is `"unknown"` for unpriced backends.
- **C-C17**: ground truth lives outside the scanned target and outside prompts (test: the scan's prompt
  records never contain a truth id); seeded and unseeded runs are labelled.
- **C-C18**: the frozen baseline records target revision, build, effective config, models, prompt and schema
  hashes, sampling, seeds, budgets; `POLICY.md` defines regression relative to the baseline with declared
  tolerance per language/family and no absolute rate; comparisons print `config_diff` first; live runs are
  operator-triggered and reported `not_run` until performed.

## As-built status (2026-09-29)

Citation/repair/diagnostic tests, the frozen-manifest verifier comparison, scorer, CLI and offline transcript baseline are implemented. Full diagnostic conversations are content-addressed (prompt hash alone conflates different candidates); 5 MB is the context/preview cap, with complete decisive submissions retained even when larger. Unreferenced context files are pruned with the newest 200 diagnostics. Comparison output requires an explicit NEW directory and named provider; dry-run variants are not run. No live efficacy claim is made.

See `docs/engineering/2026-09-29-015-completion.md` for executed evidence and remaining operator checks. The diagnostic content-addressing and explicit output-directory requirement are disclosed implementation clarifications; no evidence-validation or efficacy acceptance rule was relaxed.
