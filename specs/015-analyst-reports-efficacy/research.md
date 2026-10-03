# Phase 0 Research: Actionable analysis reports and measured scan efficacy

Grounded in a read-only recheck of the current source and the saved live run (five parallel surveys of
`internal/report`, `internal/consolidate`, `internal/verification`, `internal/engine`, `internal/inventory`,
`internal/recognize`, `internal/apps`, `internal/reports`, `internal/lifecycle`, `internal/review`,
`tests/parity`, `testdata`, both UIs). No scan, model, server restart, regeneration, or target code was run.
Each decision names what exists so the work is real behavior with evidence, and records what feature 014
already satisfies.

## R0 — Verified current state (the gap map)

**Report.** `report.go` renders: title → incomplete banner → Scan summary → Run status → **Completion (every
failed candidate inline)** → Review coverage → Per-phase agent table → Summary → Findings → Scope. Four
independent count/classification implementations disagree: `report.isSupported` (`from_confirmed` ∨
`verification_status==supported` ∨ classification reviewed/statically_supported), `consolidate.Build.Counts`
(**every non-duplicate finding**, feeding the severity tiles), `reports.Load` (non-dup + `classification==
hypothesis`), and `index.html:_isSubstantiated` (classification only). `Doc.Assessment` (candidates /
supported / unresolved / statically_supported / reviewed / hypotheses / reproduced) and
`VulnerabilityCounts` are computed and **never rendered**. Finding detail drops `description`, all evidence
beyond the first, and `verification_record.evidence[].quote` — the byte-validated captured excerpt that
already sits in `findings.json`. Heading hierarchy is broken (`### Supported findings` and each `### <id>`
are siblings). Both viewers render `SCAN_REPORT.md` through their own Markdown renderer with **no base-URL
rewriting**, so the report's relative links (`review_units.json`, `threat_model.md`) 404 in-app; React's
`Markdown.tsx` has no `urlTransform`. HTML filter only hides supported `<details>` (`data-sev` absent on
rejected/unresolved). No executive summary or narrative exists; the report is strictly deterministic. Assist
(`internal/assist`) is per-finding, provenance-stamped, and not in the report. Regeneration
(`regenerate.go` → `finalize`) has exactly the same inputs as a live run.

**Diagrams.** Prompt `skill/phases/phase1t_threat_model.md` asks for one `flowchart TD` with quoted
labels, ASCII only, `subgraph` boundaries, no `style/classDef/click`. **No Go-side validation**: `reports.
classifyText` marks `threat_model.md` `available` if non-blank. Both UIs share the same five-rule
`_fixMermaid` (trailing `\`, missing `]`/`}`, `" ]`, unquoted labels, unquoted `|…|` **only when both pipes
exist**). Vanilla UI: lazy `/static/mermaid.min.js` (11.17.2, embedded), `runMermaid` sets `data-done` before
rendering, runs **all nodes in one `m.run`** with errors swallowed (`.catch(()=>{})`), no `parseError`
handler, `.mermaid-src` fallback only when the script fails to load, theme toggle never re-renders.
React `Mermaid.tsx` (mermaid 11.17.2 locked) renders per component (isolated) but never resets `svg/failed`
when `chart` changes; fallback is repaired source with no error/retry. Classic/legacy render the fence as
plain code. Live corpus defects: unterminated `|` label + `.->` (lines 48–52), unclosed `["…"`, `" ]`, `%%`
inline comments, `style`/`classDef`/`class`, quoted subgraph ids, `→`/`–`/U+2011 in labels, edges inside a
"trust boundaries" subgraph.

**Coverage.** `review_units.go:337-356` — the only positive evidence: a `valid` unit with any `Read` span
intersecting the handler span ⇒ `reviewed_no_issue`. `ReviewDisposition.Evidence` is free text; no
semantics-version field on `review_units.json` or `coverage_ledger.json`. The hunt deliverable contract
(`skill/phases/phase2_shared.md:363-381`) is candidates only — no per-handler status; the `SAFE/NO-MATCH/
CROSS-CLASS` vocabulary lives in the orchestrator-only reference prompt, never emitted or parsed.
`deliverableValid` = non-empty file. Lifecycle "fixed" gates on the reliability predicate, not coverage
completeness (`lifecycle.go:186`); `internal/findings/comparison.go` already refuses "fixed" unless coverage
is complete (`unknown_incomparable`).

**Go recognizer.** `lang_go.go:85-94 isRouteMethodCall` matches on selector name only (all-caps Gin or
Title-case Chi, len ≥ 3) — `sel.X` is never inspected — so `r.URL.Query().Get("q")` becomes route `GET q`
(framework chi, `HandlerRef ""`, certainty resolved). `TestGoRecognizerNegativeControls` pins exactly 5
units; `coverageFixture` pins exactly 100 routes and uses `r.FormValue` to dodge the bug; this repo alone has
27 `r.URL.Query().Get(` sites.

**Grouping.** `normalize.Dedup` collapses only identical `RootCauseKey`/`StableIdentity` (first wins,
`DuplicateOf`/`ClusterID`); `Doc.Chains` is always empty; `reports.Report.Chains/RecallPct` are dead
pass-throughs. Human reviews (`internal/review/store.go`) are keyed by finding **stable identity**, append-
only with optimistic versioning and `EvidenceFingerprint`. Lifecycle keys: `source-v1:<stable>` →
family-normalized root-cause key → `cwefile:`. Ledger keys differ again (`membank.ledgerKey`).

**Benchmark.** `testdata/score.go` (build-ignored) matches 4 planted classes by family/blob substring +
filename hint over **all** non-duplicate findings; `ground_truth/vulnapp.json` has no file/line/CWE/language;
Python only. `tests/parity` has a transcript-driven fake provider, a golden projection (`golden/vulnapp.json`)
and a pure semantic `Compare`; `benchCmd` measures tokens/sec only; `Makefile` has no eval target.
`internal/pricing` prices only `ollama/*` (0) and reports `known=false` otherwise; `BudgetAccount.Snapshot`
gives spent/priced/unpriced.

**Application identity.** `POST /api/scans` persists nothing identity-related; the results dir is
`<basename(repo)>_VULNHUNT_RESULTS_<model>_<stamp>` (never `app_name`); `scan_meta.json` is written **once at
the end** (`engine.go:415`); registry `Register/SetName` runs at finalize; `reports.Load` sets `Slug` only
when `scan_meta.repo` exists, so `apps.index()` buckets a running dir under `Name` (basename) instead of the
completed `basename-sha1[:8]` slug.

**Verification.** `collectHuntCandidates` keeps `Location` verbatim (`extract.go` only strips markup); the
first grammar check is `exactLocation` inside `validateEvidenceBacked` — after a full session. No amendment
mechanism exists. The task text supplies only a ±15-line window; the route guard (`METHOD PATH`), function
span and file length that `Reconcile` enforces are never given; `skill/phases/phase2b_verify.md` is loaded
but never passed to the session; repair feedback is two boilerplate strings. `handleVerifyTool` ignores JSON
decode errors; wrong-typed args coerce to zero values. `SessionOutcome` has no per-call list, model or
provenance; `client.Provenance` is discarded on 2b calls; 2b prompt records share one label with no
candidate id; 2b repair nudges are recorded as `main`. `resumeCompatibility` ignores `verify_model/backend`.
Live run: 113 decision-less sessions; 45 "exact source location", 29 entry-point mismatch, 10 evidence
span, 5 repo-relative path; 17 of 27 turn-limit sessions carry other classes; 8 explicit unresolved verdicts.

**Already satisfied by 014 (record, don't re-implement):** evidence-state resolver + live evidence; prompt
records (clamped telemetry) and scan log; review units v1 with assignments and bounded follow-up; per-file
hunt status + bounded re-run; failure classes per session with dominant-class reasons; outcome block +
Completion/Review-coverage sections; artifact selection with disclosure; build identity; test isolation;
`reportFetch` 404≠5xx; `TestShippedApplicationsContract`-style embedded-asset checks.

## R1 — One authoritative report model (US1/US2)

**Decision**: add `internal/report/model.go` building a `ReportModel` **once in `finalize`** from records
(`consolidate.Doc.Assessment`, `partition()`-equivalent classification moved into consolidate, review units,
remediation groups, outcome, repro dispositions, git revision, run id) and persist it as
`report_model.json`. `RenderMarkdown`/`RenderHTML` render only from the model; the main UI and React read
`report_model.json` (via the report file endpoint) for counts, the findings index and finding details,
falling back to their current `findings.json` math only when the file is absent (pre-015 scans, labelled).
`consolidate.Build` gains `SupportedCounts` (severity over supported only, Unrated explicit) and
`CandidateCounts` (the old all-candidate totals, relabelled); `Counts` keeps its value for compatibility but
is no longer rendered as vulnerabilities. One classification function (`consolidate.Classify`) replaces the
four.
**Executive summary**: deterministic text assembled from model facts (target, revision, top ≤5 supported
findings by severity then group size, affected surfaces = distinct entry points/files of those, actions =
group fixes, limitations = outcome recovery steps + degraded reasons + disabled phases), word-counted at
render (≤300, tested). **No AI narrative in this feature**: FR-004's "if used" is satisfied by not using it;
the deterministic summary *is* the fallback, viewing/regeneration never touches a model. (Assist per-finding
remains available and separately labelled.)
**Section order**: summary+metrics → findings index → finding details → coverage & limitations →
candidate appendix (rejected, unresolved split into "explicit unresolved decision" vs "failed session") →
execution appendix (per-phase table; per-agent rows collapsed / on-demand in HTML, linked file in Markdown).
Heading hierarchy fixed (`##` sections, `###` per finding). Long failure explanations appear once (appendix);
other sections carry a one-line reference.
**Rationale**: the count divergence and buried summary are structural, not cosmetic; a persisted model makes
UI, Markdown, HTML and regeneration consistent by construction and testable by byte comparison (as 014 did
for Completion).
**Alternatives**: rendering the model only in Go and keeping UI math — rejected (the four implementations
already diverged); AI-authored summary — rejected for v1 (cost/availability/invention risk; deterministic
facts are what the spec requires).

## R2 — Report navigation, evidence rendering, links, exports (US2)

**Decision**: findings index rows = id, title, severity, affected surface (entry point or file), evidence
status (`evidence_captured | evidence_missing | not_verified`), group id, action; stable anchors
`#finding-<id>` / `#group-<id>`; HTML gets search + severity/status filters (over **all** rows, with
`data-status`), collapsed `<details>`, keyboard-focusable rows, `beforeprint` expand + filter disclosure +
page-break CSS (`break-inside: avoid` per finding, `break-before` per section), an explicit "Export scope:
summary | full" toggle recorded in the print header. Finding detail renders every `verification_record.
evidence[]` as `<pre><code>` escaped with `path:start-end` captions (Markdown: fenced code with a caption
line). Missing fix/evidence ⇒ explicit "not provided" line. **Links**: report Markdown/HTML keep relative
paths (portable exports); the in-app viewers rewrite relative `href`/`src` to
`/api/reports/{id}/file?path=<rel>` (`mdRender` gains a base option; React `Markdown` gets `urlTransform`),
validate schemes (`http(s):`, `mailto:`, relative only), and `rel="noopener"`. Model-authored Markdown is
escaped before rendering (already the case in `mdRender`; add the same guarantee test for React).
Reading position/selection: hash anchor + `sessionStorage` per report id; stale guard reuses 014's sequence
pattern. **Rationale**: the file endpoint already exists and is confined; rewriting links there keeps
exports portable and in-app navigation working without a second copy of the report.

## R3 — Diagrams as validated artifacts (US3)

**Decision**: new stdlib package `internal/threatmodel` with a **Mermaid flowchart subset parser**
(`flowchart|graph` + direction; node `id["label"]`/`id("…")`/`id{…}`/`id[…]`; edges `-->`, `-.->`, `==>`
with optional `|label|`; `subgraph id["label"] … end`; `%%` comments; rejects `style/classDef/class/click`
as unsupported directives), producing `Diagram{nodes, edges, boundaries}` with stable ids and a
**deterministic serializer** (sorted nodes/edges, canonical quoting, ASCII-safe labels). Validation runs at
1t finalize and at regeneration: `threat_model_diagram.json` = `{version, renderer_version:"11.17.2",
diagrams:[{index, state: valid|repaired|invalid|unsupported, original, normalized, repairs:[{rule, line,
before, after}], errors:[{line, code, message}], structure}]}`. **Bounded repair rules** (each recorded):
close an unclosed `["…"` when the quote is unterminated at EOL; `" ]` gap; quote unquoted labels; strip
`style/classDef/class/click` lines as *unsupported* (state `repaired` only if nothing else fails); map
`→`/`–`/U+2011 inside quoted labels to ASCII equivalents. **Never repaired**: an edge with a broken label
delimiter (`|… .->`) — the intended structure is ambiguous → `invalid` with the exact line and `E_EDGE_LABEL_
UNTERMINATED`; edges inside a subgraph are kept (valid Mermaid) but boundaries are recorded as such.
`reports.Material` gains `Diagram` sub-state; `apps.selectKind` treats `invalid` diagram as not-valid material
**for the diagram** while the narrative stays available (two selections: narrative, diagram).
**Rendering**: both UIs render **per diagram**: `mermaid.parse(src, {suppressErrors:true})` → render →
on failure show the structured fallback (narrative already on page + node/flow table from
`threat_model_diagram.json` or, absent that, from the client-side parser port) + error `{line, code}` +
Retry/View source; theme change re-renders; `data-done` replaced by per-element state that is cleared when
the host element is replaced (already true) **and** on theme change; `securityLevel: 'strict'` (labels
escaped; `click` directives are already rejected by the parser; `loose` was only needed for nothing we use);
SVG export button (serialize the rendered SVG to a data URL; download is user-initiated). Classic/legacy:
render the node/flow table + source (no Mermaid there today; adding the 3.5 MB script to them is out of
scope) — disclosed as "diagram rendering available in the main UI".
**Validation with the shipped renderer**: the Go parser is a *subset validator*; the authoritative check is
the browser-side `mermaid.parse` with the pinned 11.17.2. The regression corpus (FR-014) runs through the Go
parser in `go test` and through `mermaid.parse` in the browser test suite (R10); the Go serializer emits only
the subset both accept. `web-react/package.json` has **no** test runner (no vitest, no Playwright) today, so
the `mermaid.parse` check is part of the operator-run browser suite and is labelled `not run` until executed —
it is never counted as offline verification.
**Rationale**: a real structure lets the fallback be useful and the repairs auditable; refusing to guess the
audited edge is exactly what the spec demands. **Alternative** rejected: shipping a full Mermaid grammar in
Go (large, drifts from the renderer).

## R4 — Coverage semantics v2 (US4)

**Decision**: hunt deliverable contract v2 adds a required section `## Handler dispositions` after the
candidate list: one block per assigned handler in the unit's scope —
`- **Handler**: <file>:<line> <METHOD> <PATH>` / `- **Checks**: INJ=done|n/a(reason)|unresolved(reason),
NAV=…, LOG=…` (only the classes of THIS pass are expected `done`; others may be `n/a`/`unresolved`) /
`- **Defenses reviewed**:` / `- **Evidence**: <file>:<start>-<end>[, …]` / `- **Rationale**:` /
`- **Unresolved**:`. The harness parses it (`internal/engine/dispositions.go`), validates **scope**
(handler ∈ unit assignment), **revision** (unit ran at `rec.GitCommit`), **evidence** (every cited range
was actually `Read` by that unit — `agent.Result.Reads` — and intersects the handler span), **checks**
(applicability vocabulary), **identity** (fabricated ids rejected). A handler is `reviewed_no_issue` only
when a validated disposition exists whose checks for the planned passes are all `done` or explained `n/a`;
`unresolved` checks ⇒ `partial` with the unresolved list; reads without disposition ⇒ **source exposure**
only (new axis). `review_units.json` gains `semantics_version: 2`, `axes{discovered, supported_inventory,
assigned, attempted, source_exposed, completed_review, verified}`, `dispositions[].checks[]` structured;
v1 records (no version) are read as `semantics_version: 1` and labelled "read-overlap evidence (v1)" on
every surface; regeneration never upgrades them. Gaps route into the existing follow-up (unchanged bounds);
the follow-up unit's deliverable uses the same v2 section. `coverage_ledger.json` gains `semantics_version`
and `source_exposed` count. Lifecycle: `reconcileLifecycle` additionally requires `cl.Complete` (v2) before
emitting `fixed`/`not_observed` (mirrors `findings/comparison.go`), else `unknown_incomparable`.
**Rationale**: a conclusion the model must *state per handler* and the harness can *check against what it
read* is the smallest change that makes "no issue" mean analysis. **Alternative** rejected: inferring
completeness from full-span reads (the spec explicitly forbids it).

## R5 — Remediation groups (US5)

**Decision**: `internal/consolidate/groups.go` builds `remediation_groups.json` over **supported** findings
after `Dedup`: anchor = resolved `file` + enclosing function (via `recognize.Scope`) + sink statement text;
root cause = family-normalized `RootCauseKey`; preconditions = normalized `verification_record.preconditions`
token set; fix = normalized `fix` token set; scope = entry points. **Established** group: same family ∧ same
sink anchor (file+function+statement) ∧ compatible fix (Jaccard ≥ 0.6 on fix tokens or identical
`CanonicalName`); **suggested**: same family ∧ same file ∧ same fix but different function, or same function
with different sink statements. Distinct family, or same route with different sinks/preconditions ⇒ never
grouped. Group id = `RG-` + sha256(family + "|" + anchor of the earliest-observed member)[:16] — stable across
regeneration while the anchor exists; members carry `role: primary|occurrence`. Raw vs grouped counts in the
model. Human decisions stay per finding (existing store); the model exposes a **group decision status**
derived from members (`all-decided | mixed | undecided`) and flags `members_changed_since` when a member's
stable id was not present when the newest decision was made (using `Decision.ScanID`/`Revision`). No verdict
transfer: groups contain only supported findings; a new anchor is a new member only after its own
verification. Pre-verification: `BuildManifest` keeps every candidate; equivalence is *reported*
(`candidate_manifest.candidates[].likely_group`) so a future feature could skip work — no skipping here
(evidence rules unchanged). Fixture: the live run's repeated pickle/XSS/XXE/NoSQL candidates (sanitized
records) + negative controls.

## R6 — Efficacy benchmark (US6)

**Decision**: `testdata/benchmark/` = new seeded corpus `target/` (Python, Go, JS/TS services; each seeded
issue in one function; safe controls beside each class) and `truth/ground_truth.json` v2 **outside**
`target/` (never in prompts; the scan spec's repo is `target/`): entries `{id, language, cwe, family,
anchor{file, function, line_range}, root_cause, expected: vulnerable|safe_control, acceptable_matches:
[{file, function}|{route}], notes}`. New package `internal/benchmark`: `Score(resultsDir, truth)` →
`Results{per_language, per_family, supported{tp, fp, fn, precision, recall}, candidate_recall,
safe_control_fp, verification{accepted, recovered, terminal_by_class}, coverage{completed_review/total},
artifacts{complete/missing}, cost{tokens, seconds, usd: known|unknown}, denominators, run_variation?}`;
only `verification_status==supported ∧ duplicate_of==nil` counts; one truth id counts once (first match);
unmatched supported = FP; safe-control hits = FP flagged. `vhlocal bench efficacy --results <dir> [--truth
<file>] [--baseline <file>] [--json]` scores offline; `--live` is **not** a flag — a live run is
`vhlocal run` by the operator, then scoring. Frozen baseline `testdata/benchmark/baseline/<date>.json` =
`{config{target_revision, build, effective_config, models, prompts_hash, sampling, seeds, budgets}, results,
runs:[…], variation}`; policy `testdata/benchmark/POLICY.md` (regression = supported precision/recall or
safe-control FP worse than baseline − declared tolerance, per language/family; no absolute threshold).
`testdata/score.go` retired (kept as deprecated wrapper printing the new scorer's class recall). Offline
tests drive the transcript provider (`tests/parity/transcript`) over the corpus to prove the scorer and
pipeline; comparison with the audited baseline is emitted with a **config-diff block first**.

## R7 — Application identity at creation (US7)

**Decision**: `handleCreateScan`/CLI compute `app_slug = apps.SlugFor(repoAbs)` and persist it in the job
spec (`app_slug`, `app_name`); the engine writes an **initial** `scan_meta.json` at `scan_start`
(`RunRecord` with repo, app slug/name, model, started_at, `status: running`, `schema: partial`) — additive;
`reports.Load` derives `Slug` from `scan_meta.repo` as today, so the running dir groups under the canonical
slug immediately; `apps.index()` drops the `Name` fallback when `scan_meta` names a repo, and labels
`Name`-only legacy dirs `ambiguous_mapping` instead of guessing. `apps.Register/SetName` moves to scan
start (idempotent) and finalize keeps its call (no-op when present). Restart (`interrupted`) keeps the
initial record. Same display name, different repo ⇒ distinct slugs (already, via path hash) — add the test.
Regeneration reads the final record; partial records are never "completed" by regeneration.

## R8 — Citation validation, feedback, amendment, diagnostics (US8)

**Decision**: new package `internal/citation`: `Parse(text) (Citation, Normalization, error)` with the
strict grammar `path:start[-end]` plus **unambiguous** normalizations recorded as provenance (backticks,
trailing commentary after the range, `line N` / `lines N-M` phrasing, en-dash) — never for "function X,
lines a-b in file" (ambiguous → `E_CITATION_AMBIGUOUS`), disjoint ranges (→ separate supplementary citations
required), file-only (`E_CITATION_NO_LINE`); `Resolve(repo, revision, c)` checks confinement/symlinks,
existence, bounds (file length reported), and binds the handler (`inventory` route guard + `recognize.Scope`)
→ `Binding{route, handler_span, canonical_entry_point}`; error codes with `field`, `received`, `expected`,
`repairable`, `aids{file_length, handler, route, required_span}`.
**Ingestion**: `collectHuntCandidates` validates every extracted finding; a unit whose deliverable has
invalid citations gets **one bounded correction turn** in the same session (feedback lists per-finding
field errors; the unit rewrites the file) — counted as `attempts`, recorded as `citation_repair` in
`hunt_execution.detail[].citation{invalid, repaired, remaining}`; findings still invalid after the bound
enter the manifest as `status: invalid_citation` (visible, never verified, never dropped from totals).
Markdown adapter unchanged otherwise (older artifacts import through the same validator).
**Verification session**: task text now supplies canonical facts — resolved handler span, route guard
`METHOD PATH` (display label vs identity separated), file length, required evidence span — and a worked
example (tested fixture text in `skill/phases/phase2b_session.md`, loaded like other prompts, hashed). New
tool `amend_candidate{candidate_id, path, start_line, end_line, reason}` (bounded: one accepted amendment per
session, must resolve and bind); amendment recorded in `candidate_manifest.json` `amendments[]`; identity
rule: same resolved anchor (file + function + statement) ⇒ id kept; different anchor ⇒ new candidate
`CAND-…` with `supersedes` and the old marked `superseded` (its decisions are not inherited). `submit_
verification` feedback becomes structured (error code + aids); repeated identical submissions stop after 2
with `E_REPEATED_SUBMISSION`. `handleVerifyTool` rejects malformed JSON/wrong types explicitly (own class
`invalid_tool_args`, with field). **Records**: `verification_calls.jsonl` — one line per tool call/attempt:
`{candidate_id, session_attempt, call_seq, ts, operation, args_digest (and args for diagnostics), outcome:
ok|error, class, code, message, feedback, repaired_by_call?}`; `SessionOutcome` gains `calls`, `model`,
`provenance{backend, endpoint, requested_model, returned_model}`, `explicit_unresolved: bool`; aggregates
report occurrences vs sessions vs stop reasons with overlaps. Prompt records get `candidate_id` in `label`
and `kind: repair` for 2b nudges; `prompt_hash`, `tool_schema_hash` on every record and in `scan_meta`.
**Diagnostic capture**: `diagnostics/<candidate>.json` persists the complete failing submission(s), exact
feedback, schema/prompt hashes, source references (path/ranges/revision) — full content for the decisive
fields, previews elsewhere, `truncated_fields[]` declared; `--diagnostic-capture full` (scan option,
default `bounded`) stores full sanitized session context deduplicated by prompt hash; retention: newest N
per scan (N=200) and 5 MB per file, decisive fields never dropped. Never credentials, never hidden reasoning.
**Comparison harness**: `vhlocal verify-compare --manifest <candidate_manifest.json> --repo <path> --revision
<sha> --variant prompt=<file>|model=<name>[,backend,host]` re-runs *only* 2b over the frozen manifest into a
new results dir; records effective role config per call (provenance) and produces `comparison.json`
(decisions, missing, repair rate, evidence validity, ground-truth accuracy when a truth file is given,
cost/time, config diff). Operator-triggered only; offline tests use the fake provider to prove routing
(override reaches every call), frozen inputs, denominators, and the all-unresolved gate.
`resumeCompatibility` adds verify model/backend/host.
**Rationale**: the live run's dominant failures are inputs the model could not fix through its interface;
this makes them fixable, attributable and replayable without loosening a single evidence rule.

## R9 — Go recognizer receiver inference (US8/FR-030)

**Decision**: `isRouteMethodCall` requires a **router receiver**: `sel.X` is an identifier (or field) whose
declaration in the file resolves to `gin.Default()/gin.New()/gin.Engine`, `chi.NewRouter()/NewMux()/
chi.Router/*chi.Mux` (incl. `Group`/`Route` closure params typed `chi.Router`), `http.NewServeMux()`, or an
`echo.New()`; otherwise the call is not a route. Unknown receiver with a path-like first argument (starts
with `/`) is emitted as `Certainty: Ambiguous` (disclosed, excluded from the denominator); a non-path first
argument (`"q"`) is dropped. Tests: `url.Values.Get("q")`, `r.Header.Get`, `w.Header().Get`, `values.Get`
beside genuine Gin/Chi/ServeMux registrations; `TestGoRecognizerNegativeControls` count preserved; the
`coverage100` Go services switch back to `r.URL.Query().Get("q")` (proving the fix on the real construct).

## R10 — Tests, browser evidence, attestation

**Decision**: offline Go suite remains the gate (fixtures: 171-candidate sanitized replay from the live run
for the report model; diagram corpus; disposition fixtures incl. the 400-line read; grouping fixtures;
benchmark corpus with transcript provider; identity lifecycle; citation examples from the audit; mixed-
failure session; comparison routing). Embedded-asset contract tests extend `applications_form_test.go`
style to the report/diagram UI (`TestShippedReportContract`). **Repeatable browser tests** are added under
`web-react/tests/browser/` (Playwright spec files exercising `/` and `/app` against a built binary) with a
`make browser-test` target; they are **operator-run** (browser binaries are not vendored — installing them
needs network) and their results are recorded in the attestation table with browser/version; they are never
part of `go test` and never described as passed unless run. Attestation stays a distinct row type.

## Post-design constitution re-check

Records are additive with explicit versions (`report_model.json`, `threat_model_diagram.json`,
`remediation_groups.json`, `verification_calls.jsonl`, `diagnostics/`, `review_units.semantics_version`,
initial `scan_meta.json`); no new runtime dependency (parsers, scorer, grouping in stdlib Go; Mermaid stays
the existing embedded 11.17.2); static-only unchanged (citation resolution reads source only via the
confined `source` package; benchmark scans a fixture target); provenance strengthened (per-call 2b
provenance, prompt/schema hashes); no fallback (comparison variants are explicit operator inputs); resume
unchanged except stricter compatibility; every FR has an offline test. **PASS.**
