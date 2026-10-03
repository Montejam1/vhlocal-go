# Data Model: Actionable analysis reports and measured scan efficacy

All records are additive JSON in the results directory unless noted; older records read gracefully and
are labelled by version. Names below are the persisted field names.

## ReportModel (`report_model.json`, version 1) — the single authoritative report source

```
{ version: 1, scan_id, target{name, repo_basename, revision, branch}, generated_at,
  status{execution, coverage, validation_mode, job_terminal: false},   // axes verbatim from run_status
  counts{ supported, remediation_groups, rejected, unresolved_explicit, unresolved_failed,
          total_candidates, duplicates, source_review{completed, exposed, total, semantics_version} },
  severity_supported{Critical, High+, High, Medium, Low, Informational, Unrated},   // sums to counts.supported
  severity_candidates{...},                                                          // all non-duplicate candidates
  summary{ words: int, leading[≤5]{ref, title, severity, surface, action}, limitations[], narrative },
  index[]{ id, group_id?, title, severity, surface, evidence_status: evidence_captured|evidence_missing|not_verified,
           action?, anchor },
  findings[]{ id, ..., impact, prerequisites, source_to_sink, defenses, evidence[]{path,start,end,quote},
              fix?, reproduction{kind,status,path?,reason?}, verification{status, reason, explicit_unresolved} },
  groups[]{ id, family, anchor, status: established|suggested, members[]{id, role}, fix, decision_status,
            members_changed_since: bool },
  appendix{ rejected[], unresolved_explicit[], unresolved_failed[]{id, class, operation, code, message},
            phases[], agents_ref: "scan_meta.json#agents", artifacts_ref: "artifact_manifest.json" },
  refs{ review_units, coverage_ledger, hunt_execution, sessions, reconciliation, groups, diagram } }
```
Invariants: every `counts` value derives from one classification (`consolidate.Classify`); `summary.words ≤
300`; `len(summary.leading) ≤ 5`; `severity_supported` sums to `counts.supported`; `status.job_terminal` is
never inside the model (job status lives in the queue).

## SupportedCounts / CandidateCounts (`findings.json`, additive)

`severity_supported` (supported only, Unrated explicit) and `severity_candidates` (former `counts`,
relabelled); `counts` retained unchanged for compatibility, no longer rendered as vulnerabilities.

## DiagramArtifact (`threat_model_diagram.json`, version 1)

```
{ version: 1, renderer_version: "11.17.2", source: "threat_model.md",
  diagrams[]{ index, fence_line, kind: "flowchart", direction,
              state: valid|repaired|invalid|unsupported|missing,
              original: string, normalized: string?,          // deterministic serialization when valid/repaired
              structure{ nodes[]{id, label, shape}, edges[]{from, to, style: solid|dotted|thick, label?},
                         boundaries[]{id, label, nodes[]} }?,
              repairs[]{rule, line, before, after}, errors[]{line, code, message} } }
```
Rules: `invalid` never carries `structure` as valid; `repairs` never change topology (rule ids
`R_CLOSE_LABEL_QUOTE`, `R_QUOTE_GAP`, `R_QUOTE_LABEL`, `R_STRIP_DIRECTIVE`, `R_ASCII_LABEL`); error codes
`E_EDGE_LABEL_UNTERMINATED`, `E_NODE_BRACKET`, `E_UNSUPPORTED_DIRECTIVE`, `E_SUBGRAPH_ID`, `E_SYNTAX`.
`reports.Material.Diagram{state, errors}` mirrors the first diagram's state; application artifact selection
exposes `threat_model{narrative, diagram}` selections.

## Review units v2 (`review_units.json`, `semantics_version: 2`)

```
{ semantics_version: 2, revision, axes{ discovered, supported_inventory, assigned, attempted,
  source_exposed, completed_review, verified },
  assignments[] (unchanged), units[] (unchanged + dispositions_ref),
  dispositions[]{ route_id, unit_id, revision, disposition, checks[]{class, status: done|n_a|unresolved,
                  reason?}, defenses, evidence[]{path,start,end, read_by_unit: bool}, rationale,
                  unresolved[], validation{ scope: ok|out_of_scope, revision: ok|stale, evidence: ok|not_read|
                  outside_span, identity: ok|fabricated } },
  gaps[]{route_id, reason}, follow_up_ran, counts{... + source_exposed} }
```
Disposition credit: `reviewed_no_issue` ⇔ validation all `ok` ∧ every planned class `done` or `n_a`;
any `unresolved` ⇒ `partial`; no disposition ⇒ `source_exposed` (if read) else per v1 rules for
`failed/skipped/not_reviewed`. v1 files (no `semantics_version`) load as version 1 and are labelled.
`coverage_ledger.json` gains `semantics_version` and `counts.source_exposed`.

## Hunt deliverable v2 — `## Handler dispositions` section (Markdown contract, parsed)

Per handler block: `- **Handler**: file:line METHOD PATH`, `- **Checks**: INJ=done, NAV=n/a(reason),
LOG=unresolved(reason)`, `- **Defenses reviewed**:`, `- **Evidence**: file:start-end[, …]`, `- **Rationale**:`,
`- **Unresolved**:`. Absent section ⇒ unit is v1-style (source exposure only) and flagged `no_dispositions`.

## RemediationGroup (`remediation_groups.json`, version 1)

`{ version: 1, groups[]{ id: "RG-<16hex>", family, canonical_name, anchor{file, function, statement},
status: established|suggested, members[]{finding_id, stable_id, role: primary|occurrence, entry_point},
fix, preconditions, decision_status: all-decided|mixed|undecided, members_changed_since: bool },
raw_supported, grouped }`. Group id derives from family + the earliest member's anchor; stable while that
anchor persists.

## Benchmark ground truth v2 (`testdata/benchmark/truth/ground_truth.json`)

`{ version: 2, target: "testdata/benchmark/target", entries[]{ id, language: python|go|javascript|typescript,
cwe, family, expected: vulnerable|safe_control, anchor{file, function, lines[start,end]}, root_cause,
acceptable_matches[]{file, function}|{route}, notes } }`. Never copied into the target tree or prompts.

## Benchmark results / baseline (`internal/benchmark.Results`, `testdata/benchmark/baseline/<date>.json`)

`Results{ truth_version, results_dir, per_language{}, per_family{}, supported{tp, fp, fn, precision, recall,
denominator}, candidate_recall{matched, total}, safe_control_fp[], verification{accepted, recovered,
terminal_by_class{}}, coverage{completed_review, source_exposed, total, semantics_version},
artifacts{complete, missing}, cost{prompt_tokens, completion_tokens, seconds, usd: number|"unknown"},
notes[] }`. Baseline = `{ frozen_at, config{target_revision, build{version, assets_hash}, effective_config,
models{hunt, verify, recon, reproduce}, prompts_hash, tool_schema_hash, sampling, seeds, budgets},
results, runs[]{results_dir, results}, variation{precision_range, recall_range}, policy_version }`.

## Application identity

Job spec gains `app_slug`, `app_name` at creation. Initial `scan_meta.json` at `scan_start`:
`{ schema: "partial", repo, app_slug, app_name?, model, started_at, status: running, phases_requested }`;
final record replaces it. `apps.index()` groups by `scan_meta.repo` slug; dirs without any `scan_meta.json`
are `ambiguous_mapping` entries (listed, never merged).

## Citation (`internal/citation`)

`Citation{ path, start, end, primary: bool, revision, original_text, normalization[]{rule, before, after} }`,
`Binding{ route{method, path}, handler{file, decl_line, span[start,end]}, file_length, certainty: resolved|
ambiguous|unsupported }`, `Error{ code, field, received, expected, repairable: bool, aids{file_length,
handler, route, required_span} }`. Codes: `E_CITATION_FORMAT`, `E_CITATION_NO_LINE`, `E_CITATION_AMBIGUOUS`,
`E_CITATION_DISJOINT`, `E_PATH_ESCAPE`, `E_PATH_ABSOLUTE`, `E_FILE_NOT_FOUND`, `E_RANGE_OUT_OF_BOUNDS`,
`E_REVISION_STALE`, `E_HANDLER_MISMATCH`, `E_EVIDENCE_SPAN_INCOMPLETE`, `E_REPEATED_SUBMISSION`,
`E_TOOL_ARGS_JSON`, `E_TOOL_ARGS_TYPE`.

## Candidate manifest additions (`candidate_manifest.json`, schema 2)

`candidates[]{ …, citation{ original, normalized, binding, status: valid|invalid_citation }, likely_group? }`,
`amendments[]{ candidate_id, session_attempt, original, amended, reason, revision, agent, outcome: accepted|
rejected, identity: kept|superseded_by:<id> }`, `superseded[]{ old_id, new_id }`.

## Hunt execution additions (`hunt_execution.json`)

`detail[].citation{ findings, invalid, repaired, remaining, correction_turns }`.

## Verification calls (`verification_calls.jsonl`, one line per tool call / attempt)

`{ candidate_id, session_attempt, call_seq, ts, operation, args (diagnostic subset), args_digest, outcome:
ok|error, class, code?, message, feedback?, repaired_by_call? }`. `SessionOutcome` gains `calls`, `model`,
`provenance{backend, endpoint, requested_model, returned_model}`, `explicit_unresolved`, `amended: bool`.
Aggregates: `occurrences_by_class`, `sessions_by_class`, `stop_reasons`, `overlap_note`.

## Prompt record additions (`prompts.jsonl`)

`candidate_id?`, `prompt_hash`, `tool_schema_hash`, `kind: repair` for 2b nudges; `scan_meta.prompt_hashes{
phase → hash }`, `tool_schema_hashes{}`.

## Diagnostic capture (`diagnostics/<candidate_id>.json`)

`{ candidate_id, revision, prompt_hash, tool_schema_hash, failing_submissions[]{call_seq, args (full),
feedback (full), code}, source_refs[]{path, start, end}, context: bounded|full, truncated_fields[],
size_bytes }`. Retention: newest 200 per scan, 5 MB per file; decisive fields never truncated.

## Comparison run (`comparison.json`)

`{ manifest_ref, revision, variants[]{ name, prompt_hash, model, backend, endpoint, results_dir,
decisions{supported, rejected, unresolved_explicit, missing}, repair_rate, evidence_valid_rate,
truth_accuracy?, cost, seconds }, config_diff[], not_run: bool, gate{ efficacy_improved: bool|"not_run",
reason } }`.

## Attestation record (`specs/…/quickstart.md` table rows)

`{ build{version, assets_hash, built_at}, urls[], browser: string|"unknown", scenarios[]{id, result,
notes}, kind: attested|machine_executed }`.
