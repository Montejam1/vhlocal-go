# Contract — Coverage v2, remediation groups, application identity (Workstream B, part 1)

## Coverage semantics v2 (FR-015..019)
- **C-B1**: `review_units.json.semantics_version == 2` for post-015 runs; a file without the field loads as
  version 1 and every surface that shows its counts carries the label "read-overlap evidence (v1)".
- **C-B2**: `reviewed_no_issue` ⇔ a disposition exists for the route whose `validation` is all `ok` and
  whose `checks[]` for every planned class of the covering unit(s) are `done` or `n_a(reason)`; `unresolved`
  ⇒ `partial`; no disposition ⇒ never `reviewed_no_issue`.
- **C-B3**: evidence ranges cited in a disposition must have been `Read` by that unit (from
  `agent.Result.Reads`) and intersect the handler span; otherwise `validation.evidence` is `not_read` /
  `outside_span` and the disposition is not credited (still recorded).
- **C-B4**: a disposition for a route outside the unit's assignment (`scope: out_of_scope`), at a stale
  revision (`revision: stale`), or naming an unknown route id (`identity: fabricated`) is recorded and not
  credited; a bare "reviewed everything" sentence produces no disposition.
- **C-B5**: `axes.source_exposed` counts routes whose span was read by any valid unit regardless of
  disposition; `axes.completed_review == counts.reviewed_no_issue + counts.reviewed_with_findings`;
  no axis is derived from another.
- **C-B6**: the 400-line-read fixture credits 0 completed reviews; the 100-valid-dispositions fixture credits
  100; the paired 8-dispositions fixture credits 8 with `source_exposed == 100`; regeneration of a v1 record
  yields the same v1 counts and label, never v2 credit.
- **C-B7**: gaps route into the existing follow-up (one bounded unit per partition, same limits); the
  follow-up deliverable uses the v2 section; no other retries are scheduled.
- **C-B8**: lifecycle emits `fixed`/`not_observed` only when the current ledger is complete under v2;
  otherwise `unknown_incomparable` with the reason.

## Remediation groups (FR-020)
- **C-B9**: `remediation_groups.json` contains only supported, non-duplicate findings; `raw_supported ==
  Σ members`, `grouped == len(groups)`; every finding appears in exactly one group (singletons are groups
  of one, `status: established`).
- **C-B10**: `established` requires same family ∧ same sink anchor (file+function+statement) ∧ compatible
  fix; `suggested` requires same family ∧ same file ∧ compatible fix; different family, or same route with
  different sinks or preconditions ⇒ separate groups. Group ids are stable across regeneration.
- **C-B11**: no finding, decision, evidence or review history is removed or rewritten by grouping;
  `decision_status` derives from the members' review store; `members_changed_since` is true when any member's
  stable id is absent from the scan/revision of the newest member decision.
- **C-B12**: fixtures: repeated pickle / XSS / XXE / NoSQL candidates each form one group; distinct defects
  on one endpoint remain separate; the report shows raw and grouped counts.

## Application identity (FR-024)
- **C-B13**: `POST /api/scans` and `vhlocal run` persist `app_slug` (= canonical slug of the resolved repo)
  and `app_name` in the job spec before the worker starts; the initial `scan_meta.json` (`schema: partial`)
  is written at `scan_start`.
- **C-B14**: `/api/applications/{slug}` lists the running scan under the same slug as the final report;
  restart (`interrupted`) and cancellation keep it there; no second application is created at any point.
- **C-B15**: two repositories with the same basename map to distinct slugs; a results dir with no
  `scan_meta.json` is listed as `ambiguous_mapping` (never merged, never hidden).
- **C-B16**: existing entries, names, reports, ledgers and review decisions are unchanged (preservation
  tests extended).

## As-built status (2026-09-29)

Coverage v2, grouping and application identity paths are implemented with offline regressions. Creation-time app_slug is authoritative; old reports with repo provenance derive the compatible slug. Results lacking identity get independent unmapped slugs and an explicit warning. Lifecycle tests are split across server/app_identity_test.go, jobs/app_identity_test.go and engine/app_identity_test.go; the CLI regression is run_test.go.

See `docs/engineering/2026-09-29-015-completion.md` for executed evidence and remaining operator checks. The diagnostic content-addressing and explicit output-directory requirement are disclosed implementation clarifications; no evidence-validation or efficacy acceptance rule was relaxed.
