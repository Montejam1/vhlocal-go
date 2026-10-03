# Behavior matrix vs. the Python reference (`../vhlocal`)

Feature 007. **Derived by reading the reference source, not by executing Python**
(standing constraint). Each row: the behavior, the reference, the Go implementation
after this feature, and the verdict — **match**, **documented approximation**, or
**remaining gap**. Offline Go tests (`go test ./...`) pin the Go side; the operator
confirms browser rendering and live scan quality separately (T049, T034).

## Applications & discovery (US2)

| Behavior | Reference (`apps.py`/`server.py`) | Go (`internal/apps`) | Verdict |
|---|---|---|---|
| Identity slug | `basename-sha1(resolved path)[:8]` | `membank.Slug` (same) | match |
| Registration | unconditional on scan submit | `apps.Register`/`SetName` moved out of the ledger branch | match |
| Discovery | union of registry ∪ reports ∪ ledgers − hidden | `ListSummaries` same union | match |
| Summary fields | slug,name,repo,named,scans,last_scanned,latest_*,open_findings,ledger_total,has_threat_model,has_sbom | identical keys | match |
| Detail | + scan_history[] + has_ledger; hidden still resolvable | identical | match |
| null vs 0 | open_findings/ledger_total null without a ledger | `*int` nil | match |
| forgotten app | hidden, reports kept, re-scan un-hides | same | match |

## Status truthfulness (US3)

| Behavior | Reference | Go | Verdict |
|---|---|---|---|
| Three axes distinct from queue | execution/coverage/validation vs job status | `scanStatus`/`enrichScan` add axes; queue `status` separate | match |
| Per-phase progress | from validated phase outcomes | `phase_outcomes` from phases_requested/completed + deliverable validity | match |
| Never all-complete on partial | step trackers read outcomes | React + legacy trackers read `phase_outcomes` | match |
| Dead in-flight job | forced `interrupted` on load | `jobs.load` same | match |

## Threat model / SBOM (US4)

| Behavior | Reference | Go | Verdict |
|---|---|---|---|
| SBOM produced in Phase 1t, before threat agent | yes | yes | match |
| Availability flags = file existence | yes | `has_*` + explicit `Material` state | match (Go adds explicit states) |
| Generation failure surfaced | (write error handling) | `sbom.Write` error → degraded reason (no longer discarded) | match |
| Pre-existing files discoverable without re-scan | yes | reports layer reads on disk | match |

## Verification & reproduction (US5)

| Behavior | Reference | Go | Verdict |
|---|---|---|---|
| authz/logic supported without a syntactic sink | blocks only on source FAIL / class FAIL | `validateEvidenceBacked` blocks on `SourceRefuted`, not NA | match |
| Missing decision | unresolved, fail-closed | unresolved + actionable reason (stop cause + counts) | match (Go adds counts) |
| Reproduction | per-candidate authored material or explicit deferral | bounded per-candidate loop; exhaustion → missing disposition | match |
| Candidate identity | Python-AST statement digest | line/prose-insensitive heuristic (path+line+CWE) | documented approximation |
| Function-context evidence | Python AST span | indentation/`def` scan | documented approximation |

## Reports (US6)

| Behavior | Reference | Go (`internal/report`) | Verdict |
|---|---|---|---|
| Supported-first, separated sections | yes | yes | match |
| Per-supported review detail | entry/attacker-control/preconditions/defenses/impact/rationale/evidence/repro | rendered from `verification_record` + repro manifest | match |
| No candidate-total-as-confirmed | yes | explicit statement + counts | match |
| Navigation to threat/SBOM/coverage/sweep | yes | `Nav` links when present | match |
| Deterministic (no model) | yes | yes | match |
| Reviewer usefulness judgment | — | **operator-owned** (SC-006 qualitative) | remaining gap (human review) |

## Options & limits (US7)

| Behavior | Reference | Go | Verdict |
|---|---|---|---|
| Unsupported option | rejected | `validateScanOptions` rejects unknown keys/enums | match |
| `app_name` honored | registered as the app name | `apps.SetName` | match |
| Budget cap | per-token USD accounting (paid backends) | `max_budget_usd` honored; guard active; **USD token accounting not ported** (local is free) | documented approximation |
| `max_partitions` | caps the model plan; augmentation may exceed | same; surfaced in the report | match |
| Per-role backend/host | distinct providers per role | recorded in the job spec; role models run on the main provider | remaining gap |

## Cross-cutting

| Behavior | Verdict |
|---|---|
| Existing history/reports/registry/tracking preserved | match (preservation test) |
| Prior audit protections retained | match (audit suite green) |
| Parity established by reading the reference, no Python executed | honored |
| Live detection recall / real scan quality | remaining empirical question — operator-owned (T034) |

## Remaining gaps (explicit)

1. **Reviewer-usefulness of reports** and **live detection recall** are qualitative/empirical — operator-owned, not settled by offline tests.
2. **Per-role backend/host** overrides are accepted and recorded but not executed as distinct providers.
3. **USD budget accounting** is not ported (local backends are free); the cap mechanism is wired and testable but inert without a pricing layer — matching the reference's inert-cap behavior for free backends.
4. **Candidate identity / function-context** use heuristics rather than a Python AST (line-shift-insensitive; documented since feature 006).
