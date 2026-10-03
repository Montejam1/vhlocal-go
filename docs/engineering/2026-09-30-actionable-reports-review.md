# Report review and implementation handoff — 2026-09-30

## Recommendation

Make the report a remediation document for application owners and developers. Lead with the issues they should address, explain the impact and location, and give useful next steps. Keep the scope of review visible in one compact note. Put scanner troubleshooting in a separate operator section.

This is a specification and source/artifact review, not an implementation or a fresh independent verification of each vulnerability. No scan, inference call, report regeneration, or target-code execution was performed. Report artifacts were read, not rewritten. Browser appearance and print output were not visually tested during this review.

Specification: [016-actionable-vulnerability-reports/spec.md](../../specs/016-actionable-vulnerability-reports/spec.md). The active `.specify/feature.json` now selects feature 016; feature 015 files were not modified.

## Evidence reviewed

Latest saved report selected from the running application's reports listing:

`/home/br0kan/vulnhunter-reports/vc-claude-code-seeded-v2-logistics-dispatch-fastapi_VULNHUNT_RESULTS_gptoss120b_2026-09-30-003935`

The job is listed as done; the assessment records execution `partial`, coverage `degraded`, and method `static_reasoning`. These are different facts, and the redesign must preserve that distinction in understandable language.

Read `SCAN_REPORT.md`, the recorded report model and findings, established remediation groups, and sample remediation records; reviewed the current Markdown, standalone HTML, and React report generation code.

| Observation | Evidence | Consequence |
| --- | --- | --- |
| Report is 181,458 characters / 2,777 lines | Saved Markdown report | Too much content appears before users can form an action plan. |
| Opening before the index is approximately 557 whitespace-delimited words | Lines 1–74 | The bounded summary alone does not bound the whole opening. |
| Initial warning says 64 findings; actual supported count is 49 | Line 3 versus summary/model counts | A raw candidate total is presented as findings before the report later qualifies it. |
| 49 supported detections, 34 established groups | Report model; group membership checked: 49 unique members, each represented once | Use 34 primary issue entries with supporting observations accessible underneath. |
| 8 rejected; 7 unresolved (1 explicit, 6 failed sessions) | Report model counts | Keep these outside primary vulnerability totals. |
| 40/100 entry points reviewed; 90 exposed to review | Source-review counts | Report 40 reviewed, not 90; retain a short scope notice. |
| 49/49 report finding fix fields are empty | Report model and sampled original finding | Useful remediation is a content requirement, not just a styling requirement. |
| “fix not provided” occurs 54 times | Five leading rows plus 49 index rows | The current priority list is not an actionable work list. |
| Separate remediation files contain generic advice | Unsafe-deserialization sample advises validating/encoding at the sink | Merely linking existing remediation files will not satisfy the requirement. |
| Detailed findings occupy lines 131–2341 | Saved Markdown headings | Repeated detections and repeated prose dominate the deliverable. |
| Model failures, missing reproduction artifacts, and CLI recovery flags appear in the executive summary | Summary limitations | Operational troubleshooting competes with actual application risk. |

The existing top list also contains two different established groups describing pickle deserialization at the same route. This is a possible grouping-quality concern, not permission to merge by title or endpoint. This feature uses established grouping conservatively; a separate assessment can revisit the grouping algorithm.

Artifact fingerprints at review time:

```text
SCAN_REPORT.md          893949a5dc13f01d6139998fe86e3b9e9eb4df0b4aea8cf5b11134ca53db1a9b
report_model.json       72cd37863f12a52b44aca0e8e87d7d25bde7d9d949b0c7e0ec58fa7069fb7d4c
remediation_groups.json 7b7ffd08ab54a6bcf5ac4b6a2e985c1aa44119543934bf904716e2f9ed8a84e8
```

Acceptance work should freeze a sanitized copy of the required records, retain their count/group relationships, and use temporary output directories. Do not hard-code tests to an operator's home directory or mutate this saved scan as part of tests.

## Reference templates and what to borrow

Qualys documents executive reporting and detailed vulnerability fields including threat, impact, solution, and instance-specific results. Borrow that progression from overview to actionable detail. Its documented total-detection calculation can include potential vulnerabilities and information; this application should keep unresolved items separate under its existing evidence rules. [Qualys: Your Scan Report](https://docs.qualys.com/en/vmdr/latest/reports/scan_reports/win_scan_report.htm)

Tenable offers an executive summary of severity and affected assets, plus separate details grouped by vulnerability or asset. Borrow the distinction between a short management summary and technical findings, substituting application components and source locations for hosts where appropriate. [Tenable: Generate Findings Reports](https://docs.tenable.com/vulnerability-management/Content/Explore/generate-findings-reports.htm)

Nessus allows reports to include selected vulnerability groups and offers report templates and print-oriented page-break options. Borrow explicit selection of report content and a deliberate sharing/printing layout. [Tenable Nessus: Create a Scan Report](https://docs.tenable.com/nessus/Content/CreateAScanReport.htm)

Do not copy vendor branding or fabricate vendor scores, CVSS values, CVEs, external exploitability, host information, or the fact of a successful exploit. These references guide the information design; the application's recorded evidence still determines its claims.

## Proposed opening — design example, not a regenerated report

The counts below are derived from the reviewed scan's existing groups. “High+” and High are combined into High for the simplified display, preserving original ratings in technical details. Group severity is the highest mapped member severity: 13 High, 19 Medium, 2 Low. This is a documented presentation mapping, not a reassessment.

---

# Application Security Report

**vc-claude-code-seeded-v2-logistics-dispatch-fastapi**  
Scan started: September 30, 2026, 12:39 AM MDT · Revision: 047e3a2471ed

| Issues to fix | High | Medium | Low | Needs review |
| ---: | ---: | ---: | ---: | ---: |
| 34 | 13 | 19 | 2 | 7 |

## Summary

The scan identified issues affecting code execution, access to data, file handling, and concurrent updates. Start with the High-severity issues listed below. Each issue includes the affected code, the access an attacker would need, and recommended changes.

**Scan:** Incomplete · **Review scope:** 40 of 100 entry points reviewed · **Method:** Source-code analysis.

An entry point is a place where the application accepts input. Review of the remaining 60 was not completed; these results cover the reviewed code. See Scan details for follow-up work.

## Priority actions

Illustrative actions from the saved findings; the implemented priority list must follow the specified deterministic ordering and eligible group membership.

| Issue | Affected area | Recommended action |
| --- | --- | --- |
| Unsafe deserialization can execute server-side code | Dispatch bundle import | Replace deserialization of untrusted pickle data with a safe, validated data format. |
| User-supplied expressions can execute code | Dispatch formula evaluation | Replace unrestricted evaluation with a parser limited to the intended operations. |
| File writes can escape the intended directory | Dispatch vault operation | Restrict resolved file destinations to the intended directory and reject escape paths. |

View all 34 issues →

---

The action examples are proposed curated guidance, not fixes recovered from the original report. They illustrate three individual issues rather than a complete or final ordered priority list. A shipped list must use one row per primary issue and preserve separate defects.

## Example issue detail

**Unsafe deserialization can execute server-side code — High**

**What we found:** The bundle-import handler passes submitted data to Python's `pickle.loads`. This format can trigger code execution while being read.

**Why it matters:** A caller who can supply the required internal token could submit a malicious bundle and run code with the application's permissions. The token requirement remains relevant; this report does not claim the endpoint is publicly accessible without it.

**Where it is:** `backend/app/dispatch_operations.py:61–62`, `POST /ops/bundle/dispatch-thaw-172`, as recorded at revision `047e3a2471ed`.

**How to fix it:** Replace pickle for externally supplied bundles with a data format that does not execute code, and validate it against the expected schema. Reject legacy pickle input. Keep the route's access checks. This is proposed general remediation guidance based on the recorded weakness, not a tested patch.

**How to check the fix:** Add tests that valid bundles still import, malformed or unsupported bundles are rejected, and callers without the required token are denied. Review the updated code to ensure incoming bundles never reach `pickle.loads`. These are suggested checks, not results of executed tests.

**Technical evidence:** Expand to see the captured source excerpt, original finding IDs, original High+ rating, and verification record. The original evidence must remain unchanged; the prose above is a design example.

## Engineering pointers

These are starting points for planning, not a prescribed implementation.

| Area | Current behavior to address |
| --- | --- |
| `internal/report/summary.go`, `buildSummary` | Combines risk prose with candidate accounting and a long limitations/recovery list. Its 300-word limit does not include the entire opening/metrics area. |
| `internal/report/model.go`, finding projection and `actionOf` | Reads `fix` directly; an empty value becomes “fix not provided.” Preserve original data while building an actionable presentation. |
| `internal/report/markdown.go` | Emits the candidate-count warning, raw metrics, per-detection index/details, and full execution appendix. |
| `internal/report/html.go` | Carries the same content model into standalone HTML; review filter, print, disclosure, and deep-link behavior. |
| `internal/report/completion.go` | Preserve independent status facts, but separate reader-facing scope from operator diagnostics. |
| `internal/remediation/remediation.go`, `guidance` | Generic fallback is not adequate across different weakness types; never equate “encode input” with eliminating unsafe deserialization. |
| `internal/consolidate/groups.go`, `internal/engine/groups.go` | Reuse established group identities; keep all original findings/evidence and be conservative with conflicting membership. |
| `web-react/src/pages/Reports.tsx` | `ExecutiveSummary` shows limitations, raw-status badges, candidate counts, and internal metrics prominently. |
| `web-react/src/components/FindingsIndex.tsx` | Current detail cards emphasize hashes, rationale, source-to-sink fields, and empty fix text. |
| `vhlocal/web/index.html` and retained classic/legacy viewers | Audit actual deployed routing and report rendering so users do not see different report generations on different URLs. |
| `internal/engine/regenerate.go`, `internal/reports`, `internal/server` | Preserve legacy loading, explicit regeneration, active-scan protections, artifact links, and review semantics. |
| `internal/report/*_test.go`, `internal/engine/report_model_test.go`, `web-react/tests/browser/reports.spec.ts` | Revise assertions that require superseded presentation, retain integrity tests, and add actual visual/print evidence. |

Implementation must not merely rename “supported” to “confirmed,” hide the incomplete scope, or move the same candidate dump under another heading. The substantive deliverable is a compact, grouped remediation document with accurate counts and useful recommendations.

## Claude handoff

Feature 016 has already been specified and the requirements checklist reviewed. To proceed directly:

```text
/speckit-plan Use specs/016-actionable-vulnerability-reports/spec.md and docs/engineering/2026-09-30-actionable-reports-review.md. Plan the report redesign across the deployed web report, retained viewers, standalone HTML, Markdown, and print output. Include useful weakness-specific remediation, established-group accounting, separate Needs review and diagnostics, historical compatibility, and offline before/after validation on copied artifacts. Preserve verification decisions and all original evidence. Do not implement yet, run a scan, invoke an inference provider, restart the server, or regenerate operator reports.
```

If Claude needs to run its own specify stage, use the following command to update this existing feature, not create another one:

```text
/speckit-specify SPECIFY_FEATURE_DIRECTORY=specs/016-actionable-vulnerability-reports

Refine the existing Actionable Vulnerability Reports specification using docs/engineering/2026-09-30-actionable-reports-review.md and the current spec.md as the complete handoff. Make the report a clear remediation document, following Qualys/Tenable's summary-to-findings structure: concise summary and useful severity numbers; prioritized issues to fix; one detail per established defect; what we found, why it matters, where it is, how to fix it, and how to check the fix. Provide useful recorded or curated weakness-specific recommendations rather than generic boilerplate. Keep uncertain items under Needs review and operator troubleshooting under Technical diagnostics. Preserve a compact, accurate scan-completion/coverage/method note, all evidence and review decisions, and dashboard metrics. Apply the same design to web, HTML, Markdown, and print. Preserve every requirement and acceptance scenario in feature 016 unless a documented inconsistency requires clarification. Stop after specification and checklist; do not implement or run a scan.
```

## Specification validation

Five prioritized stories, 27 functional requirements, nine measurable outcomes, and a 16-item requirements checklist. The checklist concerns specification quality only. Browser, print, and timed-reader acceptance remain future implementation work. No before/after screenshot or user acceptance pass is claimed here.
