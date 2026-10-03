# Contracts — UI behavior (React primary; legacy kept accessible)

Browser-verified behavior for the React SPA (`web-react/`, the primary design surface, served at
`/app` after an operator build) with the legacy UI (`vhlocal/web/index.html`, served at `/`) kept
accessible and unregressed. These are operator-owned acceptance checks (R1/R11); each maps to the
backend contracts and to success criteria.

## Findings workspace (US1)

- **UI-F1 (destination + entry points)**: Findings is a primary sidebar destination; a finding
  opens from an application, a scan, a report, and a dashboard queue, arriving at the same
  scan-specific occurrence with its context (application, repository, scanned revision, scan,
  selected baseline) shown persistently (FR-001/002/005). (SC-002/003)
- **UI-F2 (three-pane workspace + panes)**: queue + evidence + review/AI controls in one view;
  resizable panes with remembered sizes on wide screens; secondary panes collapse accessibly at
  narrow widths without losing the selected finding or essential actions (FR-003/004). (SC-010)
- **UI-F3 (filters + saved views)**: filters for application/scan/severity/evidence/review/path/
  new-regressed; named saved views; clear reset; filtered-empty visibly distinct from
  no-findings (FR-006/007). (SC-003)
- **UI-F4 (context preservation)**: filters, sorting, selection, and queue position survive
  navigation and browser back/forward; a stable finding link reopens the same occurrence; changing
  Table/List does not discard context; missing/deleted linked records show a useful state + route
  back (FR-008/010, FR-054). (SC-003/009)

## Evidence & decision (US2)

- **UI-E1 (revision-bound source)**: syntax-highlighted source with line numbers + highlighted
  location + surrounding context, bound to the scanned revision/captured source; a missing
  revision/source is stated and other evidence stays reachable — working tree never substituted
  (FR-011/012). (SC-004)
- **UI-E2 (four dimensions)**: severity+basis, evidence assessment, human review disposition, and
  reproduction state are each shown and explained, none derived from another, no numeric confidence;
  authorization/business-logic findings reviewable without a synthetic trace; citation classes
  distinguished; unresolved citations marked unavailable/invalid (FR-013/014/015/016/017). (SC-004)
- **UI-E3 (durable decision + history)**: save disposition + notes with rationale (required for
  dismissed/accepted-risk/resolved); decision + history survive reload and restart; a later decision
  supersedes without erasing; a stale-browser conflict is surfaced, not silently overwritten;
  recording never recreates cleared tracking (FR-018/019/020/021/022). (SC-002/005)
- **UI-E4 (comparison honesty)**: new/recurring/regressed + evidence diffs vs a selected baseline;
  absent-in-partial shown unknown/incomparable (never auto-fixed); changed evidence doesn't inherit a
  dismissal (FR-023/024). (SC-005)

## Status & artifacts (US3)

- **UI-S1 (status axes)**: each run-status surface shows execution/coverage/validation (or marks an
  axis unavailable) + requested stages/outcomes with reasons; nothing inferred from a green label
  (FR-025/026). (SC-006)
- **UI-S2 (artifact manifest)**: reachable from scans/reports/application history; each artifact
  shows the correct state; available artifacts view/download; missing optional artifacts don't hide
  others; partial/interrupted scans keep usable outputs and explain unfinished work; resume/retry is
  explicit and scoped (FR-027..FR-030). (SC-006)
- **UI-S3 (workspace states)**: initial-loading/empty/filtered-empty/refreshing/stale/disconnected/
  failed are distinguishable everywhere; a failed detail leaves loading + retry; a failed refresh
  keeps prior data with a stale marker; a late response doesn't replace the current selection; a
  failed mutation isn't shown as saved/deleted (FR-031/032). (SC-006)

## Dashboard (US4)

- **UI-D1 (preservation)**: every pre-existing metric, chart, model breakdown, and latest-scan
  action remains in prior relative order with unchanged values/semantics and 008 missing-data
  handling; average findings stays a whole number (FR-033/034). (SC-001)
- **UI-D2 (Needs attention below)**: the six queues render **below** all existing sections, each
  with scope/definition/count/link and honest unknown/unavailable; a queue-data failure leaves the
  existing dashboard fully usable; queue filters never change the existing population; new
  supported-only counts are explicitly labeled (FR-035/036/037/038). (SC-001/007)

## Contextual AI (US5)

- **UI-A1 (five actions, bound + provenanced)**: explain-flow/find-mitigations/challenge/draft-test/
  propose-fix run for the selected finding, bound to finding+revision+evidence, showing real
  provider/model provenance + citations, labeled distinct from scan evidence; provider/destination
  shown before submission; no silent fallback (FR-039/040/041). (SC-008)
- **UI-A2 (lifecycle safety)**: failures/retries/cancellation visible; revisiting doesn't resubmit;
  navigating away doesn't misattach an in-flight result; drafts are reviewable diffs that don't
  execute/patch/modify the tree or auto-change severity/disposition; unsupported actions explain the
  limitation (not a dead button) (FR-042/043/045). (SC-008)

## Navigation / interaction / accessibility (US6)

- **UI-N1 (sidebar + links)**: collapsible sidebar with Overview/Dashboard, Applications, Findings,
  Scans prominent; Reports/Activity secondary; Docs/Settings discoverable; existing links resolve or
  redirect; app/scan context maintained across views; real Settings (no empty placeholder)
  (FR-046/047). (SC-009)
- **UI-N2 (consistent dialogs)**: native confirm/prompt replaced by in-app dialogs preserving
  confirmation semantics and restoring focus (FR-049). (SC-010)
- **UI-N3 (keyboard + themes + responsive)**: main review flow operable by keyboard alone in light
  and dark themes at 1440/1024/390px and 200% zoom; visible focus, accessible names, tabs with
  proper focus movement + panels, reduced-motion respected; no page-wide overflow; source/data
  regions scroll in their own containers; Table/List choice preserved (FR-048/050/051/054). (SC-010)
- **UI-N4 (scan setup)**: user-facing labels (not implementation terms), visible presets, explicit
  rejection of unsupported settings, no invented time/cost/coverage guarantees, pre-launch review of
  effective choices incl. inference destination (FR-052). (SC-009)
- **UI-N5 (application connections)**: application details keep scan history/findings/threat/SBOM
  connected; a threat/component leads to related findings only where evidence supports it, else says
  no reliable mapping; reports stay readable/exportable from the same canonical data (FR-053).

## Legacy surface (kept accessible)

- **UI-L1**: the legacy UI at `/` keeps working — existing dashboard, applications (feature-009
  Table/List + delete/forget), ledger, reports, scans, activity, settings remain functional and
  unregressed; reports and existing links remain reachable. No full legacy redesign is required;
  new-workspace features target React (FR scope, R1/R9).
