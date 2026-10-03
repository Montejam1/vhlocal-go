# Phase 1 Data Model: Evidence-centered analyst workspace

New persistence is **additive** and lives under `~/.vhlocal/` (atomic temp+rename, mirroring
`jobs.Store.persist`); scan evidence under `~/vulnhunter-reports/<scan dir>/` is **read-only** and
never rewritten. Reused entities are cited to their existing source so the feature does not
duplicate them.

## Identity model (reused)

- **Finding occurrence id** = `<scan id>` + `<stable finding identity>`. The stable identity uses
  the existing precedence `lifecycle.Key` (`source-v1:<stable_identity>` → `root_cause_key` →
  `cwe+file`), from `consolidate.Finding.StableIdentity`/`RootCauseKey` (`finding.go:55-58`). An
  **occurrence** is scan-specific; a **finding across scans** groups occurrences by stable identity.
- **Scan id** = report directory name (`reports.go` `dirRE`); carries `git_commit` and captured
  source location from `scan_meta.json` (`record.go`).

## New entities (additive stores)

### ReviewDecisionRecord — `internal/review` (`~/.vhlocal/reviews/<stable-id>.json`)

One record per stable finding identity; an append-only history of human decisions.

| Field | Type | Rule |
|---|---|---|
| `stable_id` | string | stable finding identity (see identity model); file key |
| `evidence_fingerprint` | string | hash of the evidence the latest decision was made against; used to detect materially changed evidence (FR-021) |
| `history[]` | list | append-only; never truncated |
| `history[].version` | int | monotonically increasing; the head is current |
| `history[].disposition` | enum | `needs-review` \| `investigating` \| `accepted-risk` \| `dismissed` \| `resolved` |
| `history[].rationale` | string | **required** when disposition ∈ {`dismissed`,`accepted-risk`,`resolved`} (FR-018); optional otherwise |
| `history[].notes` | string | free text |
| `history[].scan_id` | string | the occurrence the decision was recorded against |
| `history[].revision` | string | scanned revision at decision time (where recorded) |
| `history[].operator` | string | attribution; single local operator (FR-057), e.g. `local-operator` |
| `history[].decided_at` | timestamp | server clock |

Rules: a new decision **supersedes** the previous by appending a higher `version`, never erasing
history (FR-019). Writes carry the last-seen `version` (optimistic concurrency); a stale write is
rejected with the current head so the newer decision is not silently lost (FR-021). A record is
**never** created/updated as a side effect of viewing, comparison, or a ledger operation, and
creating one never enables/recreates a ledger or cleared tracking (FR-022). This store is separate
from and never writes scan evidence or the AI verdict (FR-020, Principle I).

State transitions: any disposition → any disposition (each transition is a new versioned history
entry). No terminal lock; `resolved`/`dismissed` can be reopened via a later `needs-review`/
`investigating` entry, preserving prior entries.

### SavedView — `internal/views` (`~/.vhlocal/views/<id>.json`)

| Field | Type | Rule |
|---|---|---|
| `id` | string | stable id |
| `name` | string | operator-supplied, non-empty |
| `filters` | object | subset of the queue filters (application, scan, severity, evidence assessment, human review state, file/path, new/regressed) |
| `sort` | object | `{key, dir}` |
| `created_at`/`updated_at` | timestamp | |

Rules: named views are reusable and per-operator; applying one reproduces the same population
(FR-006). A clear/reset returns the unfiltered queue.

### AssistResult — `internal/assist` (`~/.vhlocal/assist/<stable-id>/<action>-<revision>.json`)

| Field | Type | Rule |
|---|---|---|
| `stable_id` | string | finding the request is bound to |
| `scan_id` / `revision` | string | the occurrence + scanned revision the request is bound to |
| `action` | enum | `explain-flow` \| `find-mitigations` \| `challenge` \| `draft-test` \| `propose-fix` |
| `request_id` | string | client binds this to finding+revision to prevent misattachment (FR-042) |
| `status` | enum | `running` \| `succeeded` \| `failed` \| `cancelled` |
| `provenance` | object | reused `client.Provenance` (backend, endpoint redacted, requested/returned model, tokens) captured at call time (FR-040, Principle IV) |
| `citations[]` | list | source citations, each resolvable or marked unavailable/invalid |
| `output` | string/artifact | analysis text, or a **non-executed** reviewable diff/artifact for `draft-test`/`propose-fix` (FR-043) |
| `label` | const | marks the result as generated analysis, distinct from scan evidence (FR-040) |
| `created_at`/`finished_at` | timestamp | |

Rules: results are persisted and retrievable; revisiting a finding does not resubmit (FR-042);
drafts never execute code, install deps, modify the working tree, or auto-update
severity/disposition (FR-043). Provider/destination is operator-configured; no silent fallback
(FR-041). Content (repo text, model output) is untrusted and never treated as tool-authorizing
instructions (FR-044).

## New read-side projections (computed, not stored)

### FindingQueueRow — `internal/findings`
Per-occurrence projection for the queue: occurrence id, application/slug, scan id, scanned
revision (where recorded), severity + recorded basis, evidence assessment
(supported/rejected/unresolved/unknown), reproduction state (not-requested-or-attempted /
authored-but-not-executed / deferred / attempted-inconclusive-or-failed / reproduced-with-
evidence), file/path, lifecycle status (new/recurring/regressed/unknown) where comparison exists,
and the head human review disposition from `internal/review` (defaulting to `needs-review` when no
record). Read from `findings.json` (`consolidate.Doc`) across `reports.Index`; includes
ledger-disabled scans (FR-001).

### EvidenceView — `internal/evidence`
For an occurrence: revision-bound source excerpt(s) (captured source or recorded commit) with line
numbers + highlighted locations + surrounding context where available; the finding's entry point,
attacker-controlled input, flow, dangerous operation, preconditions, reviewed guards, impact,
rationale, remediation (from the verification record where present); citation classes
(observed/model-inferred/syntactic/missing). Explicit `revision-unavailable`/`source-unavailable`
state; the working tree is never substituted (FR-012).

### ArtifactManifestEntry — extends `internal/reports`
Per expected artifact (findings report, threat model/report, SBOM, verification/reproduction
material): state ∈ not-requested / pending / available / failed / missing / unreadable / malformed
/ unknown-historical, where `available` requires validated content. Reachable from scans, reports,
application history; view/download reuse `/api/reports/{id}/file` and `/api/scans/{id}/file`.

### RunStatusView — reuses `internal/consolidate/status.go` + `internal/server/status.go`
Execution / coverage / validation axes + requested stages and recorded stage outcomes (phase
outcomes), distinct from queue/job termination; an axis may be marked unavailable. No axis derived
from another (Principle II).

### ComparisonView — reuses `internal/lifecycle` + `internal/membank`
new / recurring / regressed / fixed and recall, against an operator-selected comparable baseline;
explicit unknown/incomparable when identity, scope, or coverage cannot support the conclusion; a
finding absent in a partial scan is never auto-"fixed" (FR-024).

### AttentionQueue — `internal/attention`
Per queue: key, scope, definition, count, link (to the matching filtered findings/scans
destination), and honesty flags (unknown/unavailable rather than zero). Six queues per FR-035.
Deduplicated so one item cannot inflate a count (FR-036). Computed independently of `/api/stats`
(FR-037).

## Reused entities (unchanged; cited)

- **consolidate.Doc / Finding** (`internal/consolidate`, `consolidate.go:38`, `finding.go`) —
  scan evidence, findings[], stable identity, verification status/record. Read-only here.
- **RunStatus** (`internal/consolidate/status.go:5`) — three axes. Reused.
- **lifecycle** (`internal/lifecycle/lifecycle.go`) — new/persisting/regressed/fixed. Reused.
- **membank.Ledger/Entry/CoverageSummary** (`internal/membank/membank.go`) — cross-run status +
  recall. Reused; forget/clear semantics preserved (FR-054).
- **apps.Entry / registry** (`internal/apps`) — application identity + forget (keeps reports).
  Reused.
- **client.Provenance / Provider** (`internal/client/provider.go`) + **agent.Run**
  (`internal/agent`, `Read/Grep/Glob` only) — reused by `internal/assist`.
- **reports.Report / material** (`internal/reports`) — report index + material availability;
  extended for the fuller artifact-state set.
- **jobs.Job** (`internal/jobs`) — queue status incl. `interrupted`; reused for partial/resume
  surfacing (FR-030).

## Relationships

- A **finding across scans** groups **finding occurrences** by stable identity; a
  **ReviewDecisionRecord** attaches to that stable identity (one record, many history entries).
- An **occurrence** belongs to one **scan** (revision, artifacts, status axes) and one
  **application**.
- **AssistResult**s attach to a stable identity + occurrence (scan+revision) + action.
- **SavedView**s parameterize the finding queue; **AttentionQueue**s link into the same queue with
  fixed filters.
- **ComparisonView** relates two scans (current + operator-selected baseline).
- Human review (ReviewDecisionRecord) never modifies scan evidence, the AI verdict, the ledger, or
  application registry (Principle I; FR-020/FR-022/FR-054).
