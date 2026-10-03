// Shapes mirror the Python engine's JSON API (vhlocal/server.py). Kept pragmatic
// — only the fields the UI reads — and tolerant (most optional) since older
// reports omit newer fields.

export type Severities = Record<string, number>;

export interface AppSummary {
  ambiguous_mapping?: boolean;
  slug: string;
  name: string;
  repo: string;
  named: boolean;
  scans: number;
  last_scanned: number;
  latest_findings: number;
  latest_severities: Severities;
  latest_coverage: string;
  latest_report_id: string;
  open_findings: number | null;
  ledger_total: number | null;
  has_threat_model: boolean;
  has_sbom: boolean;
}

export interface ScanHistoryRow {
  status?: string;
  ambiguous_mapping?: boolean;
  id: string;
  created: number;
  model: string;
  findings: number;
  hypotheses?: number;
  severities: Severities;
  coverage_status: string;
  coverage_degraded: boolean;
  has_report: boolean;
  has_threat_model: boolean;
  has_sbom: boolean;
  recall_pct: number | null;
  chains: number;
  // Feature 015 (FR-019): review-unit evidence standard (1 read overlap, 2 dispositions).
  coverage_semantics?: number;
  // Feature 015 (FR-020): remediation groups recorded for the scan (absent = no record).
  groups?: number;
}

// Feature 014 (FR-025): one artifact kind's selection with disclosure.
export interface ArtifactSelection {
  scan_id?: string;
  created?: number;
  revision?: string;
  path?: string;
  valid: boolean;
  older_than_latest: boolean;
  reason?: string;
}
export interface AppArtifacts {
  threat_model: ArtifactSelection;
  sbom: ArtifactSelection;
}

export interface AppDetail extends AppSummary {
  ambiguous?: ScanHistoryRow[];
  scan_history: ScanHistoryRow[];
  has_ledger: boolean;
  // Feature 014 (FR-025/026): newest-valid artifact per kind from THIS app's history.
  artifacts?: AppArtifacts;
}

export interface ReportRow {
  id: string;
  name: string;
  repo: string;
  model: string;
  created: number;
  stamp: string;
  findings: number;
  hypotheses?: number;
  severities: Severities;
  coverage_status: string;
  coverage_degraded: boolean;
  recall_pct: number | null;
  chains: number;
  sbom_total: number;
  size: number;
  has_report: boolean;
  has_sbom: boolean;
  has_threat_model: boolean;
  slug: string;
}

export interface LedgerSummary {
  slug: string;
  target: string;
  target_name: string;
  runs_recorded: number;
  total: number;
  open: number;
  fixed: number;
  regressed: number;
  reliable: number;
  by_severity: Severities;
  updated: number;
}

export interface LedgerStamp {
  run: string;
  model: string;
  date: number;
}
export interface LedgerFinding {
  key: string;
  canonical_cwe: string;
  family: string;
  title: string;
  location: string;
  severity: string;
  first_seen: LedgerStamp;
  last_seen: LedgerStamp;
  confirmed_in: string[];
  confirmed_count: number;
  cross_family: boolean;
  status: string;
  confidence: string;
}
export interface LedgerDetail {
  slug: string;
  summary: LedgerSummary;
  findings: LedgerFinding[];
}

export interface ReportFile {
  path: string;
  size: number;
}
export interface ReportFiles {
  root: string;
  files: ReportFile[];
}

// PhaseOutcome is one requested phase's validated result (feature 007, US3).
export interface PhaseOutcome {
  phase: string;
  label: string;
  requested: boolean;
  completed: boolean;
  produced: boolean;
  reason?: string;
}

// Material is an artifact's explicit availability (feature 007, US4).
export interface Material {
  state:
    | "not_requested"
    | "available"
    | "missing"
    | "unreadable"
    | "malformed"
    | "generation_failed";
  path?: string;
}

export interface Job {
  id: string;
  status: string; // QUEUE axis — distinct from execution_status below
  phase: string | null;
  agent_label: string | null;
  agent_index: number;
  agent_total: number;
  elapsed: number;
  created_at: number;
  finished_at: number | null;
  prompt_tokens: number;
  completion_tokens: number;
  findings_count: number;
  current_model: string;
  results_dir: string | null;
  error: string | null;
  // Engine status axes + per-phase outcomes (server-enriched; absent until a run
  // has produced findings.json). Distinct from the queue `status` above.
  execution_status?: string;
  coverage_status?: string;
  validation_mode?: string;
  phase_outcomes?: PhaseOutcome[];
  review_units?: ReviewUnitsSummary;
  coverage_semantics?: number;
  remediation_groups?: { grouped: number; raw_supported: number };
  threat_model?: Material;
  sbom?: Material;
  spec: {
    repo: string;
    model: string;
    phases: string;
    threat_model?: boolean;
    verify_model?: string;
    [k: string]: unknown;
  };
}

export interface Stats {
  scans: number;
  with_usage: number;
  prompt_tokens: number;
  completion_tokens: number;
  total_tokens: number;
  avg_tokens_per_scan: number;
  findings: number;
  avg_findings_per_scan: number;
  total_seconds: number;
  avg_seconds_per_scan: number;
  by_model: Record<string, { scans: number; tokens: number; findings: number }>;
}

export interface PhaseDef {
  key: string;
  title: string;
}

export interface ConfigResp {
  phases: PhaseDef[];
  allow_roots: string[];
  // Feature 014 (SC-012): build identity of the serving binary.
  build?: { version: string; embedded_assets_hash: string; built_at: string; built_at_source: string };
  defaults: {
    model: string;
    num_ctx: number;
    ollama_host: string;
    openai_host: string;
    openrouter_host: string;
    openrouter_key_set: boolean;
  };
}

export interface ModelInfo {
  name: string;
  size?: number | null;
  family?: string | null;
}

export interface ActivityEvent {
  ts: number;
  type: string;
  message: string;
  scan?: string;
  repo?: string;
  app?: string;
  model?: string;
  findings?: number;
  report?: string;
  level?: string;
}

// CycloneDX subset we render.
export interface CdxComponent {
  name: string;
  version?: string;
  group?: string;
  properties?: { name: string; value: string }[];
  licenses?: { license: { name?: string } }[];
}
export interface Cdx {
  components?: CdxComponent[];
}
export interface SbomRow {
  name: string;
  version: string;
  ecosystem: string;
  license: string;
  group: string;
}

// Feature 015 (FR-001/002): the authoritative report model (report_model.json).
// Only the fields the UI renders; counts are never recomputed client-side.
export interface ReportModelCounts {
  supported: number;
  remediation_groups: number;
  rejected: number;
  unresolved_explicit: number;
  unresolved_failed: number;
  total_candidates: number;
  duplicates: number;
  source_review: { completed: number; exposed: number; total: number; semantics_version: number; axes?: CoverageAxes };
}
// CoverageAxes (feature 015, FR-015): independent axes of a v2 review record.
export interface CoverageAxes {
  discovered: number; supported_inventory: number; assigned: number; attempted: number;
  source_exposed: number; completed_review: number; verified: number;
}
// ReviewUnitsSummary is the scan view's copy of review_units.json (feature 014/015).
export interface ReviewUnitsSummary {
  revision?: string;
  counts?: Record<string, number>;
  follow_up_ran?: boolean;
  semantics_version?: number;
  semantics_label?: string;
  axes?: CoverageAxes;
  unreviewed?: { route_id: string; reason: string }[];
}
export interface ReportModelLeading { ref: string; title: string; severity: string; surface: string; action: string }
export interface ReportModelIndexRow {
  id: string; group_id?: string; role?: "primary" | "occurrence"; group_size?: number; title: string; severity: string; surface: string;
  evidence_status: string; action?: string; anchor: string;
}
export interface ReportModelEvidence { path: string; start: number; end: number; quote: string }
export interface ReportModelFinding {
  id: string; group_id?: string; title: string; severity: string; cwe?: string; location: string; entry_point?: string;
  impact?: string; prerequisites?: string; attacker_control?: string; source_to_sink?: string; defenses?: string; rationale?: string;
  evidence: ReportModelEvidence[]; fix?: string;
  reproduction: { kind?: string; status: string; path?: string; reason?: string };
  verification: { status: string; reason?: string; explicit_unresolved: boolean };
  classification?: string;
}
export interface ReportModelCandidate { id: string; title: string; location: string; reason: string; action?: string }
export interface ReportModelFailed { id: string; title: string; location: string; class?: string; operation?: string; code?: string; message: string }
export interface ReportModel {
  version: number;
  scan_id: string;
  target: { name: string; repo_basename: string; revision?: string; branch?: string };
  status: { execution: string; coverage: string; validation_mode: string; degraded_reasons: string[] };
  counts: ReportModelCounts;
  severity_supported: Record<string, number>;
  severity_candidates: Record<string, number>;
  summary: { words: number; leading: ReportModelLeading[]; limitations: string[]; narrative: string };
  index: ReportModelIndexRow[];
  findings: ReportModelFinding[];
  groups: { id: string; family: string; canonical_name?: string; anchor: string; status: string; size: number; members: { id: string; role: string; stable_id?: string; entry_point?: string }[]; fix?: string; decision_status: string; members_changed_since: boolean }[];
  appendix: { rejected: ReportModelCandidate[]; unresolved_explicit: ReportModelCandidate[]; unresolved_failed: ReportModelFailed[] };
  coverage_semantics_label?: string;
  /** Feature 016 reader-facing projection. Absent on a report saved before it, which
   *  renders as a legacy report with its unavailable values disclosed. */
  presentation?: ReportPresentation;
}

// --- Feature 016: the reader-facing presentation projection -------------------
// Every surface reads this. None recomputes grouping, severity, counts or remediation.

export type GuidanceProvenance = "recorded" | "general" | "investigate";
export type ReviewItemKind = "inconclusive" | "incomplete";

export interface ReportIdentity {
  application: string;
  scan_date: string;
  timezone?: string;
  revision?: string;
}

export interface OpeningProse {
  risk_summary: string;
  scope_sentence?: string;
  /** Counts risk_summary plus scope_sentence; at most 180. */
  words: number;
  trimmed?: boolean;
}

export interface ScopeNote {
  execution: string;
  coverage_completed: number;
  coverage_total: number;
  /** Shown only where labelled as exposure, never as reviewed. */
  coverage_exposed: number;
  coverage_known: boolean;
  method: string;
  gap_sentence?: string;
  entry_point_gloss: string;
}

export interface ReportCounts {
  issues_to_fix: number;
  severity: Record<string, number>;
  /** Labelled separately; never added into issues_to_fix. */
  needs_review: number;
  needs_review_inconclusive: number;
  needs_review_incomplete: number;
  dismissed: number;
  /** Secondary and explicitly labelled; not a count of vulnerabilities. */
  detections: number;
  /** Appears only where labelled as candidates examined. */
  candidates_examined: number;
}

export interface PriorityAction {
  ref: string;
  issue: string;
  severity: string;
  affected_area: string;
  action: string;
}

export interface AffectedLocation {
  file: string;
  lines?: string;
  entry_point?: string;
  revision?: string;
  /** How many detections cited this location; it never multiplies the count. */
  citation_count: number;
  available: boolean;
}

export interface RemediationRecommendation {
  provenance: GuidanceProvenance;
  steps: string[];
  missing_decision?: string;
  checks?: string[];
  label?: string;
  /** The weakness mechanism in one clause, from the reviewed guidance table. */
  mechanism?: string;
  /**
   * A recorded recommendation that does not address the observed mechanism: kept
   * visible, never presented as the fix (FR-014, C-R9).
   */
  recorded_note?: string;
}

export interface IssueMember {
  finding_id: string;
  stable_id?: string;
  role: string;
  entry_point?: string;
  severity?: string;
}

export interface PrimaryIssue {
  ref: string;
  group_id?: string;
  title: string;
  severity: string;
  /** The recorded ratings, including High+, kept for technical details. */
  original_severities?: string[];
  family?: string;
  cwe?: string;
  canonical_name?: string;
  detection_count: number;
  members: IssueMember[];
  locations: AffectedLocation[];
  entry_points?: string[];
  what_we_found: string;
  why_it_matters: string;
  /** Context that stays beside the claim rather than in a technical appendix (C-P18). */
  access_required?: string;
  attacker_control?: string;
  safeguards_reviewed?: string;
  how_to_fix_it: RemediationRecommendation;
  how_to_check_the_fix: string[];
  evidence: ReportModelEvidence[];
  grouping_note?: string;
}

export interface ReviewItem {
  ref: string;
  kind: ReviewItemKind;
  title?: string;
  location?: string;
  what_is_unresolved: string;
  next_step: string;
  /** Explicitly provisional, and never in severity totals. */
  provisional_severity?: string;
  diagnostics_ref?: string;
}

export interface DismissedRecord {
  ref: string;
  title: string;
  location?: string;
  reason: string;
  decision?: string;
}

export interface ReportPresentation {
  version: number;
  identity: ReportIdentity;
  opening: OpeningProse;
  scope: ScopeNote;
  counts: ReportCounts;
  priority: PriorityAction[];
  issues: PrimaryIssue[];
  review_items: ReviewItem[];
  dismissed: DismissedRecord[];
}
