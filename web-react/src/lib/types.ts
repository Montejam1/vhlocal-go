// Shapes mirror the Python engine's JSON API (vhlocal/server.py). Kept pragmatic
// — only the fields the UI reads — and tolerant (most optional) since older
// reports omit newer fields.

export type Severities = Record<string, number>;

export interface AppSummary {
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
  id: string;
  created: number;
  model: string;
  findings: number;
  severities: Severities;
  coverage_status: string;
  coverage_degraded: boolean;
  has_report: boolean;
  has_threat_model: boolean;
  has_sbom: boolean;
  recall_pct: number | null;
  chains: number;
}

export interface AppDetail extends AppSummary {
  scan_history: ScanHistoryRow[];
  has_ledger: boolean;
}

export interface ReportFile {
  path: string;
  size: number;
}
export interface ReportFiles {
  root: string;
  files: ReportFile[];
}

export interface Job {
  id: string;
  status: string;
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
