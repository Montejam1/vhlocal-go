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
