import type {
  ActivityEvent,
  ReportModel,
  AppDetail,
  AppSummary,
  Cdx,
  ConfigResp,
  Job,
  LedgerDetail,
  LedgerSummary,
  ModelInfo,
  ReportFiles,
  ReportRow,
  SbomRow,
  Stats,
} from "./types";

// Same-origin in prod (Python serves the built app); in dev Vite proxies /api.
// Feature 014 evidence shapes. `state` is always present so the UI can explain
// unknown / not_started / running_no_files / ready / empty / unavailable /
// not_recorded / no_records / no_lines instead of showing an empty list.
export type EvidenceState = string;
export type EvidenceArtifacts = { state: EvidenceState; files: { path: string; size: number }[]; total?: number; next_offset?: number; reason?: string; error?: string };
export type PromptRecord = { seq: number; ts: string; phase: string; label: string; role: string; model: string; kind: string; system: string; task: string; truncated?: boolean; redactions?: string[]; tool_calls?: string[]; error?: string };
export type EvidencePrompts = { state: EvidenceState; records: PromptRecord[]; total?: number; next_after?: number; reason?: string; error?: string };
export type EvidenceLog = { state: EvidenceState; lines: string[]; cursor: number; total?: number; reason?: string; error?: string };
export type ReportFetch = { status: number; text: string | null; error?: string };

// getJSONSignal parses JSON for ANY status (evidence endpoints carry a state body on
// 202/404/503 too) and supports cancellation; a network failure rejects.
async function getJSONSignal<T>(path: string, signal?: AbortSignal): Promise<T & { httpStatus: number }> {
  const r = await fetch(path, { headers: { Accept: "application/json" }, signal });
  let data: unknown = {};
  try { data = await r.json(); } catch { /* non-JSON body */ }
  return Object.assign({}, data as T, { httpStatus: r.status });
}

async function getJSON<T>(path: string): Promise<T> {
  const r = await fetch(path, { headers: { Accept: "application/json" } });
  if (!r.ok) throw new Error(`${r.status} ${r.statusText} — ${path}`);
  return (await r.json()) as T;
}

async function postJSON<T>(path: string, body: unknown): Promise<T> {
  const r = await fetch(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!r.ok) throw new Error(`${r.status} ${r.statusText} — ${path}`);
  return (await r.json()) as T;
}

export const api = {
  applications: () =>
    getJSON<{ applications: AppSummary[] }>("/api/applications").then((d) => d.applications),

  application: (slug: string) =>
    getJSON<AppDetail>(`/api/applications/${encodeURIComponent(slug)}`),

  renameApplication: (slug: string, name: string) =>
    postJSON<AppSummary>(`/api/applications/${encodeURIComponent(slug)}`, { name }),

  forgetApplication: async (slug: string) => {
    const r = await fetch(`/api/applications/${encodeURIComponent(slug)}`, { method: "DELETE" });
    if (!r.ok) throw new Error(`${r.status} — forget ${slug}`);
  },

  reportFiles: (id: string) =>
    getJSON<ReportFiles>(`/api/reports/${encodeURIComponent(id)}/files`),

  reportFileUrl: (id: string, path: string) =>
    `/api/reports/${encodeURIComponent(id)}/file?path=${encodeURIComponent(path)}`,

  reportText: async (id: string, path: string): Promise<string | null> => {
    const r = await fetch(api.reportFileUrl(id, path));
    return r.ok ? r.text() : null;
  },
  // Feature 014 (FR-025): 404 (absent) stays distinct from 5xx/network (error) —
  // callers must never render a server failure as "no artifact".
  // Feature 015: the authoritative report model; null when the scan predates it
  // (404), a thrown error for any server/network failure.
  reportModel: async (id: string, signal?: AbortSignal): Promise<ReportModel | null> => {
    const r = await api.reportFetch(id, "report_model.json", signal);
    if (r.error) throw new Error(r.error);
    if (r.status === 404 || r.text == null) return null;
    return JSON.parse(r.text) as ReportModel;
  },
  reportFetch: async (id: string, path: string, signal?: AbortSignal): Promise<ReportFetch> => {
    try {
      const r = await fetch(api.reportFileUrl(id, path), { signal });
      if (r.ok) return { status: r.status, text: await r.text() };
      if (r.status === 404) return { status: 404, text: null };
      return { status: r.status, text: null, error: `HTTP ${r.status}` };
    } catch (e) {
      if ((e as Error).name === "AbortError") throw e;
      return { status: 0, text: null, error: String((e as Error).message || e) };
    }
  },

  scans: () => getJSON<{ jobs: Job[]; busy: boolean }>("/api/scans"),
  // Feature 014: scan evidence with explicit states (never a bare empty list).
  scanArtifacts: (id: string, offset = 0, limit = 200, signal?: AbortSignal) =>
    getJSONSignal<EvidenceArtifacts>(`/api/scans/${encodeURIComponent(id)}/artifacts?offset=${offset}&limit=${limit}`, signal),
  scanPrompts: (id: string, after = 0, limit = 100, signal?: AbortSignal) =>
    getJSONSignal<EvidencePrompts>(`/api/scans/${encodeURIComponent(id)}/prompts?after=${after}&limit=${limit}`, signal),
  scanLog: (id: string, tail = 500, after = 0, signal?: AbortSignal) =>
    getJSONSignal<EvidenceLog>(`/api/scans/${encodeURIComponent(id)}/log?tail=${tail}&after=${after}`, signal),
  stats: () => getJSON<Stats>("/api/stats"),
  config: () => getJSON<ConfigResp>("/api/config"),
  cancelScan: (id: string) => postJSON(`/api/scans/${encodeURIComponent(id)}/cancel`, {}),

  models: (backend: string, host?: string) => {
    const q = new URLSearchParams({ backend });
    if (host) q.set("host", host);
    return getJSON<{ models: ModelInfo[] }>(`/api/models?${q}`).then((d) => d.models);
  },
  createScan: (payload: Record<string, unknown>) => postJSON<{ id: string }>("/api/scans", payload),
  lookupApp: (repo: string) =>
    getJSON<{ slug: string; application: AppSummary | null }>(`/api/applications?repo=${encodeURIComponent(repo)}`),

  reports: () => getJSON<{ reports_dir: string; reports: ReportRow[] }>("/api/reports"),
  deleteReport: async (id: string) => {
    const r = await fetch(`/api/reports/${encodeURIComponent(id)}`, { method: "DELETE" });
    if (!r.ok) throw new Error(`${r.status} — delete ${id}`);
  },

  ledgers: () => getJSON<{ ledgers: LedgerSummary[] }>("/api/ledgers").then((d) => d.ledgers),
  ledger: (slug: string) => getJSON<LedgerDetail>(`/api/ledgers/${encodeURIComponent(slug)}`),
  clearLedger: async (slug: string) => {
    const r = await fetch(`/api/ledgers/${encodeURIComponent(slug)}`, { method: "DELETE" });
    if (!r.ok) throw new Error(`${r.status} — clear ledger ${slug}`);
  },
  removeLedgerFinding: async (slug: string, key: string) => {
    const r = await fetch(
      `/api/ledgers/${encodeURIComponent(slug)}/finding?key=${encodeURIComponent(key)}`,
      { method: "DELETE" },
    );
    if (!r.ok) throw new Error(`${r.status} — remove finding`);
  },

  activity: (opts: { limit?: number; type?: string; scan?: string } = {}) => {
    const q = new URLSearchParams();
    if (opts.limit) q.set("limit", String(opts.limit));
    if (opts.type) q.set("type", opts.type);
    if (opts.scan) q.set("scan", opts.scan);
    return getJSON<{ events: ActivityEvent[] }>(`/api/activity?${q}`).then((d) => d.events);
  },
  log: (opts: { tail?: number; scan?: string; level?: string } = {}) => {
    const q = new URLSearchParams();
    if (opts.tail) q.set("tail", String(opts.tail));
    if (opts.scan) q.set("scan", opts.scan);
    if (opts.level) q.set("level", opts.level);
    return getJSON<{ text: string }>(`/api/log?${q}`).then((d) => d.text);
  },
};

/** Flatten a CycloneDX doc into display rows (mirrors sbom.summary()). */
export function sbomRows(cdx: Cdx): { rows: SbomRow[]; byEco: Record<string, number> } {
  const rows: SbomRow[] = [];
  const byEco: Record<string, number> = {};
  for (const c of cdx.components || []) {
    const eco = c.properties?.[0]?.value || "?";
    byEco[eco] = (byEco[eco] || 0) + 1;
    rows.push({
      name: c.name || "",
      version: c.version || "",
      ecosystem: eco,
      license: c.licenses?.[0]?.license?.name || "",
      group: c.group || "",
    });
  }
  return { rows, byEco };
}
