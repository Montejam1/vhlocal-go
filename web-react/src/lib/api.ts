import type {
  ActivityEvent,
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

  scans: () => getJSON<{ jobs: Job[]; busy: boolean }>("/api/scans"),
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
