import type { AppDetail, AppSummary, Cdx, Job, PhaseDef, ReportFiles, SbomRow, Stats } from "./types";

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
  config: () => getJSON<{ phases: PhaseDef[] }>("/api/config"),
  cancelScan: (id: string) => postJSON(`/api/scans/${encodeURIComponent(id)}/cancel`, {}),
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
