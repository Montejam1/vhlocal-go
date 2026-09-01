import { useEffect, useRef, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { api } from "@/lib/api";
import { usePoll } from "@/lib/usePoll";
import type { Cdx, ReportFiles, ReportRow } from "@/lib/types";
import { Badge, SeverityStrip } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Tabs } from "@/components/ui/tabs";
import { Markdown } from "@/components/Markdown";
import { SbomTable } from "@/components/SbomTable";
import { cn, fmtDateTime } from "@/lib/utils";

export function Reports() {
  const { data, refresh } = usePoll(() => api.reports(), 0);
  const [sel, setSel] = useState<Set<string>>(new Set());
  const [open, setOpen] = useState<string | null>(null);
  const [params] = useSearchParams();

  // Deep link from Apps/Ledger: /reports?open=<id>
  useEffect(() => {
    const id = params.get("open");
    if (id) setOpen(id);
  }, [params]);

  const reports = data?.reports || [];
  const toggle = (id: string) =>
    setSel((s) => {
      const n = new Set(s);
      n.has(id) ? n.delete(id) : n.add(id);
      return n;
    });
  const allSel = reports.length > 0 && reports.every((r) => sel.has(r.id));

  const deleteSelected = async () => {
    if (!sel.size) return;
    if (!confirm(`Delete ${sel.size} report${sel.size === 1 ? "" : "s"} and all their artifacts?\n\nThis cannot be undone.`))
      return;
    for (const id of sel) {
      try {
        await api.deleteReport(id);
      } catch {
        /* keep going */
      }
    }
    setSel(new Set());
    if (open && sel.has(open)) setOpen(null);
    refresh();
  };

  return (
    <div>
      <div className="flex items-center gap-3">
        <h1 className="text-xl font-semibold text-text-1">Reports</h1>
        <span className="flex-1" />
        <Button variant="secondary" size="sm" onClick={refresh}>
          Refresh
        </Button>
      </div>

      <div className="mt-3 mb-2 flex min-h-[30px] items-center gap-2.5 text-[12.5px] text-text-3">
        <span className={sel.size ? "text-text-1" : ""}>{sel.size} selected</span>
        <Button variant="secondary" size="sm" disabled={!sel.size} onClick={() => setSel(new Set())}>
          Clear
        </Button>
        <Button variant="danger" size="sm" disabled={!sel.size} onClick={deleteSelected}>
          Delete selected{sel.size ? ` (${sel.size})` : ""}
        </Button>
      </div>

      {!data && <div className="py-10 text-center text-text-3">Loading…</div>}
      {data && reports.length === 0 && (
        <div className="py-10 text-center text-text-3">No reports yet. Run a scan and they appear here.</div>
      )}

      {reports.length > 0 && (
        <div className="overflow-x-auto rounded-[var(--radius-sm,8px)] border border-line">
          <table className="w-full text-[12.5px]">
            <thead>
              <tr className="bg-surface-2 text-text-2">
                <th className="w-9 px-3 py-2 text-center">
                  <input
                    type="checkbox"
                    checked={allSel}
                    onChange={(e) => setSel(e.target.checked ? new Set(reports.map((r) => r.id)) : new Set())}
                  />
                </th>
                {["Repository", "Findings", "Severity", "Coverage", "Model", "When", "Size"].map((h) => (
                  <th key={h} className="whitespace-nowrap px-3 py-2 text-left font-semibold">
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {reports.map((r) => (
                <tr
                  key={r.id}
                  className={cn(
                    "cursor-pointer border-t border-line hover:bg-accent-weak",
                    open === r.id && "bg-accent-weak",
                  )}
                  onClick={() => setOpen(r.id)}
                >
                  <td className="px-3 py-2 text-center" onClick={(e) => e.stopPropagation()}>
                    <input type="checkbox" checked={sel.has(r.id)} onChange={() => toggle(r.id)} />
                  </td>
                  <td className="px-3 py-2">
                    <div className="font-medium text-text-1">{r.repo || r.name}</div>
                    <div className="font-mono text-[10.5px] text-text-3">{r.id}</div>
                  </td>
                  <td className="px-3 py-2">
                    {r.has_report ? (
                      <Badge variant={r.findings ? "err" : "ok"}>{r.findings}</Badge>
                    ) : (
                      <Badge variant="warn">incomplete</Badge>
                    )}
                  </td>
                  <td className="px-3 py-2"><SeverityStrip severities={r.severities} /></td>
                  <td className="px-3 py-2">
                    {r.coverage_status ? (
                      r.coverage_degraded ? <Badge variant="warn">degraded</Badge> : <Badge variant="ok">clean</Badge>
                    ) : (
                      "—"
                    )}
                  </td>
                  <td className="whitespace-nowrap px-3 py-2 font-mono text-text-2">{r.model || "—"}</td>
                  <td className="whitespace-nowrap px-3 py-2 font-mono text-text-3">{fmtDateTime(r.created)}</td>
                  <td className="whitespace-nowrap px-3 py-2 font-mono text-text-3">{(r.size / 1024).toFixed(0)} KB</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {open && <ReportDetail id={open} row={reports.find((r) => r.id === open)} onClose={() => setOpen(null)} />}
    </div>
  );
}

function ReportDetail({ id, row, onClose }: { id: string; row?: ReportRow; onClose: () => void }) {
  const [files, setFiles] = useState<ReportFiles | null>(null);
  const [tm, setTm] = useState<string | null>(null);
  const [sbom, setSbom] = useState<Cdx | null>(null);
  const [tab, setTab] = useState("report");
  const [body, setBody] = useState<string>("");
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    setFiles(null);
    setTm(null);
    setSbom(null);
    setTab("report");
    setBody("");
    api.reportFiles(id).then(async (f) => {
      setFiles(f);
      const has = (n: string) => f.files.some((x) => x.path === n);
      const first = ["SCAN_REPORT.md", "README.md"].find(has);
      if (first) setBody((await api.reportText(id, first)) || "");
      if (has("threat_model.md")) setTm((await api.reportText(id, "threat_model.md")) || "");
      if (has("sbom.cdx.json")) {
        const t = await api.reportText(id, "sbom.cdx.json");
        if (t) try { setSbom(JSON.parse(t)); } catch { /* ignore */ }
      }
    });
    ref.current?.scrollIntoView({ behavior: "smooth", block: "start" });
  }, [id]);

  const fileUrl = (n: string) => api.reportFileUrl(id, n);
  const has = (n: string) => !!files?.files.some((x) => x.path === n);

  const tabs = [
    { key: "report", label: "Report" },
    ...(tm ? [{ key: "threat", label: "Threat model" }] : []),
    ...(sbom ? [{ key: "sbom", label: `SBOM${sbom.components ? ` · ${sbom.components.length}` : ""}` }] : []),
    { key: "artifacts", label: "Artifacts" },
  ];

  return (
    <div ref={ref} className="mt-6 border-t border-line pt-5">
      <div className="mb-2 flex items-center gap-2">
        <h2 className="font-mono text-[13px] text-text-1">{id}</h2>
        <span className="flex-1" />
        <Button variant="ghost" size="sm" onClick={onClose}>
          ✕ close
        </Button>
      </div>

      {row && (
        <div className="mb-3 flex flex-wrap items-center gap-2">
          {row.has_report && <Badge variant={row.findings ? "err" : "ok"}>{row.findings} findings</Badge>}
          <SeverityStrip severities={row.severities} />
          {row.coverage_status &&
            (row.coverage_degraded ? <Badge variant="warn">coverage degraded</Badge> : <Badge variant="ok">clean run</Badge>)}
          {row.chains > 0 && <Badge variant="accent">⛓ {row.chains} chains</Badge>}
        </div>
      )}

      <div className="mb-3 flex flex-wrap gap-2">
        {has("SCAN_REPORT.html") && (
          <a href={fileUrl("SCAN_REPORT.html")} target="_blank" rel="noopener">
            <Button variant="secondary" size="sm">Open full report ↗</Button>
          </a>
        )}
        {has("findings.sarif") && (
          <a href={fileUrl("findings.sarif")} download>
            <Button variant="secondary" size="sm">SARIF ↓</Button>
          </a>
        )}
        {has("findings.json") && (
          <a href={fileUrl("findings.json")} download>
            <Button variant="secondary" size="sm">findings.json ↓</Button>
          </a>
        )}
      </div>

      <Tabs value={tab} onChange={setTab} tabs={tabs} />
      <div className="mt-4">
        {!files && <div className="py-6 text-center text-text-3">Loading…</div>}
        {files && tab === "report" && (body ? <Markdown>{body}</Markdown> : <div className="text-text-3">No report body.</div>)}
        {files && tab === "threat" && tm && <Markdown>{tm}</Markdown>}
        {files && tab === "sbom" && sbom && <SbomTable cdx={sbom} id={id} />}
        {files && tab === "artifacts" && (
          <div className="overflow-x-auto rounded-[var(--radius-sm,8px)] border border-line">
            <table className="w-full text-[12.5px]">
              <thead>
                <tr className="bg-surface-2 text-text-2">
                  <th className="px-3 py-2 text-left font-semibold">File</th>
                  <th className="w-24 px-3 py-2 text-left font-semibold">Size</th>
                </tr>
              </thead>
              <tbody>
                {files.files.map((f) => (
                  <tr key={f.path} className="border-t border-line">
                    <td className="px-3 py-2">
                      <a className="text-accent hover:underline" href={fileUrl(f.path)} target="_blank" rel="noopener">
                        {f.path}
                      </a>
                    </td>
                    <td className="px-3 py-2 font-mono text-text-3">{(f.size / 1024).toFixed(1)} KB</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
