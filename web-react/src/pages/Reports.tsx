import { useEffect, useRef, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { api } from "@/lib/api";
import { usePoll } from "@/lib/usePoll";
import type { Cdx, ReportFiles, ReportModel, ReportPresentation, ReportRow } from "@/lib/types";
import { Badge, SeverityStrip } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Tabs } from "@/components/ui/tabs";
import { Markdown } from "@/components/Markdown";
import { FindingsIndex } from "@/components/FindingsIndex";
import { IssuesIndex } from "@/components/IssuesIndex";
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
                      <div className="flex items-center gap-1.5">
                        <Badge variant={r.findings ? "err" : "ok"}>{r.findings}</Badge>
                        {!!r.hypotheses && (
                          <span
                            className="text-[10.5px] text-text-3"
                            title="Hypotheses — worth investigating, not substantiated findings"
                          >
                            +{r.hypotheses} hyp
                          </span>
                        )}
                      </div>
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

// Feature 015 (FR-001/002): the executive summary and labelled counts render from
// report_model.json — the one authoritative model. A pre-015 scan has no model;
// the page says so instead of recomputing counts. A failed model fetch is an
// error (with retry), never silently "no summary".
type ModelState = { kind: "loading" } | { kind: "none" } | { kind: "error"; message: string } | { kind: "ok"; model: ReportModel };

// Feature 016 (T090, FR-002, FR-003, FR-004, FR-007): the bounded opening, the issue and
// severity totals, and the compact scope note. Every figure is read from the projection;
// nothing here is recomputed, and the candidate total appears only where it is labelled as
// candidates examined — in the full report's Scan details.
function PresentationSummary({ presentation }: { presentation: ReportPresentation }) {
  const { counts: c, scope: sc, identity: id, opening: op, priority } = presentation;
  return (
    <div className="mb-4 rounded-[var(--radius-sm,8px)] border border-line bg-surface-1 p-4" data-testid="executive-summary">
      <h3 className="text-[13px] font-semibold text-text-1">
        {id.application || "Scan report"}{" "}
        <span className="font-normal text-text-3">
          {id.scan_date ? `· scanned ${id.scan_date}${id.timezone ? ` (${id.timezone})` : ""}` : "· scan date not recorded"}
          {id.revision ? ` · revision ${id.revision.slice(0, 12)}` : ""}
        </span>
      </h3>
      <p className="mt-1 text-[13px] text-text-2">{op.risk_summary}</p>
      {op.scope_sentence ? <p className="mt-1 text-[12px] text-text-3">{op.scope_sentence}</p> : null}
      <div className="mt-3 flex flex-wrap items-center gap-2">
        <Badge variant={c.issues_to_fix ? "err" : "ok"}>{c.issues_to_fix} issue{c.issues_to_fix === 1 ? "" : "s"} to fix</Badge>
        <Badge variant="warn" title="neither confirmed nor dismissed; never counted as a vulnerability">{c.needs_review} need review</Badge>
        <Badge>{c.dismissed} dismissed</Badge>
      </div>
      <div className="mt-2 flex flex-wrap gap-x-3 gap-y-1 text-[12px] text-text-2">
        {["Critical", "High", "Medium", "Low", "Informational", "Unrated"].map((k) => (
          <span key={k}>{k}: <span className="font-mono">{c.severity[k] ?? 0}</span></span>
        ))}
      </div>
      {priority.length > 0 && (
        <ol className="mt-2 list-decimal pl-5 text-[12.5px]">
          {priority.map((a) => (
            <li key={a.ref}>
              <a className="text-accent hover:underline" href={`#${a.ref.toLowerCase()}`}>{a.issue}</a> — <b>{a.severity}</b> · {a.affected_area} · {a.action}
            </li>
          ))}
        </ol>
      )}
      <div className="mt-2 text-[12px] text-text-2">
        Review scope: execution <b>{sc.execution}</b> ·{" "}
        {sc.coverage_known ? <><b>{sc.coverage_completed}</b> of <b>{sc.coverage_total}</b> entry points completed</> : "entry-point coverage not recorded"} · method{" "}
        <b>{sc.method}</b>
      </div>
      {sc.gap_sentence ? <div className="mt-1 text-[12px] text-text-3">{sc.gap_sentence}</div> : null}
    </div>
  );
}

function ExecutiveSummary({ id, state, onRetry }: { id: string; state: ModelState; onRetry: () => void }) {
  if (state.kind === "loading") return <div className="mb-3 text-[12.5px] text-text-3">Loading report model…</div>;
  if (state.kind === "error")
    return (
      <div className="mb-3 flex items-center gap-3 rounded-md border border-err/40 bg-err-weak px-3 py-2 text-sm text-err">
        <span className="flex-1">Could not load the report model ({state.message}).</span>
        <Button variant="secondary" size="sm" onClick={onRetry}>Retry</Button>
      </div>
    );
  if (state.kind === "none")
    return <div className="mb-3 text-[12.5px] text-text-3">counts from findings.json (pre-015 scan — no report model)</div>;
  const m = state.model;
  // Feature 016 (T090, FR-002, FR-004, FR-007): when the saved report carries the
  // presentation projection the opening is the bounded one, with the issue and severity
  // totals and the compact scope note — not the limitations list, the raw status badges,
  // the candidate counts or the internal metrics the feature-015 summary showed.
  if (m.presentation) return <PresentationSummary presentation={m.presentation} />;
  const c = m.counts;
  const sev = (o: Record<string, number>, withUnrated: boolean) =>
    Object.entries(o || {}).filter(([k, v]) => v > 0 || (withUnrated && k === "Unrated")).map(([k, v]) => `${v} ${k}`).join(", ") || "none";
  return (
    <div className="mb-4 rounded-[var(--radius-sm,8px)] border border-line bg-surface-1 p-4" data-testid="executive-summary">
      <h3 className="text-[13px] font-semibold text-text-1">
        Executive summary <span className="font-normal text-text-3">· {m.summary.words} words · scan {id}</span>
      </h3>
      <p className="mt-1 text-[13px] text-text-2">{m.summary.narrative}</p>
      {m.summary.leading.length > 0 && (
        <ol className="mt-2 list-decimal pl-5 text-[12.5px]">
          {m.summary.leading.map((l) => (
            <li key={l.ref}>
              <a className="text-accent hover:underline" href={`#${l.ref}`}>{l.title}</a> — <b>{l.severity}</b> · {l.surface} · {l.action || "fix not provided"}
            </li>
          ))}
        </ol>
      )}
      {m.summary.limitations.length > 0 && (
        <ul className="mt-2 list-disc pl-5 text-[12px] text-text-3">
          {m.summary.limitations.map((l) => <li key={l}>{l}</li>)}
        </ul>
      )}
      <div className="mt-3 flex flex-wrap items-center gap-2">
        <Badge variant={c.supported ? "err" : "ok"}>{c.supported} supported</Badge>
        <Badge>{c.remediation_groups} groups</Badge>
        <Badge>{c.rejected} rejected</Badge>
        <Badge variant="warn" title={`${c.unresolved_explicit} explicit verifier decisions, ${c.unresolved_failed} failed sessions`}>
          {c.unresolved_explicit + c.unresolved_failed} unresolved
        </Badge>
        <span className="text-[12px] text-text-3">{c.total_candidates} candidates total — not a confirmed-vulnerability count</span>
      </div>
      <div className="mt-2 text-[12px] text-text-2">
        execution <b>{m.status.execution || "unknown"}</b> · coverage <b>{m.status.coverage || "unknown"}</b> · source review{" "}
        <b>{c.source_review.total ? `${c.source_review.completed}/${c.source_review.total}` : "no inventory"}</b>
        {m.coverage_semantics_label ? <span className="text-text-3"> ({m.coverage_semantics_label})</span> : null} · validation <b>{m.status.validation_mode || "unknown"}</b>
      </div>
      {c.source_review.axes && (
        <div className="mt-1 flex flex-wrap gap-x-3 gap-y-0.5 text-[11px] text-text-3" title="No axis is derived from another; a read without a validated disposition is exposure, not review.">
          {([
            ["discovered", c.source_review.axes.discovered], ["supported inventory", c.source_review.axes.supported_inventory],
            ["assigned", c.source_review.axes.assigned], ["attempted", c.source_review.axes.attempted],
            ["source exposed", c.source_review.axes.source_exposed], ["completed review", c.source_review.axes.completed_review],
            ["verified", c.source_review.axes.verified],
          ] as [string, number][]).map(([k, v]) => (
            <span key={k}>{k}: <span className="font-mono text-text-2">{v}</span></span>
          ))}
        </div>
      )}
      <div className="mt-1 text-[12px] text-text-2">Supported by severity: {sev(m.severity_supported, true)}</div>
      <div className="mt-1 text-[12px] text-text-3">Candidates by severity (all statuses — not vulnerabilities): {sev(m.severity_candidates, false)}</div>
    </div>
  );
}

function ReportDetail({ id, row, onClose }: { id: string; row?: ReportRow; onClose: () => void }) {
  const [files, setFiles] = useState<ReportFiles | null>(null);
  const [tm, setTm] = useState<string | null>(null);
  const [sbom, setSbom] = useState<Cdx | null>(null);
  const [tab, setTab] = useState("report");
  const [body, setBody] = useState<string>("");
  const [model, setModel] = useState<ModelState>({ kind: "loading" });
  const [modelAttempt, setModelAttempt] = useState(0);
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const ctl = new AbortController();
    setModel({ kind: "loading" });
    api
      .reportModel(id, ctl.signal)
      .then((m) => {
        if (ctl.signal.aborted) return;
        setModel(m ? { kind: "ok", model: m } : { kind: "none" });
      })
      .catch((e) => {
        if (ctl.signal.aborted) return;
        setModel({ kind: "error", message: String((e as Error).message || e) });
      });
    return () => ctl.abort();
  }, [id, modelAttempt]);

  useEffect(() => {
    let active = true;
    setFiles(null);
    setTm(null);
    setSbom(null);
    setTab("report");
    setBody("");
    api.reportFiles(id).then(async (f) => {
      if (!active) return;
      setFiles(f);
      const has = (n: string) => f.files.some((x) => x.path === n);
      const first = ["SCAN_REPORT.md", "README.md"].find(has);
      if (first) { const text = await api.reportText(id, first); if (!active) return; setBody(text || ""); }
      if (has("threat_model.md")) { const text = await api.reportText(id, "threat_model.md"); if (!active) return; setTm(text || ""); }
      if (has("sbom.cdx.json")) {
        const t = await api.reportText(id, "sbom.cdx.json");
        if (!active) return;
        if (t) try { setSbom(JSON.parse(t)); } catch { /* ignore */ }
      }
    }).catch(() => { if (active) setBody("Could not load report artifacts. Reopen the report to retry."); });
    ref.current?.scrollIntoView({ behavior: "smooth", block: "start" });
    return () => { active = false; };
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

      <ExecutiveSummary id={id} state={model} onRetry={() => setModelAttempt((n) => n + 1)} />

      {row && (
        <div className="mb-3 flex flex-wrap items-center gap-2">
          {row.has_report && <Badge variant={row.findings ? "err" : "ok"}>{row.findings} substantiated</Badge>}
          {!!row.hypotheses && (
            <Badge variant="warn" title="Worth investigating, not substantiated findings">
              {row.hypotheses} hypotheses
            </Badge>
          )}
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
        {files && tab === "report" && model.kind === "ok" && (model.model.presentation
          ? <IssuesIndex presentation={model.model.presentation} />
          : <FindingsIndex model={model.model} />)}
        {files && tab === "report" && (body ? (model.kind === "ok" ? <details className="mt-4"><summary className="cursor-pointer text-text-2">Full report and execution diagnostics</summary><Markdown base={api.reportFileUrl(id, "").replace(/\?path=$/, "")}>{body}</Markdown></details> : <Markdown base={api.reportFileUrl(id, "").replace(/\?path=$/, "")}>{body}</Markdown>) : <div className="text-text-3">No report body.</div>)}
        {files && tab === "threat" && tm && <Markdown base={api.reportFileUrl(id, "").replace(/\?path=$/, "")}>{tm}</Markdown>}
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
