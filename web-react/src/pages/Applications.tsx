import { useEffect, useRef, useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { api } from "@/lib/api";
import type { AppDetail, AppSummary, ArtifactSelection, Cdx } from "@/lib/types";
import { Card, CardTitle, CardMeta } from "@/components/ui/card";
import { Badge, SeverityStrip } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Tabs } from "@/components/ui/tabs";
import { Markdown } from "@/components/Markdown";
import { SbomTable } from "@/components/SbomTable";
import { cn, fmtDate, fmtDateTime } from "@/lib/utils";

// Feature 014 (FR-024; contracts/evidence-api.md "Bounds"): at most this many rows
// render per page; "Show more" extends by another page.
const APPS_PAGE = 100;

export function Applications() {
  const [apps, setApps] = useState<AppSummary[] | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [shown, setShown] = useState(APPS_PAGE);
  // The selection lives in the URL (`/app/apps?app=<slug>`) so it is a shareable
  // deep link and Back restores the list (FR-024).
  const [params, setParams] = useSearchParams();
  const active = params.get("app");
  const setActive = (slug: string | null) => {
    const next = new URLSearchParams(params);
    if (slug) next.set("app", slug);
    else next.delete("app");
    setParams(next);
  };

  const load = () =>
    api
      .applications()
      .then((a) => {
        setErr(null);
        setApps(a);
        if (!params.get("app") && a[0]) setActive(a[0].slug);
      })
      .catch((e) => setErr(String(e.message || e)));

  useEffect(() => {
    load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return (
    <div>
      <div className="flex items-center gap-3">
        <h1 className="text-xl font-semibold text-text-1">Applications</h1>
        <span className="flex-1" />
        <Button variant="secondary" size="sm" onClick={load}>
          Refresh
        </Button>
      </div>
      <p className="mt-1 mb-4 text-[13px] text-text-2">
        One hub per analyzed application — its scan history, vulnerability ledger, threat
        model and SBOM together.
      </p>

      {err && (
        <div className="flex items-center gap-3 rounded-md border border-err/40 bg-err-weak px-3 py-2 text-sm text-err">
          <span className="flex-1">{err}</span>
          <Button variant="secondary" size="sm" onClick={load}>Retry</Button>
        </div>
      )}
      {!apps && !err && <div className="py-10 text-center text-text-3">Loading…</div>}
      {apps && apps.length === 0 && (
        <div className="py-10 text-center text-text-3">
          No applications yet. Run a scan and name the application.
        </div>
      )}

      {apps && apps.length > 0 && (
        <>
          <div className="flex flex-col gap-2">
            {apps.slice(0, shown).map((a) => (
              <AppCard
                key={a.slug}
                app={a}
                active={a.slug === active}
                onOpen={() => setActive(a.slug)}
                onDelete={async () => {
                  if (!confirm(`Delete application “${a.name}”?\n\nIts name and ledger are removed and it leaves this list; its ${a.scans} scan report(s) are KEPT. Re-scanning brings it back.`)) return;
                  try {
                    await api.forgetApplication(a.slug);
                    if (active === a.slug) setActive(null);
                    load();
                  } catch (e) {
                    setErr(String((e as Error).message || e));
                  }
                }}
              />
            ))}
          </div>
          {apps.length > shown && (
            <div className="mt-3 flex items-center gap-3 text-[12.5px] text-text-2">
              Showing {shown} of {apps.length} applications.
              <Button variant="secondary" size="sm" onClick={() => setShown((n) => n + APPS_PAGE)}>
                Show {Math.min(APPS_PAGE, apps.length - shown)} more
              </Button>
            </div>
          )}
          {active && (
            <AppDetailView
              slug={active}
              onRenamed={load}
              onForgotten={() => {
                setActive(null);
                load();
              }}
            />
          )}
        </>
      )}
    </div>
  );
}

function AppCard({ app, active, onOpen, onDelete }: { app: AppSummary; active: boolean; onOpen: () => void; onDelete: () => void }) {
  return (
    <Card
      onClick={onOpen}
      // Keyboard parity (FR-024): the card is a focusable button; Enter/Space open it.
      tabIndex={0}
      role="button"
      aria-pressed={active}
      onKeyDown={(e) => {
        if (e.key === "Enter" || e.key === " ") {
          e.preventDefault();
          onOpen();
        }
      }}
      className={cn("relative cursor-pointer hover:border-line-strong", active && "border-accent ring-1 ring-accent")}
    >
      <button
        className="absolute right-2 top-2 rounded border border-line px-2 py-0.5 text-[11px] text-err hover:border-err hover:bg-err-weak"
        title="Delete application"
        onClick={(e) => {
          e.stopPropagation();
          onDelete();
        }}
      >
        Delete
      </button>
      <CardTitle>{app.name}</CardTitle>
      <div className="mt-0.5 truncate font-mono text-[11px] text-text-3" title={app.repo}>
        {app.repo}
      </div>
      <CardMeta>
        <Badge>{app.scans} scan{app.scans === 1 ? "" : "s"}</Badge>
        <span>{fmtDate(app.last_scanned)}</span>
      </CardMeta>
      <CardMeta>
        {app.open_findings != null && <Badge variant="err">{app.open_findings} open</Badge>}
        {app.has_threat_model && <Badge variant="ok">Threat model</Badge>}
        {app.has_sbom && <Badge>SBOM</Badge>}
        {!app.named && <Badge variant="warn">unnamed</Badge>}
      </CardMeta>
    </Card>
  );
}

function AppDetailView({
  slug,
  onRenamed,
  onForgotten,
}: {
  slug: string;
  onRenamed: () => void;
  onForgotten: () => void;
}) {
  const navigate = useNavigate();
  const [detail, setDetail] = useState<AppDetail | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [tab, setTab] = useState<"history" | "threat" | "sbom">("history");
  const pane = useRef<HTMLDivElement>(null);
  // Stale guard (FR-025): a response for a slug the operator already left is
  // dropped rather than painted over the current selection.
  const seq = useRef(0);

  const fetchDetail = () => {
    const my = ++seq.current;
    setDetail(null);
    setErr(null);
    api
      .application(slug)
      .then((d) => {
        if (my !== seq.current) return;
        setDetail(d);
        pane.current?.scrollIntoView({ block: "start", behavior: "smooth" });
      })
      .catch((e) => {
        if (my !== seq.current) return;
        setErr(String((e as Error).message || e));
      });
  };

  useEffect(() => {
    setTab("history");
    fetchDetail();
    return () => {
      seq.current++; // any in-flight response for the previous slug is now stale
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [slug]);

  if (err)
    return (
      <div ref={pane} className="mt-6 flex items-center gap-3 rounded-md border border-err/40 bg-err-weak px-3 py-2 text-sm text-err">
        <span className="flex-1">Could not load application: {err}</span>
        <Button variant="secondary" size="sm" onClick={fetchDetail}>Retry</Button>
      </div>
    );
  if (!detail) return <div ref={pane} className="mt-6 py-8 text-center text-text-3">Loading…</div>;

  const rename = async () => {
    const name = prompt("Application name:", detail.name);
    if (!name?.trim()) return;
    await api.renameApplication(slug, name.trim());
    fetchDetail();
    onRenamed();
  };

  const forget = async () => {
    if (
      !confirm(
        `Forget application “${detail.name}”?\n\n` +
          `• its name and vulnerability ledger are removed\n` +
          `• it disappears from the Apps list\n` +
          `• its ${detail.scans} scan report(s) are KEPT (still in the Reports tab)\n\n` +
          `Re-scanning the folder brings the application back.`,
      )
    )
      return;
    try {
      await api.forgetApplication(slug);
      onForgotten();
    } catch (e) {
      alert(String((e as Error).message || e));
    }
  };

  return (
    <div ref={pane} className="mt-6 border-t border-line pt-5">
      <div className="flex flex-wrap items-end gap-4">
        <div>
          <h2 className="flex items-center gap-2 text-lg font-semibold text-text-1">
            {detail.name}
            <button className="rounded px-1.5 text-text-3 hover:bg-accent-weak hover:text-accent" title="Rename" onClick={rename}>
              ✎
            </button>
          </h2>
          <div className="break-all font-mono text-[11px] text-text-3">{detail.repo}</div>
        </div>
        <span className="flex-1" />
        <Stats
          items={[
            ["scans", detail.scans],
            ["open", detail.open_findings ?? "—"],
            ["latest", detail.latest_findings],
          ]}
        />
      </div>

      <div className="mt-4 flex flex-wrap gap-2">
        {detail.ambiguous_mapping && <p role="status" className="w-full text-text-2">Application mapping unknown: these legacy results have no repository identity and have been kept separate.</p>}
        {detail.latest_report_id && (
          <Button variant="secondary" size="sm" onClick={() => navigate(`/reports?open=${detail.latest_report_id}`)}>
            Open latest report
          </Button>
        )}
        {detail.has_ledger && (
          <Button variant="secondary" size="sm" onClick={() => navigate(`/ledger?slug=${encodeURIComponent(slug)}`)}>
            Vulnerability ledger
          </Button>
        )}
        <span className="flex-1" />
        <Button variant="danger" size="sm" onClick={forget}>
          Forget application
        </Button>
      </div>

      <Tabs
        className="mt-4"
        value={tab}
        onChange={(t) => setTab(t as typeof tab)}
        tabs={[
          { key: "history", label: "History" },
          { key: "threat", label: "Threat model" },
          { key: "sbom", label: "SBOM" },
        ]}
      />
      <div className="mt-4">
        {tab === "history" && <History detail={detail} />}
        {tab === "threat" && <IntelTab slug={slug} detail={detail} kind="threat" />}
        {tab === "sbom" && <IntelTab slug={slug} detail={detail} kind="sbom" />}
      </div>
    </div>
  );
}

function Stats({ items }: { items: [string, number | string][] }) {
  return (
    <div className="flex gap-5">
      {items.map(([label, val]) => (
        <div key={label} className="flex flex-col items-center">
          <b className="text-xl font-bold leading-none text-text-1">{val}</b>
          <span className="text-[10px] uppercase tracking-wide text-text-3">{label}</span>
        </div>
      ))}
    </div>
  );
}

function History({ detail }: { detail: AppDetail }) {
  const navigate = useNavigate();
  const rows = detail.scan_history || [];
  return (
    <div className="overflow-x-auto rounded-[var(--radius-sm,8px)] border border-line">
      <table className="w-full text-[12.5px]">
        <thead>
          <tr className="bg-surface-2 text-text-2">
            {["When", "Model", "Findings", "Severity", "Coverage", "TM"].map((h) => (
              <th key={h} className="whitespace-nowrap px-3 py-2 text-left font-semibold">
                {h}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.length === 0 && (
            <tr>
              <td colSpan={6} className="py-6 text-center text-text-3">
                No scans yet.
              </td>
            </tr>
          )}
          {rows.map((s) => (
            <tr key={s.id} className="cursor-pointer border-t border-line hover:bg-accent-weak"
                onClick={() => navigate(`/reports?open=${s.id}`)}>
              <td className="whitespace-nowrap px-3 py-2 font-mono text-text-2">{fmtDateTime(s.created)} {s.status && <Badge variant={s.status === "done" ? "ok" : "warn"}>{s.status}</Badge>}{s.ambiguous_mapping && <span> · mapping unknown</span>}</td>
              <td className="whitespace-nowrap px-3 py-2 font-mono text-text-2">{s.model || "—"}</td>
              <td className="px-3 py-2">
                <div className="flex items-center gap-1.5">
                  <Badge variant={s.findings ? "err" : "ok"}>{s.findings}</Badge>
                  {!!s.groups && (
                    <span className="text-[10.5px] text-text-3" title="Remediation groups — one actionable fix per group">
                      {s.groups} group{s.groups === 1 ? "" : "s"}
                    </span>
                  )}
                  {!!s.hypotheses && (
                    <span className="text-[10.5px] text-text-3"
                          title="Hypotheses — worth investigating, not substantiated findings">
                      +{s.hypotheses} hyp
                    </span>
                  )}
                </div>
              </td>
              <td className="px-3 py-2"><SeverityStrip severities={s.severities} /></td>
              <td className="px-3 py-2">
                {s.coverage_status ? (
                  s.coverage_degraded ? <Badge variant="warn">degraded</Badge> : <Badge variant="ok">clean</Badge>
                ) : "—"}
                {s.coverage_semantics ? (
                  <span className="ml-1 text-[10.5px] text-text-3"
                        title={s.coverage_semantics >= 2 ? "validated handler dispositions (v2)" : "read-overlap evidence (v1)"}>
                    v{s.coverage_semantics}
                  </span>
                ) : null}
              </td>
              <td className="px-3 py-2 text-text-2">{s.has_threat_model ? "✓" : ""}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

// Selection header (FR-025): originating scan, time and revision, with an explicit
// disclosure when the material is older than the latest scan.
function SelectionNote({ sel, label }: { sel: ArtifactSelection; label: string }) {
  return (
    <div className="mb-3 flex flex-wrap items-center gap-2 text-[12px] text-text-2">
      <span>
        From scan <span className="font-mono">{sel.scan_id}</span>
        {sel.created ? ` · ${fmtDateTime(sel.created)}` : ""}
        {sel.revision ? <> · revision <span className="font-mono">{sel.revision}</span></> : null}
      </span>
      {sel.older_than_latest && (
        <Badge variant="warn" title={`The latest scan produced no valid ${label.toLowerCase()}`}>
          older than the latest scan
        </Badge>
      )}
    </div>
  );
}

type IntelState =
  | { kind: "loading" }
  | { kind: "absent"; reason: string }
  | { kind: "error"; message: string }
  | { kind: "malformed"; scanId: string }
  | { kind: "text"; text: string }
  | { kind: "cdx"; cdx: Cdx };

function IntelTab({ slug, detail, kind }: { slug: string; detail: AppDetail; kind: "threat" | "sbom" }) {
  const label = kind === "threat" ? "Threat model" : "SBOM";
  const file = kind === "threat" ? "threat_model.md" : "sbom.cdx.json";
  // Server-side selection (feature 014) — the newest VALID artifact from THIS
  // application's own history; pre-014 servers fall back to the has_* flags.
  const sel: ArtifactSelection | null = detail.artifacts
    ? detail.artifacts[kind === "threat" ? "threat_model" : "sbom"]
    : null;
  const fallbackScan = (detail.scan_history || []).find((s) => (kind === "threat" ? s.has_threat_model : s.has_sbom));
  const scanId = sel ? (sel.valid ? sel.scan_id ?? null : null) : fallbackScan?.id ?? null;
  const [state, setState] = useState<IntelState>({ kind: "loading" });
  const [attempt, setAttempt] = useState(0);

  useEffect(() => {
    if (sel && !sel.valid) {
      setState({ kind: "absent", reason: sel.reason || `no valid ${label.toLowerCase()}` });
      return;
    }
    if (!scanId) {
      setState({ kind: "absent", reason: `no ${label.toLowerCase()} in this application's history` });
      return;
    }
    const ctl = new AbortController();
    setState({ kind: "loading" });
    api
      .reportFetch(scanId, file, ctl.signal)
      .then((r) => {
        if (ctl.signal.aborted) return;
        if (r.error) return setState({ kind: "error", message: r.error }); // never "absent"
        if (r.status === 404 || r.text == null) return setState({ kind: "absent", reason: `${file} is absent from scan ${scanId}` });
        if (kind === "threat") return setState({ kind: "text", text: r.text });
        try {
          setState({ kind: "cdx", cdx: JSON.parse(r.text) as Cdx });
        } catch {
          setState({ kind: "malformed", scanId });
        }
      })
      .catch((e) => {
        if (ctl.signal.aborted) return;
        setState({ kind: "error", message: String((e as Error).message || e) });
      });
    return () => ctl.abort(); // slug/tab switch: drop the in-flight response
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [slug, kind, scanId, attempt]);

  if (state.kind === "loading") return <div className="py-6 text-center text-text-3">Loading…</div>;
  if (state.kind === "error")
    return (
      <div className="flex items-center gap-3 rounded-md border border-err/40 bg-err-weak px-3 py-2 text-sm text-err">
        <span className="flex-1">Could not load the {label.toLowerCase()} ({state.message}).</span>
        <Button variant="secondary" size="sm" onClick={() => setAttempt((n) => n + 1)}>Retry</Button>
      </div>
    );
  if (state.kind === "absent")
    return (
      <div className="py-8 text-center text-text-3">
        {label} unavailable: {state.reason}.
        {kind === "threat" && (
          <>
            <br />
            Run a scan with <b>Build threat model (PASTA)</b> enabled to build one.
          </>
        )}
      </div>
    );
  if (state.kind === "malformed")
    return (
      <div className="rounded-md border border-err/40 bg-err-weak px-3 py-2 text-sm text-err">
        SBOM in scan <span className="font-mono">{state.scanId}</span> is malformed (not valid CycloneDX JSON).
      </div>
    );
  return (
    <>
      {sel && sel.valid && <SelectionNote sel={sel} label={label} />}
      {state.kind === "text" ? <Markdown base={scanId ? api.reportFileUrl(scanId, "").replace(/\?path=$/, "") : undefined}>{state.text}</Markdown> : <SbomTable cdx={state.cdx} id={scanId!} />}
    </>
  );
}
