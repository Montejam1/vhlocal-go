import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { api } from "@/lib/api";
import type { AppDetail, AppSummary, Cdx } from "@/lib/types";
import { Card, CardTitle, CardMeta } from "@/components/ui/card";
import { Badge, SeverityStrip } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Tabs } from "@/components/ui/tabs";
import { Markdown } from "@/components/Markdown";
import { SbomTable } from "@/components/SbomTable";
import { cn, fmtDate, fmtDateTime } from "@/lib/utils";

export function Applications() {
  const [apps, setApps] = useState<AppSummary[] | null>(null);
  const [active, setActive] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);

  const load = () =>
    api
      .applications()
      .then((a) => {
        setApps(a);
        setActive((cur) => cur || a[0]?.slug || null);
      })
      .catch((e) => setErr(String(e.message || e)));

  useEffect(() => {
    load();
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

      {err && <div className="rounded-md border border-err/40 bg-err-weak px-3 py-2 text-sm text-err">{err}</div>}
      {!apps && !err && <div className="py-10 text-center text-text-3">Loading…</div>}
      {apps && apps.length === 0 && (
        <div className="py-10 text-center text-text-3">
          No applications yet. Run a scan and name the application.
        </div>
      )}

      {apps && apps.length > 0 && (
        <>
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3">
            {apps.map((a) => (
              <AppCard key={a.slug} app={a} active={a.slug === active} onClick={() => setActive(a.slug)} />
            ))}
          </div>
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

function AppCard({ app, active, onClick }: { app: AppSummary; active: boolean; onClick: () => void }) {
  return (
    <Card
      onClick={onClick}
      className={cn("cursor-pointer hover:border-line-strong", active && "border-accent ring-1 ring-accent")}
    >
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
  const [tab, setTab] = useState<"history" | "threat" | "sbom">("history");

  useEffect(() => {
    setDetail(null);
    setTab("history");
    api.application(slug).then(setDetail).catch(() => setDetail(null));
  }, [slug]);

  if (!detail) return <div className="mt-6 py-8 text-center text-text-3">Loading…</div>;

  const rename = async () => {
    const name = prompt("Application name:", detail.name);
    if (!name?.trim()) return;
    await api.renameApplication(slug, name.trim());
    api.application(slug).then(setDetail);
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
    <div className="mt-6 border-t border-line pt-5">
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
        {detail.latest_report_id && (
          <Button variant="secondary" size="sm" onClick={() => navigate(`/reports?open=${detail.latest_report_id}`)}>
            Open latest report
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
              <td className="whitespace-nowrap px-3 py-2 font-mono text-text-2">{fmtDateTime(s.created)}</td>
              <td className="whitespace-nowrap px-3 py-2 font-mono text-text-2">{s.model || "—"}</td>
              <td className="px-3 py-2">
                <Badge variant={s.findings ? "err" : "ok"}>{s.findings}</Badge>
              </td>
              <td className="px-3 py-2"><SeverityStrip severities={s.severities} /></td>
              <td className="px-3 py-2">
                {s.coverage_status ? (
                  s.coverage_degraded ? <Badge variant="warn">degraded</Badge> : <Badge variant="ok">clean</Badge>
                ) : "—"}
              </td>
              <td className="px-3 py-2 text-text-2">{s.has_threat_model ? "✓" : ""}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function IntelTab({ slug, detail, kind }: { slug: string; detail: AppDetail; kind: "threat" | "sbom" }) {
  const [content, setContent] = useState<string | Cdx | null | "loading" | "none">("loading");
  const want = kind === "threat" ? "has_threat_model" : "has_sbom";
  const scan = (detail.scan_history || []).find((s) => (s as any)[want]);

  useEffect(() => {
    setContent("loading");
    if (!scan) {
      setContent("none");
      return;
    }
    const file = kind === "threat" ? "threat_model.md" : "sbom.cdx.json";
    api.reportText(scan.id, file).then((txt) => {
      if (!txt) return setContent("none");
      if (kind === "threat") setContent(txt);
      else {
        try {
          setContent(JSON.parse(txt) as Cdx);
        } catch {
          setContent("none");
        }
      }
    });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [slug, kind]);

  if (content === "loading") return <div className="py-6 text-center text-text-3">Loading…</div>;
  if (content === "none")
    return (
      <div className="py-8 text-center text-text-3">
        {kind === "threat" ? "No threat model for this application yet." : "No SBOM for this application yet."}
        <br />
        Run a scan with <b>Build threat model (PASTA)</b> enabled.
      </div>
    );
  if (kind === "threat") return <Markdown>{content as string}</Markdown>;
  return <SbomTable cdx={content as Cdx} id={scan!.id} />;
}
