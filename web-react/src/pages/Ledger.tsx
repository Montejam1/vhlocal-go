import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import { usePoll } from "@/lib/usePoll";
import type { LedgerDetail, LedgerFinding, LedgerSummary } from "@/lib/types";
import { Card, CardTitle, CardMeta } from "@/components/ui/card";
import { Badge, SevBadge, SeverityStrip } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { cn, fmtDate } from "@/lib/utils";

export function Ledger() {
  const { data: ledgers, refresh } = usePoll<LedgerSummary[]>(() => api.ledgers(), 0);
  const [active, setActive] = useState<string | null>(null);

  useEffect(() => {
    if (ledgers && !active && ledgers[0]) setActive(ledgers[0].slug);
  }, [ledgers, active]);

  return (
    <div>
      <div className="flex items-center gap-3">
        <h1 className="text-xl font-semibold text-text-1">Vulnerability ledger</h1>
        <span className="flex-1" />
        <Button variant="secondary" size="sm" onClick={refresh}>
          Refresh
        </Button>
      </div>
      <p className="mt-1 mb-4 text-[13px] text-text-2">
        A persistent, per-application memory of findings across every scan — deduped by root
        cause, tracked as open / fixed / regressed, and scored by how many runs confirmed each.
      </p>

      {!ledgers && <div className="py-10 text-center text-text-3">Loading…</div>}
      {ledgers && ledgers.length === 0 && (
        <div className="py-10 text-center text-text-3">
          No ledgers yet. Run a scan with the <b>vulnerability ledger</b> option enabled.
        </div>
      )}

      {ledgers && ledgers.length > 0 && (
        <>
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3">
            {ledgers.map((l) => (
              <LedgerCard key={l.slug} l={l} active={l.slug === active} onClick={() => setActive(l.slug)} />
            ))}
          </div>
          {active && <LedgerView slug={active} />}
        </>
      )}
    </div>
  );
}

function LedgerCard({ l, active, onClick }: { l: LedgerSummary; active: boolean; onClick: () => void }) {
  return (
    <Card onClick={onClick} className={cn("cursor-pointer hover:border-line-strong", active && "border-accent ring-1 ring-accent")}>
      <CardTitle>{l.target_name}</CardTitle>
      <div className="mt-0.5 truncate font-mono text-[11px] text-text-3" title={l.target}>
        {l.target}
      </div>
      <CardMeta>
        <Badge>{l.total} tracked</Badge>
        <span>{l.runs_recorded} run{l.runs_recorded === 1 ? "" : "s"}</span>
        <span>{fmtDate(l.updated)}</span>
      </CardMeta>
      <CardMeta>
        {l.open > 0 && <Badge variant="err">{l.open} open</Badge>}
        {l.fixed > 0 && <Badge variant="ok">{l.fixed} fixed</Badge>}
        {l.regressed > 0 && <Badge variant="warn">{l.regressed} regressed</Badge>}
        {l.reliable > 0 && <Badge variant="accent">{l.reliable} reliable</Badge>}
      </CardMeta>
    </Card>
  );
}

const SEV_ORDER = ["Critical", "High+", "High", "Medium", "Moderate", "Low", "Informational", "Info", "Unrated"];

function LedgerView({ slug }: { slug: string }) {
  const [d, setD] = useState<LedgerDetail | null>(null);
  useEffect(() => {
    setD(null);
    api.ledger(slug).then(setD).catch(() => setD(null));
  }, [slug]);
  if (!d) return <div className="mt-6 py-8 text-center text-text-3">Loading…</div>;

  const sm = d.summary;
  const rank = (s: string) => (SEV_ORDER.indexOf(s) + 99) % 100;
  const findings = (d.findings || []).slice().sort((a, b) => {
    const st = (x: LedgerFinding) => (x.status === "regressed" ? 0 : x.status === "open" ? 1 : 2);
    if (st(a) !== st(b)) return st(a) - st(b);
    if (rank(a.severity) !== rank(b.severity)) return rank(a.severity) - rank(b.severity);
    return (b.confirmed_count || 0) - (a.confirmed_count || 0);
  });

  const statusBadge = (s: string) =>
    s === "regressed" ? <Badge variant="warn">regressed</Badge> : s === "fixed" ? <Badge variant="ok">fixed</Badge> : <Badge variant="err">open</Badge>;
  const confBadge = (c: string) =>
    c ? <Badge variant={c === "reliable" ? "ok" : c === "provisional" ? "warn" : "default"}>{c}</Badge> : null;

  return (
    <div className="mt-6 border-t border-line pt-5">
      <div className="flex flex-wrap items-end gap-4">
        <div>
          <h2 className="text-lg font-semibold text-text-1">{sm.target_name}</h2>
          <div className="break-all font-mono text-[11px] text-text-3">{sm.target}</div>
        </div>
        <span className="flex-1" />
        <div className="flex gap-5">
          {([["tracked", sm.total], ["open", sm.open], ["regressed", sm.regressed], ["reliable", sm.reliable], ["runs", sm.runs_recorded]] as [string, number][]).map(
            ([label, v]) => (
              <div key={label} className="flex flex-col items-center">
                <b className="text-xl font-bold leading-none text-text-1">{v}</b>
                <span className="text-[10px] uppercase tracking-wide text-text-3">{label}</span>
              </div>
            ),
          )}
        </div>
      </div>

      <div className="my-3">
        <SeverityStrip severities={sm.by_severity} />
      </div>

      <div className="overflow-x-auto rounded-[var(--radius-sm,8px)] border border-line">
        <table className="w-full text-[12.5px]">
          <thead>
            <tr className="bg-surface-2 text-text-2">
              {["Severity", "Finding", "CWE", "Location", "Status", "Seen", "Confidence"].map((h) => (
                <th key={h} className="whitespace-nowrap px-3 py-2 text-left font-semibold">
                  {h}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {findings.length === 0 && (
              <tr>
                <td colSpan={7} className="py-6 text-center text-text-3">No findings recorded.</td>
              </tr>
            )}
            {findings.map((f) => (
              <tr key={f.key} className="border-t border-line">
                <td className="px-3 py-2"><SevBadge severity={f.severity || "Unrated"} /></td>
                <td className="min-w-[240px] max-w-[520px] px-3 py-2 text-text-1">{f.title || "—"}</td>
                <td className="whitespace-nowrap px-3 py-2 font-mono text-text-2">{f.canonical_cwe || f.family || "—"}</td>
                <td className="max-w-[220px] truncate px-3 py-2 font-mono text-[11px] text-text-2">{f.location || "—"}</td>
                <td className="px-3 py-2">{statusBadge(f.status)}</td>
                <td className="whitespace-nowrap px-3 py-2 text-text-2" title={`confirmed in ${f.confirmed_count} run(s)`}>
                  {f.confirmed_count}×{f.cross_family ? " ⨯fam" : ""}
                </td>
                <td className="px-3 py-2">{confBadge(f.confidence)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
