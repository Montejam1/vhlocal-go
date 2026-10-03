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

  // A cleared ledger disappears from the list — drop the selection and reload.
  const onCleared = (slug: string) => {
    if (active === slug) setActive(null);
    refresh();
  };

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
          <div className="flex flex-col gap-2">
            {ledgers.map((l) => (
              <LedgerCard
                key={l.slug}
                l={l}
                active={l.slug === active}
                onClick={() => setActive(l.slug)}
                onDelete={async () => {
                  if (!confirm(`Delete the ledger for “${l.target_name}”?\n\nThis removes its ${l.total} tracked finding(s) across every run. Scan reports are KEPT.`)) return;
                  try {
                    await api.clearLedger(l.slug);
                    onCleared(l.slug);
                  } catch (e) {
                    alert(String((e as Error).message || e));
                  }
                }}
              />
            ))}
          </div>
          {active && <LedgerView slug={active} onListRefresh={refresh} onCleared={onCleared} />}
        </>
      )}
    </div>
  );
}

function LedgerCard({ l, active, onClick, onDelete }: { l: LedgerSummary; active: boolean; onClick: () => void; onDelete: () => void }) {
  return (
    <Card onClick={onClick} className={cn("relative cursor-pointer hover:border-line-strong", active && "border-accent ring-1 ring-accent")}>
      <button
        className="absolute right-2 top-2 rounded border border-line px-2 py-0.5 text-[11px] text-err hover:border-err hover:bg-err-weak"
        title="Delete ledger"
        onClick={(e) => {
          e.stopPropagation();
          onDelete();
        }}
      >
        Delete
      </button>
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

function LedgerView({
  slug,
  onListRefresh,
  onCleared,
}: {
  slug: string;
  onListRefresh: () => void;
  onCleared: (slug: string) => void;
}) {
  const [d, setD] = useState<LedgerDetail | null>(null);
  const [busy, setBusy] = useState(false);
  const load = () => api.ledger(slug).then(setD).catch(() => setD(null));
  useEffect(() => {
    setD(null);
    load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [slug]);
  if (!d) return <div className="mt-6 py-8 text-center text-text-3">Loading…</div>;

  const clearLedger = async () => {
    if (!window.confirm(
      `Clear the entire ledger for “${d.summary.target_name}”?\n\n` +
      `This permanently removes all ${d.summary.total} tracked finding(s) across ` +
      `every run. Scan reports are kept — only the accumulated ledger is cleared.`,
    )) return;
    setBusy(true);
    try {
      await api.clearLedger(slug);
      onCleared(slug);
    } catch {
      window.alert("Failed to clear the ledger.");
    } finally {
      setBusy(false);
    }
  };

  const removeFinding = async (f: LedgerFinding) => {
    if (!window.confirm(
      `Remove this finding from the ledger?\n\n${f.title || f.key}\n\n` +
      `It stops being tracked across runs. A later scan that re-confirms it will ` +
      `add it back.`,
    )) return;
    setBusy(true);
    try {
      await api.removeLedgerFinding(slug, f.key);
      await load();
      onListRefresh();
    } catch {
      window.alert("Failed to remove the finding.");
    } finally {
      setBusy(false);
    }
  };

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
        <Button variant="danger" size="sm" disabled={busy || sm.total === 0} onClick={clearLedger}>
          Clear ledger
        </Button>
      </div>

      <div className="my-3">
        <SeverityStrip severities={sm.by_severity} />
      </div>

      <div className="overflow-x-auto rounded-[var(--radius-sm,8px)] border border-line">
        <table className="w-full text-[12.5px]">
          <thead>
            <tr className="bg-surface-2 text-text-2">
              {["Severity", "Finding", "CWE", "Location", "Status", "Seen", "Confidence", ""].map((h, i) => (
                <th key={h || `act-${i}`} className="whitespace-nowrap px-3 py-2 text-left font-semibold">
                  {h}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {findings.length === 0 && (
              <tr>
                <td colSpan={8} className="py-6 text-center text-text-3">No findings recorded.</td>
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
                <td className="px-3 py-2 text-right">
                  <button
                    type="button"
                    disabled={busy}
                    onClick={() => removeFinding(f)}
                    title="Remove this finding from the ledger"
                    className="rounded px-1.5 py-0.5 text-text-3 hover:bg-err-weak hover:text-err disabled:opacity-40"
                  >
                    ✕
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
