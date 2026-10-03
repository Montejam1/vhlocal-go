import { useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import type { ReportModel, ReportModelFinding } from "@/lib/types";
import { Badge } from "@/components/ui/badge";

// Feature 015 (US2, C-A7/C-A8): the model-driven findings index — search,
// severity/status filters over every row, keyboard-activatable rows with stable
// anchors, collapsed details, captured evidence as code, explicit "not provided"
// lines, and the candidate appendices. Selection lives in the URL (?finding=) so
// it survives refresh and navigation.
export function FindingsIndex({ model }: { model: ReportModel }) {
  const [params, setParams] = useSearchParams();
  const [q, setQ] = useState("");
  const [sev, setSev] = useState("");
  const [status, setStatus] = useState("");
  const selected = params.get("finding");
  const byId = useMemo(() => new Map(model.findings.map((f) => [f.id, f])), [model]);

  const select = (id: string | null) => {
    const next = new URLSearchParams(params);
    if (id) next.set("finding", id);
    else next.delete("finding");
    setParams(next, { replace: true });
  };

  useEffect(() => {
    if (selected) document.getElementById("finding-" + selected)?.scrollIntoView({ block: "start" });
  }, [selected]);

  const match = (text: string, s: string, st: string) =>
    (!q || text.toLowerCase().includes(q.toLowerCase())) && (!sev || s.toLowerCase() === sev) && (!status || st === status);

  const rows = model.index.filter((r) => match(`${r.id} ${r.title} ${r.surface}`, r.severity, "supported"));
  const rejected = model.appendix.rejected.filter((r) => match(`${r.id} ${r.title} ${r.location}`, "", "rejected"));
  const explicit = model.appendix.unresolved_explicit.filter((r) => match(`${r.id} ${r.title} ${r.location}`, "", "unresolved_explicit"));
  const failed = model.appendix.unresolved_failed.filter((r) => match(`${r.id} ${r.title} ${r.location}`, "", "unresolved_failed"));
  const total = model.index.length + model.appendix.rejected.length + model.appendix.unresolved_explicit.length + model.appendix.unresolved_failed.length;
  const shown = rows.length + rejected.length + explicit.length + failed.length;
  const active = q || sev || status;

  return (
    <div data-testid="findings-index">
      <div className="mb-2 flex flex-wrap items-center gap-2 text-[12.5px]">
        <input className="rounded border border-line bg-surface-1 px-2 py-1" type="search" placeholder="search id, title, surface" value={q} onChange={(e) => setQ(e.target.value)} aria-label="Search findings" />
        <select className="rounded border border-line bg-surface-1 px-2 py-1" value={sev} onChange={(e) => setSev(e.target.value)} aria-label="Severity filter">
          <option value="">all severities</option>
          {["critical", "high+", "high", "medium", "low", "informational", "unrated"].map((s) => <option key={s}>{s}</option>)}
        </select>
        <select className="rounded border border-line bg-surface-1 px-2 py-1" value={status} onChange={(e) => setStatus(e.target.value)} aria-label="Status filter">
          <option value="">all statuses</option>
          <option value="supported">supported</option>
          <option value="rejected">rejected</option>
          <option value="unresolved_explicit">unresolved (explicit)</option>
          <option value="unresolved_failed">unresolved (failed)</option>
        </select>
        {active && <span className="rounded bg-warn-weak px-2 py-0.5 text-warn">Filtered view — showing {shown} of {total} rows</span>}
      </div>

      <h3 className="mt-3 text-[13px] font-semibold text-text-1">
        Findings index ({rows.length} of {model.index.length} supported, raw)
        {model.groups?.length ? <span className="ml-2 font-normal text-text-3">· {model.groups.length} remediation group{model.groups.length === 1 ? "" : "s"} — primary first, ↳ occurrences beneath</span> : null}
      </h3>
      <div className="overflow-x-auto rounded-[var(--radius-sm,8px)] border border-line">
        <table className="w-full text-[12.5px]">
          <thead>
            <tr className="bg-surface-2 text-text-2">
              {["#", "Finding", "Severity", "Surface", "Evidence", "Action"].map((h) => <th key={h} className="whitespace-nowrap px-3 py-2 text-left font-semibold">{h}</th>)}
            </tr>
          </thead>
          <tbody>
            {rows.length === 0 && <tr><td colSpan={6} className="py-4 text-center text-text-3">No supported findings match.</td></tr>}
            {rows.map((r, i) => (
              <tr
                key={r.id}
                tabIndex={0}
                role="button"
                data-anchor={r.anchor}
                data-group={r.group_id}
                data-role={r.role}
                id={r.role === "primary" && r.group_id ? `group-${r.group_id}` : undefined}
                className={"cursor-pointer border-t border-line hover:bg-accent-weak " + (selected === r.id ? "bg-accent-weak" : "")}
                onClick={() => select(r.id)}
                onKeyDown={(e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); select(r.id); } }}
              >
                <td className="px-3 py-2 font-mono text-text-3">{i + 1}</td>
                <td className={"px-3 py-2" + (r.role === "occurrence" ? " pl-8" : "")}>
                  {r.role === "occurrence" ? <span className="mr-1 text-text-3" aria-label="occurrence of the group above">↳</span> : null}
                  <span className="font-mono text-[11px]">{r.id}</span> — {r.title}
                  {r.group_id ? (
                    <span className="ml-1 text-[10.5px] text-text-3" title={r.role === "primary" && (r.group_size || 0) > 1 ? `remediation group · ${r.group_size} occurrences` : "remediation group"}>
                      {r.group_id}{r.role === "primary" && (r.group_size || 0) > 1 ? ` ×${r.group_size}` : ""}
                    </span>
                  ) : null}
                </td>
                <td className="px-3 py-2"><Badge variant={/^(critical|high)/i.test(r.severity) ? "err" : "warn"}>{r.severity}</Badge></td>
                <td className="px-3 py-2 font-mono text-[11px]">{r.surface}</td>
                <td className="px-3 py-2 text-[11px]">{r.evidence_status}</td>
                <td className="px-3 py-2 text-[11.5px]">{r.action || "fix not provided"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <div className="mt-3 flex flex-col gap-2">
        {rows.map((r) => {
          const f = byId.get(r.id);
          return f ? <FindingDetail key={f.id} f={f} open={selected === f.id} onToggle={() => select(selected === f.id ? null : f.id)} /> : null;
        })}
      </div>

      <Appendix title={`Rejected candidates (${rejected.length})`} note="Reviewed and refuted — not vulnerabilities.">
        {rejected.map((r) => <li key={r.id}><b className="font-mono text-[11px]">{r.id}</b> — {r.title} <span className="text-text-3">({r.location})</span> · {r.reason} · <i>action: {r.action}</i></li>)}
      </Appendix>
      <Appendix title={`Unresolved — explicit decision (${explicit.length})`} note="The verifier examined these and submitted unresolved: evidence of uncertainty, not confirmation.">
        {explicit.map((r) => <li key={r.id}><b className="font-mono text-[11px]">{r.id}</b> — {r.title} <span className="text-text-3">({r.location})</span> · {r.reason}</li>)}
      </Appendix>
      <Appendix title={`Unresolved — session failed (${failed.length})`} note="No decision was recorded: the verification session failed. Investigate the failure class before treating these as noise.">
        {failed.map((r) => <li key={r.id}><b className="font-mono text-[11px]">{r.id}</b> — {r.title} <span className="text-text-3">({r.location})</span> · <code>{r.class || "unknown"}</code> operation: {r.operation || "unknown"}; code: {r.code || "not recorded"} · {r.message}</li>)}
      </Appendix>
    </div>
  );
}

function FindingDetail({ f, open, onToggle }: { f: ReportModelFinding; open: boolean; onToggle: () => void }) {
  const row = (k: string, v?: string) => (
    <>
      <dt className="text-text-3">{k}</dt>
      <dd className="break-words">{v && v.trim() ? v : <i className="text-text-3">not recorded</i>}</dd>
    </>
  );
  return (
    <details id={"finding-" + f.id} className="rounded-[var(--radius-sm,8px)] border border-line bg-surface-1 px-3 py-2" open={open} onToggle={(e) => { if ((e.target as HTMLDetailsElement).open !== open) onToggle(); }}>
      <summary className="cursor-pointer text-[13px]"><Badge variant={/^(critical|high)/i.test(f.severity) ? "err" : "warn"}>{f.severity}</Badge> <b className="font-mono text-[11px]">{f.id}</b> — {f.title}</summary>
      <dl className="mt-2 grid grid-cols-[150px_1fr] gap-x-3 gap-y-1 text-[12.5px]">
        {row("CWE", f.cwe)}
        {row("Location", f.location)}
        {row("Entry point", f.entry_point)}
        {row("Impact", f.impact)}
        {row("Attacker prerequisites", f.prerequisites)}
        {row("Attacker control", f.attacker_control)}
        {row("Source-to-sink reasoning", f.source_to_sink)}
        {row("Reviewed defenses", f.defenses)}
        {row("Rationale", f.rationale)}
        <dt className="text-text-3">Captured evidence</dt>
        <dd>
          {f.evidence.length === 0 ? "none (not verified)" : f.evidence.map((e) => (
            <figure key={`${e.path}:${e.start}`} className="my-1">
              <figcaption className="font-mono text-[11px] text-text-3">{e.path}:{e.start}-{e.end}</figcaption>
              <pre className="overflow-auto rounded border border-line bg-surface-2 p-2 text-[11px]"><code>{e.quote}</code></pre>
            </figure>
          ))}
        </dd>
        <dt className="text-text-3">Recommended fix</dt>
        <dd>{f.fix && f.fix.trim() ? f.fix : "not provided"}</dd>
        {row("Reproduction", `${f.reproduction.status}${f.reproduction.path ? ` (${f.reproduction.path})` : ""}${f.reproduction.reason ? ` — ${f.reproduction.reason}` : ""} — not executed`)}
        {row("Classification", f.classification)}
      </dl>
    </details>
  );
}

function Appendix({ title, note, children }: { title: string; note: string; children: React.ReactNode[] }) {
  return (
    <details className="mt-3">
      <summary className="cursor-pointer text-[13px] font-semibold text-text-1">{title}</summary>
      <p className="text-[12px] text-text-3">{note}</p>
      <ul className="mt-1 list-disc pl-5 text-[12px]">{children.length ? children : <li className="list-none text-text-3">None.</li>}</ul>
    </details>
  );
}
