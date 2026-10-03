import { useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import type { PrimaryIssue, ReportPresentation } from "@/lib/types";
import { Badge } from "@/components/ui/badge";

// Feature 016 (US5, FR-021, FR-022, FR-023, C-P27, C-P30): the reader-facing index, one row
// per PRIMARY ISSUE, read from the presentation projection.
//
// Nothing here recomputes grouping, severity, counts or guidance: the projection established
// them when the report was built. Needs review and dismissed candidates are separate,
// on-demand sections and never enter the issue list or the severity filter. Filtering is
// presentation only — the full total stays visible, and a zero-match view says so.

const SEVERITIES = ["critical", "high", "medium", "low", "informational", "unrated"] as const;

type Scope = "" | "issue" | "review" | "dismissed";

export function IssuesIndex({ presentation }: { presentation: ReportPresentation }) {
  const [params, setParams] = useSearchParams();
  const [q, setQ] = useState("");
  const [sev, setSev] = useState("");
  const [scope, setScope] = useState<Scope>("");
  const selected = params.get("issue");

  const select = (ref: string | null) => {
    const next = new URLSearchParams(params);
    if (ref) next.set("issue", ref);
    else next.delete("issue");
    setParams(next, { replace: true });
  };

  useEffect(() => {
    if (selected) document.getElementById(selected.toLowerCase())?.scrollIntoView({ block: "start" });
  }, [selected]);

  const text = (s: string) => s.toLowerCase();
  const hit = (s: string) => !q || text(s).includes(text(q));

  const issues = useMemo(
    () => presentation.issues.filter((is) => hit(`${is.title} ${affected(is)}`) && (!sev || is.severity.toLowerCase() === sev) && (!scope || scope === "issue")),
    [presentation.issues, q, sev, scope],
  );
  const review = presentation.review_items.filter((it) => hit(`${it.title ?? ""} ${it.location ?? ""}`) && !sev && (!scope || scope === "review"));
  const dismissed = presentation.dismissed.filter((d) => hit(`${d.title} ${d.location ?? ""}`) && !sev && (!scope || scope === "dismissed"));

  // The full totals, which filtering never changes.
  const totals = {
    issues: presentation.issues.length,
    review: presentation.review_items.length,
    dismissed: presentation.dismissed.length,
  };
  const shown = issues.length + review.length + dismissed.length;
  const total = totals.issues + totals.review + totals.dismissed;
  const filtering = Boolean(q || sev || scope);

  return (
    <div data-testid="issues-index">
      <div className="mb-2 flex flex-wrap items-center gap-2 text-[12.5px]">
        <input
          className="min-w-0 flex-1 rounded border border-line bg-surface-1 px-2 py-1 sm:flex-none"
          type="search"
          placeholder="search issue, file"
          value={q}
          onChange={(e) => setQ(e.target.value)}
          aria-label="Search issues"
        />
        <select className="rounded border border-line bg-surface-1 px-2 py-1" value={sev} onChange={(e) => setSev(e.target.value)} aria-label="Severity filter">
          <option value="">all severities</option>
          {SEVERITIES.map((s) => <option key={s}>{s}</option>)}
        </select>
        <select className="rounded border border-line bg-surface-1 px-2 py-1" value={scope} onChange={(e) => setScope(e.target.value as Scope)} aria-label="Section filter">
          <option value="">all sections</option>
          <option value="issue">issues to fix</option>
          <option value="review">needs review</option>
          <option value="dismissed">dismissed</option>
        </select>
        {filtering && (
          <span className="rounded bg-warn-weak px-2 py-0.5 text-warn">
            Filtered view — showing {shown} of {total} rows · {totals.issues} issues to fix in the full report
          </span>
        )}
      </div>

      <h3 className="mt-3 text-[13px] font-semibold text-text-1">
        Issues to fix <span className="font-normal text-text-3">· {issues.length} of {totals.issues} established defect{totals.issues === 1 ? "" : "s"}</span>
      </h3>
      <div className="overflow-x-auto rounded-[var(--radius-sm,8px)] border border-line">
        <table className="w-full text-[12.5px]">
          <thead>
            <tr className="bg-surface-2 text-text-2">
              {["#", "Severity", "Issue", "Affected", "Recommended action"].map((h) => (
                <th key={h} className="whitespace-nowrap px-3 py-2 text-left font-semibold">{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {issues.length === 0 && (
              <tr>
                <td colSpan={5} className="py-4 text-center text-text-3">
                  {filtering ? `No issue matches this filter. The full report has ${totals.issues}.` : "No issue was established in the reviewed code."}
                </td>
              </tr>
            )}
            {issues.map((is, i) => (
              <tr
                key={is.ref}
                tabIndex={0}
                role="button"
                data-anchor={is.ref.toLowerCase()}
                data-sev={is.severity.toLowerCase()}
                className={"cursor-pointer border-t border-line hover:bg-accent-weak focus:outline focus:outline-2 focus:outline-accent " + (selected === is.ref ? "bg-accent-weak" : "")}
                onClick={() => select(is.ref)}
                onKeyDown={(e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); select(is.ref); } }}
              >
                <td className="px-3 py-2 font-mono text-text-3">{i + 1}</td>
                <td className="px-3 py-2"><Badge variant={/^(critical|high)$/i.test(is.severity) ? "err" : "warn"}>{is.severity}</Badge></td>
                <td className="px-3 py-2 break-words">{is.title}</td>
                <td className="px-3 py-2 font-mono text-[11px] break-all">{affected(is)}</td>
                <td className="px-3 py-2 text-[11.5px] break-words">{firstStep(is)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <div className="mt-3 flex flex-col gap-2">
        {issues.map((is) => (
          <IssueDetail key={is.ref} issue={is} open={selected === is.ref} onToggle={() => select(selected === is.ref ? null : is.ref)} />
        ))}
      </div>

      <Section title={`Needs review (${review.length} of ${totals.review})`} note="Neither confirmed nor dismissed. None is counted among the issues to fix, and none carries an assessed severity.">
        {review.map((it) => (
          <li key={it.ref}>
            <b>{it.title}</b> — {it.what_is_unresolved}
            {it.location ? <span className="font-mono text-[11px] text-text-3"> ({it.location})</span> : null}
            {it.provisional_severity ? <> · severity proposed, not established: {it.provisional_severity}</> : null} · next step: {it.next_step}
          </li>
        ))}
      </Section>
      <Section title={`Dismissed candidates (${dismissed.length} of ${totals.dismissed})`} note="Examined and refuted, with the reason recorded at the time. A dismissal is never re-decided by the report.">
        {dismissed.map((d) => (
          <li key={d.ref}>
            <b>{d.title}</b>
            {d.location ? <span className="font-mono text-[11px] text-text-3"> ({d.location})</span> : null} — {d.reason} · recorded decision: {d.decision}
          </li>
        ))}
      </Section>
      <p className="mt-2 text-[11.5px] text-text-3">
        Scanner diagnostics — {presentation.counts.candidates_examined} candidates examined, {presentation.counts.detections} supported detections — are in the full
        report under Scan details.
      </p>
    </div>
  );
}

// IssueDetail renders the five reader sections in the order FR-011 fixes them, with the
// recorded technical evidence as optional detail.
function IssueDetail({ issue, open, onToggle }: { issue: PrimaryIssue; open: boolean; onToggle: () => void }) {
  const fix = issue.how_to_fix_it;
  const row = (k: string, v?: string) =>
    v && v.trim() ? (
      <>
        <dt className="text-text-3">{k}</dt>
        <dd className="break-words">{v}</dd>
      </>
    ) : null;
  return (
    <details
      id={issue.ref.toLowerCase()}
      className="rounded-[var(--radius-sm,8px)] border border-line bg-surface-1 px-3 py-2"
      open={open}
      onToggle={(e) => { if ((e.target as HTMLDetailsElement).open !== open) onToggle(); }}
    >
      <summary className="cursor-pointer text-[13px]">
        <Badge variant={/^(critical|high)$/i.test(issue.severity) ? "err" : "warn"}>{issue.severity}</Badge> {issue.title}{" "}
        <span className="font-mono text-[11px] text-text-3">{issue.ref}</span>
      </summary>
      {/* Pre-016 deep links keep working: each backing detection and the recorded group id
          remain addressable inside the issue that reports them. */}
      {issue.members.map((m) => <span key={m.finding_id} id={`finding-${m.finding_id}`} />)}
      {issue.group_id ? <span id={`group-${issue.group_id}`} /> : null}

      <h4 className="mt-2 text-[12.5px] font-semibold text-text-1">What we found</h4>
      <p className="text-[12.5px] text-text-2">{issue.what_we_found}</p>
      <dl className="mt-1 grid grid-cols-[150px_1fr] gap-x-3 gap-y-1 text-[12.5px] max-sm:grid-cols-1">
        {row("Weakness", [issue.canonical_name, issue.cwe ? `(${issue.cwe})` : ""].filter(Boolean).join(" "))}
        {row("Access required", issue.access_required)}
        {row("What an attacker controls", issue.attacker_control)}
        {row("Safeguards reviewed", issue.safeguards_reviewed)}
        {issue.original_severities?.length ? row("Recorded rating", `${issue.original_severities.join(", ")} (shown as ${issue.severity})`) : null}
      </dl>

      <h4 className="mt-2 text-[12.5px] font-semibold text-text-1">Why it matters</h4>
      <p className="text-[12.5px] text-text-2">{issue.why_it_matters}</p>

      <h4 className="mt-2 text-[12.5px] font-semibold text-text-1">Where it is</h4>
      <ul className="list-disc pl-5 text-[12.5px]">
        {issue.locations.length === 0 && <li>the affected location was not recorded</li>}
        {issue.locations.map((l) => (
          <li key={`${l.file}:${l.lines ?? ""}`} className="break-all">
            <code className="font-mono text-[11px]">{l.available ? `${l.file}${l.lines ? `:${l.lines}` : ""}` : `${l.file || "location not recorded"} (citation not resolvable)`}</code>
            {l.citation_count > 1 ? <> — cited by {l.citation_count} detections</> : null}
            {l.entry_point ? <> · reached through {l.entry_point}</> : null}
          </li>
        ))}
      </ul>

      <h4 className="mt-2 text-[12.5px] font-semibold text-text-1">How to fix it</h4>
      {fix.label ? <p className="text-[11.5px] text-text-3">{fix.label}</p> : null}
      <ol className="list-decimal pl-5 text-[12.5px]">{fix.steps.map((s) => <li key={s}>{s}</li>)}</ol>
      {fix.missing_decision ? <p className="mt-1 text-[12.5px]"><b>Decision this needs from you:</b> {fix.missing_decision}</p> : null}
      {fix.recorded_note ? <p className="mt-1 text-[12.5px]"><b>Recorded recommendation, kept for reference:</b> {fix.recorded_note}</p> : null}

      <h4 className="mt-2 text-[12.5px] font-semibold text-text-1">How to check the fix</h4>
      <ul className="list-disc pl-5 text-[12.5px]">
        {issue.how_to_check_the_fix.length === 0 && <li>no check is suggested for this weakness class; decide one from the change you make</li>}
        {issue.how_to_check_the_fix.map((c) => <li key={c}>{c}</li>)}
      </ul>

      <details className="mt-2">
        <summary className="cursor-pointer text-[12.5px] font-semibold text-text-2">Technical evidence</summary>
        <dl className="mt-1 grid grid-cols-[150px_1fr] gap-x-3 gap-y-1 text-[12px] max-sm:grid-cols-1">
          <dt className="text-text-3">Established by</dt>
          <dd className="break-all font-mono text-[11px]">
            {issue.members.map((m) => `${m.finding_id}${m.severity && m.severity !== issue.severity ? ` (recorded ${m.severity})` : ""}`).join(", ")}
            {issue.group_id ? ` · recorded group ${issue.group_id}` : ""}
          </dd>
          {row("Grouping", issue.grouping_note)}
        </dl>
        {issue.evidence.length === 0 ? (
          <p className="text-[12px] text-text-3">none recorded</p>
        ) : (
          issue.evidence.map((e) => (
            <figure key={`${e.path}:${e.start}`} className="my-1">
              <figcaption className="font-mono text-[11px] text-text-3">{e.path}:{e.start}-{e.end}</figcaption>
              <pre className="overflow-auto rounded border border-line bg-surface-2 p-2 text-[11px]"><code>{e.quote}</code></pre>
            </figure>
          ))
        )}
      </details>
    </details>
  );
}

function Section({ title, note, children }: { title: string; note: string; children: React.ReactNode[] }) {
  return (
    <details className="mt-3">
      <summary className="cursor-pointer text-[13px] font-semibold text-text-1">{title}</summary>
      <p className="text-[12px] text-text-3">{note}</p>
      <ul className="mt-1 list-disc pl-5 text-[12px]">{children.length ? children : <li className="list-none text-text-3">None.</li>}</ul>
    </details>
  );
}

// affected and firstStep read the projection; neither derives a new fact.
function affected(is: PrimaryIssue): string {
  if (is.locations.length === 0) return "location not recorded";
  if (is.locations.length === 1) {
    const l = is.locations[0];
    const where = l.available ? `${l.file}${l.lines ? `:${l.lines}` : ""}` : l.file || "location not recorded";
    return l.citation_count > 1 ? `${where} (${l.citation_count} detections)` : where;
  }
  return `${is.locations.length} locations`;
}

function firstStep(is: PrimaryIssue): string {
  const fix = is.how_to_fix_it;
  if (fix.steps.length) return fix.steps[0];
  if (fix.missing_decision) return `Decide and then enforce: ${fix.missing_decision}`;
  return "Inspect the affected code and establish the required change";
}
