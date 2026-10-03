// HTML rendering of the report model (feature 015, US1/US2): same order and
// numbers as the Markdown, single self-contained offline file, index with
// search/severity/status filters over every row, collapsed finding details,
// print scope and page breaks.
package report

import (
	"fmt"
	"html"
	"strings"
)

// RenderHTML produces a single self-contained SCAN_REPORT.html.
func RenderHTML(in Input) string {
	return renderHTMLModel(in, BuildModel(in))
}

// renderHTMLModel renders from the presentation projection when the model carries one,
// and otherwise through the unchanged legacy path (FR-026, C-C7).
func renderHTMLModel(in Input, m ReportModel) string {
	if m.Presentation != nil {
		return renderHTMLPresentation(in, m)
	}
	return renderHTMLLegacy(in, m)
}

func renderHTMLLegacy(in Input, m ReportModel) string {
	rs := in.Doc.RunStatus
	esc := html.EscapeString
	c := m.Counts

	// Banner (one line).
	bannerHTML := ""
	if !isCleanRun(in) {
		bannerHTML = fmt.Sprintf(`<div class="broken">⚠ <b>Incomplete run.</b> %s (%d coverage reason(s) — see <a href="#coverage">Coverage and limitations</a>.)</div>`,
			esc(brokenBanner(in)), len(rs.CoverageDegradedReasons))
	}

	// Executive summary.
	var sum strings.Builder
	fmt.Fprintf(&sum, `<p class="narrative">%s</p>`, esc(m.Summary.Narrative))
	if len(m.Summary.Leading) > 0 {
		sum.WriteString(`<h3>Leading issues</h3><ol class="leading">`)
		for _, l := range m.Summary.Leading {
			fmt.Fprintf(&sum, `<li><a href="#%s">%s</a> — <span class="sev sev-%s">%s</span> · %s · %s</li>`,
				esc(l.Ref), esc(l.Title), esc(strings.ToLower(l.Severity)), esc(l.Severity), esc(l.Surface), esc(l.Action))
		}
		fmt.Fprintf(&sum, `</ol><p class="muted">Complete list: <a href="#findings-index">Findings index</a> (%d supported).</p>`, c.Supported)
	}
	if len(m.Summary.Limitations) > 0 {
		sum.WriteString(`<h3>Material limitations</h3><ul class="limitations">`)
		for _, l := range m.Summary.Limitations {
			fmt.Fprintf(&sum, `<li>%s</li>`, esc(l))
		}
		sum.WriteString(`</ul>`)
	}

	// Outcome metrics + tiles (supported only) + candidate severities (labelled).
	var tiles strings.Builder
	tile := func(label string, n int) {
		fmt.Fprintf(&tiles, `<div class="tile"><div class="tn">%d</div><div class="tl">%s</div></div>`, n, esc(label))
	}
	tile("Supported findings", c.Supported)
	for _, sd := range sevDisplay {
		if n := m.SeveritySupported[sd.label]; n > 0 || sd.label == "Unrated" {
			tile(sd.glyph+" "+sd.label, n)
		}
	}
	var metrics strings.Builder
	fmt.Fprintf(&metrics, `<ul class="metrics"><li><b>Supported findings (raw)</b>: %d</li><li><b>Remediation groups (grouped)</b>: %d — one actionable fix per group; occurrences keep their own evidence</li><li><b>Rejected candidates</b>: %d</li>`, c.Supported, c.RemediationGroups, c.Rejected)
	fmt.Fprintf(&metrics, `<li><b>Unresolved candidates</b>: %d — %d explicit verifier decisions, %d failed verification sessions</li>`, c.UnresolvedExplicit+c.UnresolvedFailed, c.UnresolvedExplicit, c.UnresolvedFailed)
	fmt.Fprintf(&metrics, `<li><b>Total candidates</b>: %d — a candidate total is not a confirmed-vulnerability count.</li>`, c.TotalCandidates)
	fmt.Fprintf(&metrics, `<li><b>Execution</b>: %s</li><li><b>Coverage</b>: %s</li>`, esc(orText(m.Status.Execution, "unknown")), esc(orText(m.Status.Coverage, "unknown")))
	if c.SourceReview.Total > 0 {
		fmt.Fprintf(&metrics, `<li><b>Source review</b>: %d of %d entry points completed (%s)</li>`, c.SourceReview.Completed, c.SourceReview.Total, esc(orText(m.CoverageSemanticsLabel, "coverage semantics unknown")))
	} else {
		metrics.WriteString(`<li><b>Source review</b>: no entry-point inventory for this run</li>`)
	}
	fmt.Fprintf(&metrics, `<li><b>Validation mode</b>: %s</li></ul>`, esc(orText(m.Status.ValidationMode, "unknown")))
	metrics.WriteString(`<p class="muted">Candidates by severity (all statuses — not vulnerabilities): `)
	var cs []string
	for _, sd := range sevDisplay {
		if n := m.SeverityCandidates[sd.label]; n > 0 {
			cs = append(cs, fmt.Sprintf("%s %d", esc(sd.label), n))
		}
	}
	if len(cs) == 0 {
		cs = []string{"none"}
	}
	metrics.WriteString(strings.Join(cs, " · ") + `</p>`)
	if len(in.Nav) > 0 {
		metrics.WriteString(`<p class="nav">`)
		for i, n := range in.Nav {
			if i > 0 {
				metrics.WriteString(" · ")
			}
			fmt.Fprintf(&metrics, `<a href="%s">%s</a>`, esc(n.Path), esc(n.Label))
		}
		metrics.WriteString(`</p>`)
	}

	// Findings index (every row filterable/searchable, keyboard-focusable).
	var index strings.Builder
	if len(m.Index) == 0 {
		index.WriteString(`<p class="muted">No supported findings.</p>`)
	} else {
		if len(m.Groups) > 0 {
			fmt.Fprintf(&index, `<p class="muted">%d supported finding(s) (raw) in %d remediation group(s). Groups are listed primary first; ↳ marks an occurrence of the same defect with its own evidence.</p>`, m.Counts.Supported, m.Counts.RemediationGroups)
		}
		index.WriteString(`<table id="index"><thead><tr><th>#</th><th>Finding</th><th>Severity</th><th>Surface</th><th>Evidence</th><th>Action</th></tr></thead><tbody>`)
		for i, row := range m.Index {
			grp, attrs, mark := "", "", ""
			if row.GroupID != "" {
				grp = fmt.Sprintf(` <a class="grp" href="#group-%s">%s</a>`, esc(row.GroupID), esc(row.GroupID))
				attrs = fmt.Sprintf(` data-group="%s" data-role="%s"`, esc(row.GroupID), esc(row.Role))
				if row.Role == "primary" {
					attrs += fmt.Sprintf(` id="group-%s"`, esc(row.GroupID))
					if row.GroupSize > 1 {
						grp += fmt.Sprintf(` <span class="muted">(%d occurrences)</span>`, row.GroupSize)
					}
				} else if row.Role == "occurrence" {
					mark = `<span class="occ" aria-label="occurrence of the group above">↳</span> `
				}
			}
			fmt.Fprintf(&index, `<tr class="idx" tabindex="0" data-sev="%s" data-status="supported" data-evidence="%s" data-text="%s"%s><td>%d</td><td>%s<a href="#%s">%s</a> — %s%s</td><td><span class="sev sev-%s">%s</span></td><td>%s</td><td>%s</td><td>%s</td></tr>`,
				esc(strings.ToLower(row.Severity)), esc(row.EvidenceStatus), esc(strings.ToLower(row.ID+" "+row.Title+" "+row.Surface)),
				attrs, i+1, mark, esc(row.Anchor), esc(row.ID), esc(row.Title), grp, esc(strings.ToLower(row.Severity)), esc(row.Severity), esc(row.Surface), esc(row.EvidenceStatus), esc(orText(row.Action, "fix not provided")))
		}
		index.WriteString(`</tbody></table>`)
	}

	// Findings — collapsed details, every evidence excerpt as escaped code.
	var rows strings.Builder
	if len(m.Findings) == 0 {
		rows.WriteString(`<p class="muted">No findings were verified as supported. Rejected and unresolved candidates are in Appendix A.</p>`)
	} else {
		fmt.Fprintf(&rows, `<p class="muted">Supported findings (%d) — each verified by source-grounded review.</p>`, len(m.Findings))
	}
	for _, f := range m.Findings {
		sev := strings.ToLower(f.Severity)
		fmt.Fprintf(&rows, `<details class="finding" id="finding-%s" data-sev="%s" data-status="supported" data-text="%s"><summary><span class="sev sev-%s">%s</span> <b>%s</b> — %s</summary>`,
			esc(f.ID), esc(sev), esc(strings.ToLower(f.ID+" "+f.Title+" "+f.Location)), esc(sev), esc(f.Severity), esc(f.ID), esc(f.Title))
		rows.WriteString(`<dl>`)
		if f.GroupID != "" {
			fmt.Fprintf(&rows, `<dt>Remediation group</dt><dd><a href="#group-%s">%s</a></dd>`, esc(f.GroupID), esc(f.GroupID))
		}
		fmt.Fprintf(&rows, `<dt>CWE</dt><dd>%s</dd><dt>Location</dt><dd>%s</dd><dt>Entry point</dt><dd>%s</dd>`, esc(orNR(f.CWE)), esc(f.Location), esc(orNR(f.EntryPoint)))
		fmt.Fprintf(&rows, `<dt>Impact</dt><dd>%s</dd><dt>Attacker prerequisites</dt><dd>%s</dd><dt>Attacker control</dt><dd>%s</dd><dt>Source-to-sink reasoning</dt><dd>%s</dd><dt>Reviewed defenses</dt><dd>%s</dd><dt>Rationale</dt><dd>%s</dd>`,
			esc(orNR(f.Impact)), esc(orNR(f.Prerequisites)), esc(orNR(f.AttackerControl)), esc(orNR(f.SourceToSink)), esc(orNR(f.Defenses)), esc(orNR(f.Rationale)))
		if len(f.Evidence) == 0 {
			rows.WriteString(`<dt>Captured evidence</dt><dd>none (not verified)</dd>`)
		} else {
			fmt.Fprintf(&rows, `<dt>Captured evidence</dt><dd>%d excerpt(s)`, len(f.Evidence))
			for _, e := range f.Evidence {
				fmt.Fprintf(&rows, `<figure class="evidence"><figcaption><code>%s:%d-%d</code></figcaption><pre><code>%s</code></pre></figure>`, esc(e.Path), e.Start, e.End, esc(e.Quote))
			}
			rows.WriteString(`</dd>`)
		}
		if strings.TrimSpace(f.Fix) == "" {
			rows.WriteString(`<dt>Recommended fix</dt><dd>not provided</dd>`)
		} else {
			fmt.Fprintf(&rows, `<dt>Recommended fix</dt><dd>%s</dd>`, esc(f.Fix))
		}
		fmt.Fprintf(&rows, `<dt>Reproduction</dt><dd>%s</dd><dt>Classification</dt><dd>%s</dd></dl></details>`, esc(in.reproLine(f.ID)), esc(orNR(f.Classification)))
	}

	// Coverage and limitations.
	var cov strings.Builder
	fmt.Fprintf(&cov, `<h3>Scan summary</h3><p><b>Target:</b> %s &nbsp; <b>Model:</b> %s &nbsp; <b>Host:</b> %s`, esc(in.Target), esc(in.Model), esc(redactEndpoint(in.Host)))
	if m.Target.Revision != "" {
		fmt.Fprintf(&cov, ` &nbsp; <b>Revision:</b> %s`, esc(m.Target.Revision))
	}
	fmt.Fprintf(&cov, `<br><b>Started:</b> %s &nbsp; <b>Finished:</b> %s &nbsp; <b>Duration:</b> %s</p>`, esc(in.StartedAt), esc(in.FinishedAt), esc(in.Duration))
	fmt.Fprintf(&cov, `<h3>Run status (three axes)</h3><p class="axes"><span><b>Execution:</b> %s</span><span><b>Coverage:</b> %s</span><span><b>Validation:</b> %s</span></p>`, esc(rs.ExecutionStatus), esc(rs.CoverageStatus), esc(rs.ValidationMode))
	if len(rs.CoverageDegradedReasons) > 0 {
		cov.WriteString(`<ul class="degraded">`)
		for _, r := range rs.CoverageDegradedReasons {
			fmt.Fprintf(&cov, `<li>%s</li>`, esc(r))
		}
		cov.WriteString(`</ul>`)
	}
	cov.WriteString(sourceReviewHTML(m))
	cov.WriteString(failuresHTML(in))
	if m.DiagramSummary != "" {
		fmt.Fprintf(&cov, `<h3>Threat model diagram</h3><p><b>Validation</b> (<a href="threat_model_diagram.json">threat_model_diagram.json</a>): %s</p>`, esc(m.DiagramSummary))
	}
	cov.WriteString(completionHTML(in) + reviewCoverageHTML(in))
	cov.WriteString(`<h3>Scope and limitations</h3><ul>`)
	if !in.CodeExecuted {
		cov.WriteString("<li>The target's code was <b>never executed</b>; findings are confirmed by reasoning, not by execution.</li>")
	}
	if !in.VerifyModelUsed {
		cov.WriteString("<li>Falsification ran on the <b>same model</b> that produced the candidates.</li>")
	}
	cov.WriteString("<li>No network egress beyond the configured inference endpoint.</li></ul>")

	// Appendix A — candidates.
	var appA strings.Builder
	candList := func(title, note string, fs []CandidateRow, status string) {
		fmt.Fprintf(&appA, `<h3>%s (%d)</h3><p class="muted">%s</p>`, esc(title), len(fs), esc(note))
		if len(fs) == 0 {
			appA.WriteString(`<p class="muted">None.</p>`)
			return
		}
		appA.WriteString(`<ul class="unsupported">`)
		for _, r := range fs {
			fmt.Fprintf(&appA, `<li class="cand" data-status="%s" data-text="%s"><b>%s</b> — %s <span class="muted">(%s)</span> · %s · <i>action: %s</i></li>`,
				esc(status), esc(strings.ToLower(r.ID+" "+r.Title+" "+r.Location)), esc(r.ID), esc(r.Title), esc(r.Location), esc(r.Reason), esc(r.Action))
		}
		appA.WriteString(`</ul>`)
	}
	candList("Rejected candidates", "Reviewed and refuted — not vulnerabilities.", m.Appendix.Rejected, "rejected")
	candList("Unresolved (explicit decision)", "The verifier examined these and submitted unresolved: evidence of uncertainty, not confirmation.", m.Appendix.UnresolvedExplicit, "unresolved_explicit")
	fmt.Fprintf(&appA, `<h3>Unresolved (session failed) (%d)</h3><p class="muted">No decision was recorded: the verification session failed. Investigate the failure class before treating these as noise.</p>`, len(m.Appendix.UnresolvedFailed))
	if len(m.Appendix.UnresolvedFailed) == 0 {
		appA.WriteString(`<p class="muted">None.</p>`)
	} else {
		appA.WriteString(`<ul class="unsupported">`)
		for _, r := range m.Appendix.UnresolvedFailed {
			fmt.Fprintf(&appA, `<li class="cand" data-status="unresolved_failed" data-text="%s"><b>%s</b> — %s <span class="muted">(%s)</span> · <code>%s</code> operation: %s; code: %s · %s</li>`,
				esc(strings.ToLower(r.ID+" "+r.Title+" "+r.Location)), esc(r.ID), esc(r.Title), esc(r.Location), esc(orText(r.Class, "unknown")), esc(orText(r.Operation, "unknown")), esc(orText(r.Code, "not recorded")), esc(r.Message))
		}
		appA.WriteString(`</ul>`)
	}

	// Appendix B — execution (per-agent rows on demand).
	var appB strings.Builder
	if len(m.Appendix.Phases) > 0 {
		appB.WriteString(`<h3>Phases</h3><table><tr><th>Phase</th><th>Agents</th><th>Turns</th><th>Stop reasons</th><th>Produced</th><th>Prompt tok</th><th>Completion tok</th></tr>`)
		for _, p := range m.Appendix.Phases {
			prod := "no"
			if p.Produced {
				prod = "yes"
			}
			fmt.Fprintf(&appB, `<tr><td>%s</td><td>%d</td><td>%d</td><td>%s</td><td>%s</td><td>%d</td><td>%d</td></tr>`, esc(p.Phase), p.Agents, p.Turns, esc(stopsText(p.Stops)), prod, p.PromptTokens, p.CompletionTokens)
		}
		appB.WriteString(`</table>`)
	}
	if outcomes := phaseOutcomes(in); len(outcomes) > 0 {
		fmt.Fprintf(&appB, `<details class="agents"><summary>Per-phase outcome — %d agent row(s) (also in <code>%s</code>)</summary><table><tr><th>Phase</th><th>Agent</th><th>Turns</th><th>Stop reason</th><th>Produced</th><th>Prompt tok</th><th>Completion tok</th></tr>`, len(outcomes), esc(m.Appendix.AgentsRef))
		for _, o := range outcomes {
			prod := "no"
			if o.Produced {
				prod = "yes"
			}
			fmt.Fprintf(&appB, `<tr><td>%s</td><td>%s</td><td>%d</td><td>%s</td><td>%s</td><td>%d</td><td>%d</td></tr>`, esc(o.Phase), esc(o.Label), o.Turns, esc(o.Stop), prod, o.PT, o.CT)
		}
		appB.WriteString(`</table></details>`)
	}
	fmt.Fprintf(&appB, `<p class="muted">Artifact records: <code>%s</code>. Evidence records: <code>%s</code>, <code>%s</code>, <code>%s</code>.</p>`, esc(m.Appendix.ArtifactsRef), esc(m.Refs["review_units"]), esc(m.Refs["hunt_execution"]), esc(m.Refs["sessions"]))

	return fmt.Sprintf(htmlShell,
		esc(in.Target), esc(in.FinishedAt), esc(in.Target),
		bannerHTML, sum.String(), tiles.String(), metrics.String(), index.String(), rows.String(), cov.String(), appA.String(), appB.String())
}

// htmlShell is the single-file page: inline CSS/JS only (no external requests),
// print stylesheet (light palette, expanded details, page breaks, export scope
// header), filter/search over every row with a disclosure banner.
const htmlShell = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Scan Report — %s (%s)</title>
<style>
:root{--bg:#fff;--fg:#1a1a1a;--muted:#666;--card:#f5f5f5;--line:#e0e0e0;
--crit:#b3153a;--high:#ec835a;--medplus:#ec835a;--med:#fab219;--low:#9aa0a6;--info:#9aa0a6}
@media(prefers-color-scheme:dark){:root:not([data-theme=light]){--bg:#161616;--fg:#eee;--muted:#aaa;--card:#222;--line:#333}}
:root[data-theme=dark]{--bg:#161616;--fg:#eee;--muted:#aaa;--card:#222;--line:#333}
body{margin:0;font:14px/1.5 system-ui,sans-serif;background:var(--bg);color:var(--fg)}
.wrap{max-width:960px;margin:0 auto;padding:24px 16px}
h1{font-size:1.5rem}h2{font-size:1.1rem;border-bottom:1px solid var(--line);padding-bottom:4px;margin-top:28px}h3{font-size:1rem;margin-top:20px}
.tiles{display:flex;flex-wrap:wrap;gap:8px;margin:16px 0}
.tile{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:10px 14px;min-width:80px}
.tn{font-size:1.4rem;font-weight:700}.tl{color:var(--muted);font-size:.8rem}
.axes span{display:inline-block;margin-right:16px}.muted{color:var(--muted)}
.finding{border:1px solid var(--line);border-radius:6px;margin:8px 0;padding:8px 12px;background:var(--card)}
.finding summary{cursor:pointer}
dl{display:grid;grid-template-columns:140px 1fr;gap:2px 12px;margin:8px 0 0}
dt{color:var(--muted)}
figure.evidence{margin:6px 0}figure.evidence pre{background:var(--bg);border:1px solid var(--line);padding:6px;overflow:auto;white-space:pre-wrap}
.sev{font-weight:700;padding:0 6px;border-radius:4px}
.sev-critical{color:var(--crit)}.sev-high\+{color:var(--high)}.sev-high{color:var(--high)}.sev-medium{color:var(--med)}
.controls{margin:12px 0;display:flex;flex-wrap:wrap;gap:8px;align-items:center}
#banner{display:none;background:#fde68a;color:#111;padding:8px;border-radius:6px;margin:8px 0}
.broken{background:#fde68a;color:#111;padding:10px 12px;border-radius:6px;margin:12px 0;border:1px solid #d9a800}
table{border-collapse:collapse;width:100%%;margin:8px 0;font-size:.9rem}
th,td{border:1px solid var(--line);padding:4px 8px;text-align:left;vertical-align:top}
tr.idx:focus{outline:2px solid #2563eb}
tr.idx[data-role="occurrence"] td:nth-child(2){padding-left:22px}.occ{color:var(--muted)}
.printhdr{display:none}
@media print{
 :root{--bg:#fff;--fg:#000;--card:#fff}
 .controls{display:none}.printhdr{display:block;font-size:.8rem;color:#333;border-bottom:1px solid #999;margin-bottom:8px}
 details{display:block}details>*{display:revert}
 .finding,.cand,tr{break-inside:avoid}h2{break-before:page}h2:first-of-type{break-before:auto}
 pre{white-space:pre-wrap}
 .sev{-webkit-print-color-adjust:exact;print-color-adjust:exact}
 body[data-scope=summary] #findings,body[data-scope=summary] #coverage,body[data-scope=summary] #appendix-a,body[data-scope=summary] #appendix-b,body[data-scope=summary] #findings-h,body[data-scope=summary] #coverage-h,body[data-scope=summary] #appendix-a-h,body[data-scope=summary] #appendix-b-h{display:none}
}
</style></head>
<body data-scope="full"><div class="wrap">
<div class="printhdr" id="printhdr"></div>
<h1>Security Scan Report — %s</h1>
%s
<h2>Executive summary</h2>
%s
<h2>Outcome metrics</h2>
<div class="tiles">%s</div>
%s
<h2 id="findings-index">Findings index</h2>
<div class="controls">
 <label>Search: <input id="q" type="search" oninput="applyFilter()" placeholder="id, title, surface"></label>
 <label>Severity:
  <select id="sevFilter" onchange="applyFilter()">
   <option value="">all</option><option>critical</option><option>high+</option><option>high</option><option>medium</option><option>low</option><option>informational</option><option>unrated</option>
  </select></label>
 <label>Status:
  <select id="statusFilter" onchange="applyFilter()">
   <option value="">all</option><option value="supported">supported</option><option value="rejected">rejected</option><option value="unresolved_explicit">unresolved (explicit)</option><option value="unresolved_failed">unresolved (failed)</option>
  </select></label>
 <label>Export scope:
  <select id="scope" onchange="setScope()"><option value="full">full</option><option value="summary">summary</option></select></label>
 <button onclick="expandAll()">Expand all</button>
 <button onclick="window.print()">Save as PDF</button>
</div>
<div id="banner"></div>
%s
<h2 id="findings-h">Findings</h2>
<div id="findings">%s</div>
<h2 id="coverage-h">Coverage and limitations</h2>
<div id="coverage">%s</div>
<h2 id="appendix-a-h">Appendix A — Candidates</h2>
<div id="appendix-a">%s</div>
<h2 id="appendix-b-h">Appendix B — Execution</h2>
<div id="appendix-b">%s</div>
</div>
<script>
function applyFilter(){var v=document.getElementById('sevFilter').value,st=document.getElementById('statusFilter').value,q=(document.getElementById('q').value||'').toLowerCase();var n=0,shown=0;
 document.querySelectorAll('.idx,.finding,.cand').forEach(function(el){n++;var ok=(!v||el.dataset.sev===v)&&(!st||el.dataset.status===st)&&(!q||(el.dataset.text||'').indexOf(q)>=0);el.hidden=!ok;if(ok)shown++;});
 var b=document.getElementById('banner');var active=v||st||q;
 if(active){b.style.display='block';b.textContent='Filtered view — showing '+shown+' of '+n+' rows (severity: '+(v||'all')+', status: '+(st||'all')+(q?', search: "'+q+'"':'')+')';}else{b.style.display='none';}
 updatePrintHeader();}
function setScope(){document.body.dataset.scope=document.getElementById('scope').value;updatePrintHeader();}
function updatePrintHeader(){var h=document.getElementById('printhdr');var b=document.getElementById('banner');h.textContent='Export scope: '+document.body.dataset.scope+(b.style.display==='block'?' · '+b.textContent:' · no filter active');}
function expandAll(){document.querySelectorAll('details.finding').forEach(function(el){el.open=true;});}
window.addEventListener('beforeprint',function(){expandAll();updatePrintHeader();});
document.addEventListener('keydown',function(e){if((e.key==='Enter'||e.key===' ')&&e.target.classList&&e.target.classList.contains('idx')){var a=e.target.querySelector('a');if(a){e.preventDefault();location.hash=a.getAttribute('href');var d=document.getElementById(a.getAttribute('href').slice(1));if(d&&d.tagName==='DETAILS')d.open=true;}}});
try{var k='vhlocal.report.pos.'+location.pathname;var saved=sessionStorage.getItem(k);if(saved)window.scrollTo(0,parseInt(saved,10));window.addEventListener('scroll',function(){sessionStorage.setItem(k,String(window.scrollY));});}catch(e){}
updatePrintHeader();
</script>
</body></html>`
