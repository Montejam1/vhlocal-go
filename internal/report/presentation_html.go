package report

import (
	"fmt"
	"html"
	"strings"
)

// Feature 016 (US1): the standalone HTML document, rendered from the same presentation
// projection as the Markdown so the two cannot disagree on a count, an order or a label.
// One self-contained file: inline CSS and JS only, no external request, print styles kept.

func renderHTMLPresentation(in Input, m ReportModel) string {
	p := m.Presentation
	esc := html.EscapeString

	// Identity and the one-line honesty note.
	var ident strings.Builder
	fmt.Fprintf(&ident, `<p class="identity"><b>Application:</b> %s`, esc(p.Identity.Application))
	if p.Identity.ScanDate != "" {
		when := p.Identity.ScanDate
		if p.Identity.Timezone != "" {
			when += " (" + p.Identity.Timezone + ")"
		}
		fmt.Fprintf(&ident, ` &nbsp; <b>Scanned:</b> %s`, esc(when))
	} else {
		ident.WriteString(` &nbsp; <b>Scanned:</b> date not recorded`)
	}
	if p.Identity.Revision != "" {
		fmt.Fprintf(&ident, ` &nbsp; <b>Revision:</b> %s`, esc(shortRev(p.Identity.Revision)))
	}
	ident.WriteString(`</p>`)
	if scopeIsIncomplete(p.Scope) {
		ident.WriteString(`<div class="broken">⚠ <b>This assessment is not exhaustive.</b> The results below cover the code that was reviewed; <a href="#scan-details">Scan details</a> records what was not.</div>`)
	}

	// Executive summary: bounded prose, then the totals as tiles and a table.
	var sum strings.Builder
	fmt.Fprintf(&sum, `<p class="narrative">%s</p>`, esc(p.Opening.RiskSummary))
	if p.Opening.ScopeSentence != "" {
		fmt.Fprintf(&sum, `<p class="scope">%s</p>`, esc(p.Opening.ScopeSentence))
	}
	sum.WriteString(`<div class="tiles">`)
	fmt.Fprintf(&sum, `<div class="tile"><div class="tn">%d</div><div class="tl">Issues to fix</div></div>`, p.Counts.IssuesToFix)
	for _, s := range DisplaySeverities {
		fmt.Fprintf(&sum, `<div class="tile"><div class="tn sev sev-%s">%d</div><div class="tl">%s</div></div>`,
			esc(strings.ToLower(s)), p.Counts.Severity[s], esc(s))
	}
	fmt.Fprintf(&sum, `<div class="tile"><div class="tn">%d</div><div class="tl">Needs review</div></div>`, p.Counts.NeedsReview)
	fmt.Fprintf(&sum, `<div class="tile"><div class="tn">%d</div><div class="tl">Dismissed</div></div>`, p.Counts.Dismissed)
	sum.WriteString(`</div><p class="muted">Needs review and dismissed candidates are counted separately and are never part of the issues to fix.</p>`)

	// Priority actions.
	var prio strings.Builder
	if len(p.Priority) == 0 {
		prio.WriteString(`<p class="muted">No established issue requires a fix. Needs review and Scan details record what remains open.</p>`)
	} else {
		prio.WriteString(`<table><thead><tr><th>#</th><th>Issue</th><th>Severity</th><th>Affected area</th><th>Next action</th></tr></thead><tbody>`)
		for i, a := range p.Priority {
			fmt.Fprintf(&prio, `<tr><td>%d</td><td><a href="#%s">%s</a></td><td><span class="sev sev-%s">%s</span></td><td>%s</td><td>%s</td></tr>`,
				i+1, esc(strings.ToLower(a.Ref)), esc(a.Issue), esc(strings.ToLower(a.Severity)), esc(a.Severity), esc(a.AffectedArea), esc(a.Action))
		}
		prio.WriteString(`</tbody></table>`)
	}

	// The vulnerability index: filterable, keyboard-focusable, one row per issue.
	var index strings.Builder
	if len(p.Issues) == 0 {
		index.WriteString(`<p class="muted">None established in the reviewed code.</p>`)
	} else {
		index.WriteString(`<table id="index"><thead><tr><th>#</th><th>Severity</th><th>Issue</th><th>Affected</th><th>Recommended action</th></tr></thead><tbody>`)
		for i, is := range p.Issues {
			fmt.Fprintf(&index, `<tr class="idx" tabindex="0" data-sev="%s" data-text="%s"><td>%d</td><td><span class="sev sev-%s">%s</span></td><td><a href="#%s">%s</a></td><td>%s</td><td>%s</td></tr>`,
				esc(strings.ToLower(is.Severity)), esc(strings.ToLower(is.Title+" "+affectedSummary(is))),
				i+1, esc(strings.ToLower(is.Severity)), esc(is.Severity), esc(strings.ToLower(is.Ref)), esc(is.Title),
				esc(affectedSummary(is)), esc(primaryAction(is)))
		}
		index.WriteString(`</tbody></table>`)
	}

	// Issue details: one collapsed block per primary issue, never one per detection.
	var details strings.Builder
	for _, is := range p.Issues {
		details.WriteString(issueDetailHTML(is))
	}
	if len(p.Issues) == 0 {
		details.WriteString(`<p class="muted">No issue details, because no issue was established in the reviewed code.</p>`)
	}

	return fmt.Sprintf(presentationShell,
		esc(p.Identity.Application), esc(orNR(in.FinishedAt)), esc(p.Identity.Application),
		ident.String(), sum.String(), prio.String(), index.String(), details.String(),
		needsReviewHTML(m), scanDetailsHTML(in, m), dismissedHTML(m))
}

// issueDetailHTML renders one primary issue, keeping every existing deep link working:
// the issue reference, the recorded group id and each backing detection id.
func issueDetailHTML(is PrimaryIssue) string {
	esc := html.EscapeString
	var b strings.Builder
	fmt.Fprintf(&b, `<details class="issue" id="%s" data-sev="%s" data-text="%s" open>`,
		esc(strings.ToLower(is.Ref)), esc(strings.ToLower(is.Severity)), esc(strings.ToLower(is.Title)))
	fmt.Fprintf(&b, `<summary><span class="sev sev-%s">%s</span> <b>%s</b></summary>`,
		esc(strings.ToLower(is.Severity)), esc(is.Severity), esc(is.Title))
	if is.GroupID != "" {
		fmt.Fprintf(&b, `<span id="group-%s"></span>`, esc(is.GroupID))
	}
	for _, mem := range is.Members {
		fmt.Fprintf(&b, `<span id="finding-%s"></span>`, esc(mem.FindingID))
	}

	// 1. What we found, with the context that belongs beside the claim (FR-012, C-P18).
	fmt.Fprintf(&b, `<h4>What we found</h4><p>%s</p><dl>`, esc(is.WhatWeFound))
	if is.CWE != "" || is.CanonicalName != "" {
		fmt.Fprintf(&b, `<dt>Weakness</dt><dd>%s</dd>`, esc(weaknessText(is)))
	}
	if is.AccessRequired != "" {
		fmt.Fprintf(&b, `<dt>Access required</dt><dd>%s</dd>`, esc(is.AccessRequired))
	}
	if is.AttackerControl != "" {
		fmt.Fprintf(&b, `<dt>What an attacker controls</dt><dd>%s</dd>`, esc(is.AttackerControl))
	}
	if is.SafeguardsReviewed != "" {
		fmt.Fprintf(&b, `<dt>Safeguards reviewed</dt><dd>%s</dd>`, esc(is.SafeguardsReviewed))
	}
	if len(is.OriginalSeverities) > 0 {
		fmt.Fprintf(&b, `<dt>Recorded rating</dt><dd>%s (shown as %s)</dd>`, esc(strings.Join(is.OriginalSeverities, ", ")), esc(is.Severity))
	}
	b.WriteString(`</dl>`)

	// 2. Why it matters.
	fmt.Fprintf(&b, `<h4>Why it matters</h4><p>%s</p>`, esc(is.WhyItMatters))

	// 3. Where it is: one entry per deduplicated location (FR-013, C-P15).
	b.WriteString(`<h4>Where it is</h4><ul>`)
	if len(is.Locations) == 0 {
		b.WriteString(`<li>the affected location was not recorded</li>`)
	}
	for _, l := range is.Locations {
		fmt.Fprintf(&b, `<li><code>%s</code>`, esc(locationText(l)))
		if l.CitationCount > 1 {
			fmt.Fprintf(&b, ` — cited by %d detections`, l.CitationCount)
		}
		if l.EntryPoint != "" {
			fmt.Fprintf(&b, ` · reached through %s`, esc(l.EntryPoint))
		}
		b.WriteString(`</li>`)
	}
	if len(is.EntryPoints) > 0 {
		fmt.Fprintf(&b, `<li>Entry points: %s</li>`, esc(strings.Join(is.EntryPoints, ", ")))
	}
	b.WriteString(`</ul>`)

	// 4. How to fix it, with its provenance disclosed (FR-014, C-R2, C-R3).
	b.WriteString(`<h4>How to fix it</h4>`)
	if is.HowToFixIt.Label != "" {
		fmt.Fprintf(&b, `<p class="muted">%s</p>`, esc(is.HowToFixIt.Label))
	}
	b.WriteString(`<ol>`)
	for _, s := range is.HowToFixIt.Steps {
		fmt.Fprintf(&b, `<li>%s</li>`, esc(s))
	}
	b.WriteString(`</ol>`)
	if is.HowToFixIt.MissingDecision != "" {
		fmt.Fprintf(&b, `<p><b>Decision this needs from you:</b> %s</p>`, esc(is.HowToFixIt.MissingDecision))
	}
	if is.HowToFixIt.RecordedNote != "" {
		fmt.Fprintf(&b, `<p><b>Recorded recommendation, kept for reference:</b> %s</p>`, esc(is.HowToFixIt.RecordedNote))
	}

	// 5. How to check the fix. These are suggestions; none has been run.
	b.WriteString(`<h4>How to check the fix</h4><ul>`)
	if len(is.HowToCheckTheFix) == 0 {
		b.WriteString(`<li>no check is suggested for this weakness class; decide one from the change you make</li>`)
	}
	for _, chk := range is.HowToCheckTheFix {
		fmt.Fprintf(&b, `<li>%s</li>`, esc(chk))
	}
	b.WriteString(`</ul>`)

	// Optional detail: provenance and the captured evidence.
	b.WriteString(`<h4>Technical evidence</h4><dl>`)
	fmt.Fprintf(&b, `<dt>Established by</dt><dd>%s</dd>`, esc(detectionList(is)))
	if is.GroupingNote != "" {
		fmt.Fprintf(&b, `<dt>Grouping</dt><dd>%s</dd>`, esc(is.GroupingNote))
	}
	if len(is.Evidence) == 0 {
		b.WriteString(`<dt>Captured evidence</dt><dd>none recorded</dd>`)
	} else {
		fmt.Fprintf(&b, `<dt>Captured evidence</dt><dd>%d excerpt(s)`, len(is.Evidence))
		for _, e := range is.Evidence {
			fmt.Fprintf(&b, `<figure class="evidence"><figcaption><code>%s:%d-%d</code></figcaption><pre><code>%s</code></pre></figure>`,
				esc(e.Path), e.Start, e.End, esc(e.Quote))
		}
		b.WriteString(`</dd>`)
	}
	b.WriteString(`</dl></details>`)
	return b.String()
}

func needsReviewHTML(m ReportModel) string {
	p := m.Presentation
	esc := html.EscapeString
	var b strings.Builder
	if len(p.ReviewItems) == 0 {
		return `<p class="muted">Nothing is awaiting review for this scan.</p>`
	}
	fmt.Fprintf(&b, `<p class="muted">%s could not be settled either way: neither confirmed nor dismissed. None is counted among the issues to fix, and none carries an assessed severity.</p>`,
		esc(plural(len(p.ReviewItems), "item", "items")))
	group := func(kind, heading, note string) {
		var rows []ReviewItem
		for _, it := range p.ReviewItems {
			if it.Kind == kind {
				rows = append(rows, it)
			}
		}
		if len(rows) == 0 {
			return
		}
		fmt.Fprintf(&b, `<h3>%s</h3><p class="muted">%s</p><ul class="review">`, esc(heading), esc(note))
		for _, it := range rows {
			fmt.Fprintf(&b, `<li class="rev" data-text="%s"><b>%s</b> — %s`,
				esc(strings.ToLower(it.Title+" "+it.Location)), esc(it.Title), esc(it.WhatIsUnresolved))
			if it.Location != "" {
				fmt.Fprintf(&b, ` · location: <code>%s</code>`, esc(it.Location))
			}
			if it.ProvisionalSeverity != "" {
				fmt.Fprintf(&b, ` · severity proposed, not established: %s`, esc(it.ProvisionalSeverity))
			}
			fmt.Fprintf(&b, ` · next step: %s`, esc(it.NextStep))
			if it.DiagnosticsRef != "" {
				fmt.Fprintf(&b, ` · diagnostics: %s`, esc(it.DiagnosticsRef))
			}
			b.WriteString(`</li>`)
		}
		b.WriteString(`</ul>`)
	}
	group(ReviewInconclusive, "Inconclusive", "examined, with no decision either way")
	group(ReviewIncomplete, "Assessment not completed", "the review stopped before reaching a decision")
	return b.String()
}

func dismissedHTML(m ReportModel) string {
	p := m.Presentation
	esc := html.EscapeString
	var b strings.Builder
	b.WriteString(`<p class="muted">Examined and refuted. Kept here with the reason recorded at the time; a dismissal is never re-decided by the report.</p>`)
	if len(p.Dismissed) == 0 {
		b.WriteString(`<p class="muted">None.</p>`)
		return b.String()
	}
	b.WriteString(`<ul class="dismissed">`)
	for _, d := range p.Dismissed {
		fmt.Fprintf(&b, `<li class="dis" data-text="%s"><b>%s</b>`, esc(strings.ToLower(d.Title+" "+d.Location)), esc(d.Title))
		if d.Location != "" {
			fmt.Fprintf(&b, ` (<code>%s</code>)`, esc(d.Location))
		}
		fmt.Fprintf(&b, ` — %s · recorded decision: %s</li>`, esc(d.Reason), esc(d.Decision))
	}
	b.WriteString(`</ul>`)
	return b.String()
}

// scanDetailsHTML is the operator section: the same facts as the Markdown, collapsed by
// default so they do not compete with the vulnerability content (FR-001, FR-003).
func scanDetailsHTML(in Input, m ReportModel) string {
	p := m.Presentation
	rs := in.Doc.RunStatus
	esc := html.EscapeString
	var b strings.Builder
	b.WriteString(`<p class="muted">Scanner troubleshooting and provenance. Nothing here changes the issue counts above.</p>`)
	fmt.Fprintf(&b, `<h3>Scan summary</h3><p><b>Target:</b> %s &nbsp; <b>Model:</b> %s &nbsp; <b>Inference endpoint:</b> %s`,
		esc(in.Target), esc(orNR(in.Model)), esc(orNR(redactEndpoint(in.Host))))
	if m.Target.Revision != "" {
		fmt.Fprintf(&b, ` &nbsp; <b>Revision:</b> %s`, esc(m.Target.Revision))
	}
	fmt.Fprintf(&b, `<br><b>Started:</b> %s &nbsp; <b>Finished:</b> %s &nbsp; <b>Duration:</b> %s</p>`,
		esc(orNR(in.StartedAt)), esc(orNR(in.FinishedAt)), esc(orNR(in.Duration)))
	if pl := partitionLine(in.Doc.Meta); pl != "" {
		fmt.Fprintf(&b, `<p>%s</p>`, esc(pl))
	}

	fmt.Fprintf(&b, `<h3>Run status (three independent axes)</h3><p class="axes"><span><b>Execution:</b> %s</span><span><b>Coverage:</b> %s</span><span><b>Assessment method:</b> %s</span></p><p class="muted">The raw recorded values are under Technical diagnostics.</p>`,
		esc(p.Scope.Execution), esc(orNR(rs.CoverageStatus)), esc(p.Scope.Method))
	if len(rs.CoverageDegradedReasons) > 0 {
		b.WriteString(`<ul class="degraded">`)
		for _, r := range rs.CoverageDegradedReasons {
			fmt.Fprintf(&b, `<li>%s</li>`, esc(r))
		}
		b.WriteString(`</ul>`)
	}

	c := p.Counts
	b.WriteString(`<h3>Accounting</h3><ul class="metrics">`)
	fmt.Fprintf(&b, `<li><b>Candidates examined</b>: %d — allegations the scan looked at; not a count of established defects</li>`, c.CandidatesExamined)
	fmt.Fprintf(&b, `<li><b>Supported detections</b>: %d — individual detections that survived review; one defect cited in several places is still one issue</li>`, c.Detections)
	fmt.Fprintf(&b, `<li><b>Issues to fix</b>: %d — the established defects reported above</li>`, c.IssuesToFix)
	fmt.Fprintf(&b, `<li><b>Needs review</b>: %d — %d inconclusive, %d where review did not finish</li>`, c.NeedsReview, c.NeedsInconclusive, c.NeedsIncomplete)
	fmt.Fprintf(&b, `<li><b>Dismissed</b>: %d</li>`, c.Dismissed)
	if m.Counts.Duplicates > 0 {
		fmt.Fprintf(&b, `<li><b>Duplicate detections folded</b>: %d</li>`, m.Counts.Duplicates)
	}
	b.WriteString(`</ul>`)

	if len(p.GroupingNotes) > 0 {
		b.WriteString(`<h3>Grouping</h3><p class="muted">Recorded remediation groups that are not one of the issues above, and why.</p><ul>`)
		for _, n := range p.GroupingNotes {
			fmt.Fprintf(&b, `<li>%s</li>`, esc(n))
		}
		b.WriteString(`</ul>`)
	}

	b.WriteString(sourceReviewHTML(m))
	b.WriteString(reviewCoverageHTML(in))

	b.WriteString(`<h3>Scope and limitations</h3><ul>`)
	if !in.CodeExecuted {
		b.WriteString(`<li>The target's code was <b>never executed</b>; issues are established by reading the source, not by running an exploit.</li>`)
	}
	if !in.VerifyModelUsed {
		b.WriteString(`<li>Falsification ran on the <b>same model</b> that produced the candidates.</li>`)
	}
	b.WriteString(`<li>No network egress beyond the configured inference endpoint.</li></ul>`)

	// Technical diagnostics (FR-019, C-C4, C-C5): collapsed here, and excluded from the
	// default print body by the stylesheet.
	b.WriteString(`<details id="technical-diagnostics" class="diagnostics"><summary>Technical diagnostics — scanner troubleshooting only</summary>`)
	b.WriteString(`<p class="muted">Nothing below changes a count, a severity or a decision above.</p>`)
	fmt.Fprintf(&b, `<h4>Recorded statuses</h4><ul class="metrics"><li><b>execution_status</b>: recorded as <code>%s</code></li><li><b>coverage_status</b>: recorded as <code>%s</code></li><li><b>validation_mode</b>: recorded as <code>%s</code></li><li><b>coverage semantics</b>: %s</li></ul>`,
		esc(orNR(rs.ExecutionStatus)), esc(orNR(rs.CoverageStatus)), esc(orNR(rs.ValidationMode)), esc(orNR(m.CoverageSemanticsLabel)))
	fmt.Fprintf(&b, `<h4>Provider and model</h4><ul class="metrics"><li><b>Model</b>: %s</li><li><b>Inference endpoint</b>: %s</li><li><b>Credentials</b>: never recorded in a report; any credential in the endpoint URL is redacted here</li><li><b>Falsification model</b>: %s</li></ul>`,
		esc(orNR(in.Model)), esc(orNR(redactEndpoint(in.Host))), esc(verifyModelText(in)))
	fmt.Fprintf(&b, `<h4>Configuration</h4><ul class="metrics"><li><b>Code execution</b>: %s</li><li><b>Separate falsification model</b>: %s</li>`,
		esc(codeExecutionText(in.CodeExecuted)), yesNo(in.VerifyModelUsed))
	if pl := partitionLine(in.Doc.Meta); pl != "" {
		fmt.Fprintf(&b, `<li>%s</li>`, esc(pl))
	}
	if phases := metaList(in.Doc.Meta, "phases_requested"); len(phases) > 0 {
		fmt.Fprintf(&b, `<li><b>Phases requested</b>: %s</li>`, esc(strings.Join(phases, ", ")))
	}
	if phases := metaList(in.Doc.Meta, "phases_completed"); len(phases) > 0 {
		fmt.Fprintf(&b, `<li><b>Phases completed</b>: %s</li>`, esc(strings.Join(phases, ", ")))
	}
	b.WriteString(`</ul>`)
	b.WriteString(failuresHTML(in))
	if m.DiagramSummary != "" {
		fmt.Fprintf(&b, `<h4>Threat model diagram</h4><p><b>Validation</b> (<a href="threat_model_diagram.json">threat_model_diagram.json</a>): %s</p>`, esc(m.DiagramSummary))
	}
	b.WriteString(completionHTML(in))

	if len(m.Appendix.UnresolvedFailed) > 0 {
		b.WriteString(`<h4>Unfinished verification sessions</h4><p class="muted">Each row is an assessment that did not reach a decision. The matching reader-facing entries are under Needs review.</p><ul class="unsupported">`)
		for _, r := range m.Appendix.UnresolvedFailed {
			fmt.Fprintf(&b, `<li><b>%s</b> — %s (<code>%s</code>) · <code>%s</code> operation: %s; code: %s · %s</li>`,
				esc(r.ID), esc(r.Title), esc(r.Location), esc(orText(r.Class, "unknown")),
				esc(orText(r.Operation, "unknown")), esc(orText(r.Code, "not recorded")), esc(r.Message))
		}
		b.WriteString(`</ul>`)
	}

	if len(m.Appendix.Phases) > 0 {
		b.WriteString(`<h4>Execution</h4><table><tr><th>Phase</th><th>Agents</th><th>Turns</th><th>Stop reasons</th><th>Produced</th><th>Prompt tok</th><th>Completion tok</th></tr>`)
		for _, ph := range m.Appendix.Phases {
			fmt.Fprintf(&b, `<tr><td>%s</td><td>%d</td><td>%d</td><td>%s</td><td>%s</td><td>%d</td><td>%d</td></tr>`,
				esc(ph.Phase), ph.Agents, ph.Turns, esc(stopsText(ph.Stops)), yesNo(ph.Produced), ph.PromptTokens, ph.CompletionTokens)
		}
		b.WriteString(`</table>`)
	}
	if outcomes := phaseOutcomes(in); len(outcomes) > 0 {
		fmt.Fprintf(&b, `<details class="agents"><summary>Per-phase outcome — %d agent row(s) (also in <code>%s</code>)</summary><table><tr><th>Phase</th><th>Agent</th><th>Turns</th><th>Stop reason</th><th>Produced</th><th>Prompt tok</th><th>Completion tok</th></tr>`,
			len(outcomes), esc(m.Appendix.AgentsRef))
		for _, o := range outcomes {
			fmt.Fprintf(&b, `<tr><td>%s</td><td>%s</td><td>%d</td><td>%s</td><td>%s</td><td>%d</td><td>%d</td></tr>`,
				esc(o.Phase), esc(o.Label), o.Turns, esc(o.Stop), yesNo(o.Produced), o.PT, o.CT)
		}
		b.WriteString(`</table></details>`)
	}
	b.WriteString(`</details>`)

	if len(in.Nav) > 0 {
		b.WriteString(`<h3>Related documents</h3><p class="nav">`)
		for i, n := range in.Nav {
			if i > 0 {
				b.WriteString(" · ")
			}
			fmt.Fprintf(&b, `<a href="%s">%s</a>`, esc(n.Path), esc(n.Label))
		}
		b.WriteString(`</p>`)
	}
	fmt.Fprintf(&b, `<p class="muted">Artifact records: <code>%s</code>. Evidence records: <code>%s</code>, <code>%s</code>, <code>%s</code>.</p>`,
		esc(m.Appendix.ArtifactsRef), esc(m.Refs["review_units"]), esc(m.Refs["hunt_execution"]), esc(m.Refs["sessions"]))
	return b.String()
}

// presentationShell is the single self-contained page: inline CSS and JS only, no
// external request, a print stylesheet that expands the collapsed sections, and a filter
// over the index and the issue details.
const presentationShell = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Scan Report — %s (%s)</title>
<style>
:root{--bg:#fff;--fg:#1a1a1a;--muted:#666;--card:#f5f5f5;--line:#e0e0e0;
--crit:#b3153a;--high:#ec835a;--med:#fab219;--low:#9aa0a6;--info:#9aa0a6;--unr:#9aa0a6}
@media(prefers-color-scheme:dark){:root:not([data-theme=light]){--bg:#161616;--fg:#eee;--muted:#aaa;--card:#222;--line:#333}}
:root[data-theme=dark]{--bg:#161616;--fg:#eee;--muted:#aaa;--card:#222;--line:#333}
body{margin:0;font:14px/1.5 system-ui,sans-serif;background:var(--bg);color:var(--fg)}
.wrap{max-width:960px;margin:0 auto;padding:24px 16px}
h1{font-size:1.5rem}h2{font-size:1.1rem;border-bottom:1px solid var(--line);padding-bottom:4px;margin-top:28px}h3{font-size:1rem;margin-top:20px}
.identity{color:var(--muted)}
.narrative{font-size:1.02rem}
.tiles{display:flex;flex-wrap:wrap;gap:8px;margin:16px 0}
.tile{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:10px 14px;min-width:80px}
.tn{font-size:1.4rem;font-weight:700}.tl{color:var(--muted);font-size:.8rem}
.axes span{display:inline-block;margin-right:16px}.muted{color:var(--muted)}
/* A recorded path, title or source line can be arbitrarily long and may contain no break
   opportunity. Break inside the cell rather than letting the page scroll sideways. */
td,dd,dt,li,p,summary,code,figcaption{overflow-wrap:anywhere;word-break:break-word}
.tablewrap{overflow:auto}
.issue{border:1px solid var(--line);border-radius:6px;margin:8px 0;padding:8px 12px;background:var(--card)}
.issue summary{cursor:pointer}
h4{font-size:.95rem;margin:14px 0 4px}
dl{display:grid;grid-template-columns:200px 1fr;gap:2px 12px;margin:8px 0 0}
dt{color:var(--muted)}
figure.evidence{margin:6px 0}figure.evidence pre{background:var(--bg);border:1px solid var(--line);padding:6px;overflow:auto;white-space:pre-wrap}
.sev{font-weight:700;padding:0 6px;border-radius:4px}
.sev-critical{color:var(--crit)}.sev-high{color:var(--high)}.sev-medium{color:var(--med)}
.sev-low{color:var(--low)}.sev-informational{color:var(--info)}.sev-unrated{color:var(--unr)}
.controls{margin:12px 0;display:flex;flex-wrap:wrap;gap:8px;align-items:center}
#banner{display:none;background:#fde68a;color:#111;padding:8px;border-radius:6px;margin:8px 0}
.broken{background:#fde68a;color:#111;padding:10px 12px;border-radius:6px;margin:12px 0;border:1px solid #d9a800}
table{border-collapse:collapse;width:100%%;margin:8px 0;font-size:.9rem}
th,td{border:1px solid var(--line);padding:4px 8px;text-align:left;vertical-align:top}
tr.idx:focus{outline:2px solid #2563eb}
.printhdr{display:none}
/* Readable on a narrow screen: the definition lists collapse to one column and the
   tables keep their own horizontal scroll rather than widening the page. */
@media(max-width:420px){.wrap{padding:16px 12px}dl{grid-template-columns:1fr}table{font-size:.85rem}.tiles{gap:6px}.tile{min-width:64px;padding:8px 10px}}
@media print{
 :root{--bg:#fff;--fg:#000;--card:#fff}
 .controls{display:none}.printhdr{display:block;font-size:.8rem;color:#333;border-bottom:1px solid #999;margin-bottom:8px}
 details{display:block}details>*{display:revert}
 .issue,.rev,.dis,tr{break-inside:avoid}h2{break-before:page}h2:first-of-type{break-before:auto}
 pre{white-space:pre-wrap}
 .sev{-webkit-print-color-adjust:exact;print-color-adjust:exact}
 body[data-scope=summary] #details,body[data-scope=summary] #needs-review,body[data-scope=summary] #scan-details,body[data-scope=summary] #dismissed,body[data-scope=summary] #details-h,body[data-scope=summary] #needs-review-h,body[data-scope=summary] #scan-details-h,body[data-scope=summary] #dismissed-h{display:none}
 /* Scanner troubleshooting is not part of the printed report unless an operator asks for
    it by choosing the diagnostics export scope. */
 #technical-diagnostics{display:none}
 body[data-scope=diagnostics] #technical-diagnostics{display:block}
}
</style></head>
<body data-scope="full"><div class="wrap">
<div class="printhdr" id="printhdr"></div>
<h1>Security Scan Report — %s</h1>
%s
<h2 id="summary-h">Summary</h2>
<div id="summary">%s</div>
<h2 id="priority-h">Priority actions</h2>
<div id="priority">%s</div>
<h2 id="issues-h">Issues to fix</h2>
<div class="controls">
 <label>Search: <input id="q" type="search" oninput="applyFilter()" placeholder="issue, file"></label>
 <label>Severity:
  <select id="sevFilter" onchange="applyFilter()">
   <option value="">all</option><option>critical</option><option>high</option><option>medium</option><option>low</option><option>informational</option><option>unrated</option>
  </select></label>
 <label>Export scope:
  <select id="scope" onchange="setScope()"><option value="full">full</option><option value="summary">summary</option><option value="diagnostics">full + diagnostics</option></select></label>
 <button onclick="expandAll()">Expand all</button>
 <button onclick="window.print()">Save as PDF</button>
</div>
<div id="banner"></div>
<div id="issues" class="issues-index">%s</div>
<h2 id="details-h">Issue details</h2>
<div id="details">%s</div>
<h2 id="needs-review-h">Needs review</h2>
<div id="needs-review">%s</div>
<h2 id="scan-details-h">Scan details</h2>
<details id="scan-details" class="scan"><summary>Scanner diagnostics and provenance</summary>%s</details>
<h2 id="dismissed-h">Dismissed candidates</h2>
<details id="dismissed" class="dismissed-section"><summary>Examined and refuted</summary>%s</details>
</div>
<script>
function applyFilter(){var v=document.getElementById('sevFilter').value,q=(document.getElementById('q').value||'').toLowerCase();var n=0,shown=0;
 document.querySelectorAll('.idx,.issue').forEach(function(el){n++;var ok=(!v||el.dataset.sev===v)&&(!q||(el.dataset.text||'').indexOf(q)>=0);el.hidden=!ok;if(ok)shown++;});
 var b=document.getElementById('banner');var active=v||q;
 if(active){b.style.display='block';b.textContent='Filtered view — showing '+shown+' of '+n+' rows (severity: '+(v||'all')+(q?', search: "'+q+'"':'')+')';}else{b.style.display='none';}
 updatePrintHeader();}
function setScope(){document.body.dataset.scope=document.getElementById('scope').value;updatePrintHeader();}
function updatePrintHeader(){var h=document.getElementById('printhdr');var b=document.getElementById('banner');h.textContent='Export scope: '+document.body.dataset.scope+(b.style.display==='block'?' · '+b.textContent:' · no filter active');}
function expandAll(){document.querySelectorAll('details').forEach(function(el){el.open=true;});}
window.addEventListener('beforeprint',function(){expandAll();updatePrintHeader();});
document.addEventListener('keydown',function(e){if((e.key==='Enter'||e.key===' ')&&e.target.classList&&e.target.classList.contains('idx')){var a=e.target.querySelector('a');if(a){e.preventDefault();location.hash=a.getAttribute('href');var d=document.getElementById(a.getAttribute('href').slice(1));if(d&&d.tagName==='DETAILS')d.open=true;}}});
try{var k='vhlocal.report.pos.'+location.pathname;var saved=sessionStorage.getItem(k);if(saved)window.scrollTo(0,parseInt(saved,10));window.addEventListener('scroll',function(){sessionStorage.setItem(k,String(window.scrollY));});}catch(e){}
updatePrintHeader();
</script>
</body></html>`
