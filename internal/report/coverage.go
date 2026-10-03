package report

import (
	"fmt"
	"html"
	"sort"
	"strings"
)

// Feature 015 (FR-015/019, T053): the "Source review coverage" block of
// "Coverage and limitations" — the semantics label first, then the axes as a
// table. Under v1 the only evidence is the read overlap, so the block says so and
// shows completed/total; under v2 every axis is listed and none is derived from
// another. Omitted when the run has no review-unit record.

// buildScopeNote carries the three independent status facts plus the completed-review
// coverage figure (feature 016, T026). The exposure axis is kept separate and never shown
// as reviewed, and unknown coverage stays unknown rather than being filled in from the
// discovered, assigned or attempted axes (FR-004, C-P8, C-P9).
func buildScopeNote(m *ReportModel) ScopeNote {
	sr := m.Counts.SourceReview
	n := ScopeNote{
		Execution:       plainExecution(m.Status.Execution),
		Method:          plainMethod(m.Status.ValidationMode),
		EntryPointGloss: "places where the application accepts input",
	}
	if sr.Total > 0 {
		n.CoverageKnown = true
		n.CoverageComplete, n.CoverageTotal, n.CoverageExposed = sr.Completed, sr.Total, sr.Exposed
		if sr.Completed < sr.Total {
			n.GapSentence = fmt.Sprintf("Review of the remaining %d was not completed; these results cover the reviewed code.", sr.Total-sr.Completed)
		}
	}
	return n
}

type axisRow struct {
	name, meaning string
	n             int
}

func axisRows(a *CoverageAxes) []axisRow {
	return []axisRow{
		{"Discovered", "entry points found by inventory", a.Discovered},
		{"Supported inventory", "entry points the inventory can locate in source", a.SupportedInventory},
		{"Assigned", "entry points a hunt partition covered", a.Assigned},
		{"Attempted", "entry points whose covering unit ran", a.Attempted},
		{"Source exposed", "entry points whose handler span a unit read (exposure, not review)", a.SourceExposed},
		{"Completed review", "entry points with a validated handler disposition or an in-span finding", a.CompletedReview},
		{"Verified", "entry points with a finding that reached verification", a.Verified},
	}
}

func sourceReviewMarkdown(m ReportModel) string {
	sr := m.Counts.SourceReview
	if sr.Total == 0 && sr.Axes == nil {
		return ""
	}
	var b strings.Builder
	b.WriteString("### Source review coverage\n\n")
	fmt.Fprintf(&b, "- **Evidence standard**: %s\n", orNR(m.CoverageSemanticsLabel))
	fmt.Fprintf(&b, "- **Completed review**: %d of %d entry points\n", sr.Completed, sr.Total)
	if sr.Axes == nil {
		b.WriteString("- **Source exposed**: under v1 semantics exposure equals completion (a read of the handler span was the review evidence); no separate axis was recorded\n\n")
		return b.String()
	}
	fmt.Fprintf(&b, "- **Source exposed**: %d (reads are exposure only — never analysis credit)\n\n", sr.Exposed)
	b.WriteString("| Axis | Count | Meaning |\n|---|---:|---|\n")
	for _, r := range axisRows(sr.Axes) {
		fmt.Fprintf(&b, "| %s | %d | %s |\n", r.name, r.n, r.meaning)
	}
	b.WriteString("\n_No axis is derived from another; a read without a validated disposition counts as exposure, not review._\n\n")
	return b.String()
}

func sourceReviewHTML(m ReportModel) string {
	sr := m.Counts.SourceReview
	if sr.Total == 0 && sr.Axes == nil {
		return ""
	}
	e := html.EscapeString
	var b strings.Builder
	fmt.Fprintf(&b, `<h3>Source review coverage</h3><p><b>Evidence standard:</b> %s &nbsp; <b>Completed review:</b> %d of %d entry points`, e(orNR(m.CoverageSemanticsLabel)), sr.Completed, sr.Total)
	if sr.Axes == nil {
		b.WriteString(`<br><span class="muted">Under v1 semantics exposure equals completion (a read of the handler span was the review evidence); no separate axis was recorded.</span></p>`)
		return b.String()
	}
	fmt.Fprintf(&b, ` &nbsp; <b>Source exposed:</b> %d <span class="muted">(reads are exposure only — never analysis credit)</span></p>`, sr.Exposed)
	b.WriteString(`<table class="axes-table"><thead><tr><th>Axis</th><th>Count</th><th>Meaning</th></tr></thead><tbody>`)
	for _, r := range axisRows(sr.Axes) {
		fmt.Fprintf(&b, `<tr><td>%s</td><td class="num">%d</td><td>%s</td></tr>`, e(r.name), r.n, e(r.meaning))
	}
	b.WriteString(`</tbody></table><p class="muted">No axis is derived from another; a read without a validated disposition counts as exposure, not review.</p>`)
	return b.String()
}

// Feature 015 (FR-026, C-C10): the verification-failure block of "Coverage and
// limitations". Occurrences, sessions and stop reasons are three different views of
// the same sessions and deliberately do not sum to each other, so the note saying
// so is rendered with them rather than left to the reader.

// failureRows orders the classes deterministically over both maps.
func failureRows(f FailureAggregates) []string {
	seen := map[string]bool{}
	for k := range f.OccurrencesByClass {
		seen[k] = true
	}
	for k := range f.SessionsByClass {
		seen[k] = true
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func stopRows(f FailureAggregates) []string {
	out := make([]string, 0, len(f.StopReasons))
	for k := range f.StopReasons {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func failuresMarkdown(in Input) string {
	f := in.Failures
	if f == nil || f.Sessions == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("### Verification failures\n\n")
	fmt.Fprintf(&b, "- **Sessions**: %d (%d tool call(s)/attempt(s) recorded in [%s](%s))\n", f.Sessions, f.Calls, verifyCallsRef, verifyCallsRef)
	if f.ExplicitUnresolved > 0 {
		fmt.Fprintf(&b, "- **Explicit `unresolved` decisions**: %d — a verifier judgement, not a failure\n", f.ExplicitUnresolved)
	}
	if f.AmendedSessions > 0 {
		fmt.Fprintf(&b, "- **Sessions that amended a citation**: %d\n", f.AmendedSessions)
	}
	rows := failureRows(*f)
	if len(rows) == 0 {
		b.WriteString("- No tool or submission failure was recorded in any session.\n\n")
		return b.String()
	}
	b.WriteString("\n| Failure class | Occurrences | Sessions affected |\n|---|---:|---:|\n")
	for _, k := range rows {
		fmt.Fprintf(&b, "| %s | %d | %d |\n", k, f.OccurrencesByClass[k], f.SessionsByClass[k])
	}
	if stops := stopRows(*f); len(stops) > 0 {
		b.WriteString("\n| Stop reason | Sessions |\n|---|---:|\n")
		for _, k := range stops {
			fmt.Fprintf(&b, "| %s | %d |\n", k, f.StopReasons[k])
		}
	}
	fmt.Fprintf(&b, "\n_%s_\n\n", orText(f.OverlapNote, defaultOverlapNote))
	return b.String()
}

func failuresHTML(in Input) string {
	f := in.Failures
	if f == nil || f.Sessions == 0 {
		return ""
	}
	e := html.EscapeString
	var b strings.Builder
	fmt.Fprintf(&b, `<h3>Verification failures</h3><p><b>Sessions:</b> %d &nbsp; <b>Calls recorded:</b> %d (<a href="%s">%s</a>)`, f.Sessions, f.Calls, verifyCallsRef, verifyCallsRef)
	if f.ExplicitUnresolved > 0 {
		fmt.Fprintf(&b, ` &nbsp; <b>Explicit unresolved:</b> %d <span class="muted">(a verifier judgement, not a failure)</span>`, f.ExplicitUnresolved)
	}
	if f.AmendedSessions > 0 {
		fmt.Fprintf(&b, ` &nbsp; <b>Amended citations:</b> %d`, f.AmendedSessions)
	}
	b.WriteString(`</p>`)
	rows := failureRows(*f)
	if len(rows) == 0 {
		b.WriteString(`<p class="muted">No tool or submission failure was recorded in any session.</p>`)
		return b.String()
	}
	b.WriteString(`<table class="axes-table"><thead><tr><th>Failure class</th><th>Occurrences</th><th>Sessions affected</th></tr></thead><tbody>`)
	for _, k := range rows {
		fmt.Fprintf(&b, `<tr><td>%s</td><td class="num">%d</td><td class="num">%d</td></tr>`, e(k), f.OccurrencesByClass[k], f.SessionsByClass[k])
	}
	b.WriteString(`</tbody></table>`)
	if stops := stopRows(*f); len(stops) > 0 {
		b.WriteString(`<table class="axes-table"><thead><tr><th>Stop reason</th><th>Sessions</th></tr></thead><tbody>`)
		for _, k := range stops {
			fmt.Fprintf(&b, `<tr><td>%s</td><td class="num">%d</td></tr>`, e(k), f.StopReasons[k])
		}
		b.WriteString(`</tbody></table>`)
	}
	fmt.Fprintf(&b, `<p class="muted">%s</p>`, e(orText(f.OverlapNote, defaultOverlapNote)))
	return b.String()
}

const (
	verifyCallsRef = "verification_calls.jsonl"
	// defaultOverlapNote is used when an older record carries no note of its own.
	defaultOverlapNote = "Occurrences count every failure; sessions affected counts sessions with at least one failure of that class; " +
		"a session can appear under several classes and ends with exactly one stop reason, so these views do not sum to each other."
)
