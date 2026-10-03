package report

import (
	"encoding/json"
	"fmt"
	"html"
	"strings"
)

// outcomeView mirrors engine.OutcomeSummary's JSON (feature 014, FR-021/022). The
// report package cannot import the engine, so the run_status.outcome value — an
// engine struct in a live finalize, a decoded map when read back from
// findings.json — is normalized through its JSON form. Both paths render the
// same bytes, which is what the consistency test (SC-009) checks.
type outcomeView struct {
	Units struct {
		Total, Assigned, Attempted, ReviewedWithFindings, ReviewedNoIssue int
		Partial, Failed, Skipped, Unsupported, NotReviewed                int
	}
	Candidates struct {
		Supported, Rejected, Unresolved int
	}
	FailedAssignments []struct {
		UnitID, Path, Reason string
	}
	FailedCandidates []struct {
		CandidateID, Class, Reason string
	}
	MissingArtifacts       []string
	DisabledOptionalPhases []string
	RecoverySteps          []string
}

// Record files each Completion line links to (relative to the results dir).
const (
	reviewUnitsRef  = "review_units.json"
	huntExecRef     = "hunt_execution.json"
	sessionsRef     = "verification_sessions.json"
	reconRef        = "verification_reconciliation.json"
	artifactManiRef = "artifact_manifest.json"
	scanMetaRef     = "scan_meta.json"
)

// outcomeOf extracts the completion block from the document; ok=false when the
// run predates feature 014 (no block) so the section is omitted, never invented.
func outcomeOf(in Input) (v outcomeView, ok bool) {
	raw := in.Doc.RunStatus.Outcome
	if raw == nil {
		return v, false
	}
	b, err := json.Marshal(raw)
	if err != nil {
		return v, false
	}
	// snake_case keys → the view's exported fields via a lenient re-map.
	var m map[string]any
	if json.Unmarshal(b, &m) != nil {
		return v, false
	}
	nb, _ := json.Marshal(camelKeys(m))
	if json.Unmarshal(nb, &v) != nil {
		return v, false
	}
	return v, true
}

// camelKeys rewrites snake_case JSON keys to the field names used by outcomeView
// (encoding/json matches field names case-insensitively, so "unitid" ≈ UnitID).
func camelKeys(v any) any {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, val := range t {
			out[strings.ReplaceAll(k, "_", "")] = camelKeys(val)
		}
		return out
	case []any:
		for i := range t {
			t[i] = camelKeys(t[i])
		}
		return t
	}
	return v
}

// completionMarkdown renders the "## Completion" section (FR-022). Every count is
// its own line; each group links to the record it was read from.
func completionMarkdown(in Input) string {
	v, ok := outcomeOf(in)
	if !ok {
		return ""
	}
	var b strings.Builder
	b.WriteString("### Completion\n\n")
	u := v.Units
	fmt.Fprintf(&b, "- **Review units** ([%s](%s)): %d reviewed of %d entry points — %d with findings, %d no issue, %d partial, %d failed, %d skipped, %d unsupported, %d not reviewed\n",
		reviewUnitsRef, reviewUnitsRef, u.ReviewedWithFindings+u.ReviewedNoIssue, u.Total,
		u.ReviewedWithFindings, u.ReviewedNoIssue, u.Partial, u.Failed, u.Skipped, u.Unsupported, u.NotReviewed)
	c := v.Candidates
	fmt.Fprintf(&b, "- **Candidates** ([%s](%s)): %d supported, %d rejected, %d unresolved\n", reconRef, reconRef, c.Supported, c.Rejected, c.Unresolved)
	fmt.Fprintf(&b, "- **Failed assignments** ([%s](%s)): %d\n", huntExecRef, huntExecRef, len(v.FailedAssignments))
	for _, fa := range v.FailedAssignments {
		fmt.Fprintf(&b, "  - `%s` %s — %s\n", fa.Path, orDash(fa.UnitID), fa.Reason)
	}
	fmt.Fprintf(&b, "- **Failed candidates** ([%s](%s)): %d — listed with class and reason in Appendix A (Unresolved, session failed)\n", sessionsRef, sessionsRef, len(v.FailedCandidates))
	fmt.Fprintf(&b, "- **Missing artifacts** ([%s](%s)): %d\n", artifactManiRef, artifactManiRef, len(v.MissingArtifacts))
	for _, m := range v.MissingArtifacts {
		fmt.Fprintf(&b, "  - %s\n", m)
	}
	fmt.Fprintf(&b, "- **Disabled optional phases** ([%s](%s)): %s\n", scanMetaRef, scanMetaRef, joinOrNone(v.DisabledOptionalPhases))
	if len(v.RecoverySteps) > 0 {
		b.WriteString("- **Recovery steps**:\n")
		for i, s := range v.RecoverySteps {
			fmt.Fprintf(&b, "  %d. %s\n", i+1, s)
		}
	} else {
		b.WriteString("- **Recovery steps**: none\n")
	}
	b.WriteString("\n")
	return b.String()
}

// completionHTML renders the same block for SCAN_REPORT.html.
func completionHTML(in Input) string {
	v, ok := outcomeOf(in)
	if !ok {
		return ""
	}
	e := html.EscapeString
	link := func(ref string) string { return fmt.Sprintf(`<a href="%s">%s</a>`, ref, ref) }
	var b strings.Builder
	b.WriteString(`<h3>Completion</h3><ul class="completion">`)
	u := v.Units
	fmt.Fprintf(&b, `<li><b>Review units</b> (%s): %d reviewed of %d entry points — %d with findings, %d no issue, %d partial, %d failed, %d skipped, %d unsupported, %d not reviewed</li>`,
		link(reviewUnitsRef), u.ReviewedWithFindings+u.ReviewedNoIssue, u.Total,
		u.ReviewedWithFindings, u.ReviewedNoIssue, u.Partial, u.Failed, u.Skipped, u.Unsupported, u.NotReviewed)
	c := v.Candidates
	fmt.Fprintf(&b, `<li><b>Candidates</b> (%s): %d supported, %d rejected, %d unresolved</li>`, link(reconRef), c.Supported, c.Rejected, c.Unresolved)
	fmt.Fprintf(&b, `<li><b>Failed assignments</b> (%s): %d`, link(huntExecRef), len(v.FailedAssignments))
	if len(v.FailedAssignments) > 0 {
		b.WriteString("<ul>")
		for _, fa := range v.FailedAssignments {
			fmt.Fprintf(&b, `<li><code>%s</code> %s — %s</li>`, e(fa.Path), e(orDash(fa.UnitID)), e(fa.Reason))
		}
		b.WriteString("</ul>")
	}
	b.WriteString("</li>")
	fmt.Fprintf(&b, `<li><b>Failed candidates</b> (%s): %d — listed with class and reason in Appendix A</li>`, link(sessionsRef), len(v.FailedCandidates))
	fmt.Fprintf(&b, `<li><b>Missing artifacts</b> (%s): %d`, link(artifactManiRef), len(v.MissingArtifacts))
	if len(v.MissingArtifacts) > 0 {
		b.WriteString("<ul>")
		for _, m := range v.MissingArtifacts {
			fmt.Fprintf(&b, `<li>%s</li>`, e(m))
		}
		b.WriteString("</ul>")
	}
	b.WriteString("</li>")
	fmt.Fprintf(&b, `<li><b>Disabled optional phases</b> (%s): %s</li>`, link(scanMetaRef), e(joinOrNone(v.DisabledOptionalPhases)))
	if len(v.RecoverySteps) > 0 {
		b.WriteString(`<li><b>Recovery steps</b><ol>`)
		for _, s := range v.RecoverySteps {
			fmt.Fprintf(&b, `<li>%s</li>`, e(s))
		}
		b.WriteString("</ol></li>")
	} else {
		b.WriteString(`<li><b>Recovery steps</b>: none</li>`)
	}
	b.WriteString("</ul>")
	return b.String()
}

func orDash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}

func joinOrNone(s []string) string {
	if len(s) == 0 {
		return "none"
	}
	return strings.Join(s, ", ")
}

// reviewCoverageMarkdown lists the unreviewed entry points with reasons (FR-016).
// Omitted entirely when the run has no review-unit record; when the record exists
// and has no gaps it says so explicitly rather than staying silent.
func reviewCoverageMarkdown(in Input) string {
	if in.ReviewGaps == nil {
		return ""
	}
	var b strings.Builder
	fmt.Fprintf(&b, "### Review coverage\n\n_Unreviewed entry points ([%s](%s)): %d_\n\n", reviewUnitsRef, reviewUnitsRef, len(in.ReviewGaps))
	for _, g := range in.ReviewGaps {
		fmt.Fprintf(&b, "- `%s` — %s\n", g.RouteID, g.Reason)
	}
	if len(in.ReviewGaps) > 0 {
		b.WriteString("\n")
	}
	return b.String()
}

func reviewCoverageHTML(in Input) string {
	if in.ReviewGaps == nil {
		return ""
	}
	e := html.EscapeString
	var b strings.Builder
	fmt.Fprintf(&b, `<h3>Review coverage</h3><p class="muted">Unreviewed entry points (<a href="%s">%s</a>): %d</p>`, reviewUnitsRef, reviewUnitsRef, len(in.ReviewGaps))
	if len(in.ReviewGaps) > 0 {
		b.WriteString("<ul>")
		for _, g := range in.ReviewGaps {
			fmt.Fprintf(&b, `<li><code>%s</code> — %s</li>`, e(g.RouteID), e(g.Reason))
		}
		b.WriteString("</ul>")
	}
	return b.String()
}
