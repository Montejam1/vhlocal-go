package report

import (
	"encoding/json"
	"fmt"
	"html"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// T027 (FR-009) / feature 016 T036: the counts and the section order agree across
// report_model.json, the Markdown and the HTML written by Write — the JSON the UIs consume
// is the same model the documents were rendered from.
//
// The assertion is unchanged; the labels and section names follow the feature-016
// document, because that is what Write now produces. Every count checked here is read from
// the persisted projection rather than retyped, so the test cannot drift from the model.
func TestSurfacesAgreeOnCountsAndOrder(t *testing.T) {
	in := replayInput(t)
	dir := t.TempDir()
	if _, _, err := Write(in, dir); err != nil {
		t.Fatal(err)
	}
	mb, _ := os.ReadFile(filepath.Join(dir, ModelFile))
	var m ReportModel
	if err := json.Unmarshal(mb, &m); err != nil {
		t.Fatal(err)
	}
	if m.Presentation == nil {
		t.Fatal("the persisted model carries no presentation projection")
	}
	mdb, _ := os.ReadFile(filepath.Join(dir, MDFile))
	hb, _ := os.ReadFile(filepath.Join(dir, HTMLFile))
	md, h := string(mdb), string(hb)
	c := m.Presentation.Counts

	mdWants := []string{
		fmt.Sprintf("| **Issues to fix** | %d |", c.IssuesToFix),
		fmt.Sprintf("- **Candidates examined**: %d", c.CandidatesExamined),
		fmt.Sprintf("- **Supported detections**: %d", c.Detections),
		fmt.Sprintf("- **Needs review**: %d — %d inconclusive, %d where review did not finish", c.NeedsReview, c.NeedsInconclusive, c.NeedsIncomplete),
		fmt.Sprintf("- **Dismissed**: %d", c.Dismissed),
	}
	for _, w := range mdWants {
		if !strings.Contains(md, w) {
			t.Errorf("markdown lacks %q", w)
		}
	}
	htmlWants := []string{
		fmt.Sprintf(`<div class="tn">%d</div><div class="tl">Issues to fix</div>`, c.IssuesToFix),
		fmt.Sprintf(`<li><b>Candidates examined</b>: %d`, c.CandidatesExamined),
		fmt.Sprintf(`<li><b>Supported detections</b>: %d`, c.Detections),
		fmt.Sprintf(`<li><b>Dismissed</b>: %d</li>`, c.Dismissed),
	}
	for _, w := range htmlWants {
		if !strings.Contains(h, w) {
			t.Errorf("html lacks %q", w)
		}
	}
	// The same number of issues on every surface: one index row and one detail section per
	// primary issue, never one per detection.
	issues := len(m.Presentation.Issues)
	if issues == 0 {
		t.Fatal("fixture established no issues")
	}
	if n := strings.Count(md, "\n### "); n < issues {
		t.Errorf("markdown issue headings = %d, model = %d", n, issues)
	}
	if n := strings.Count(h, `<details class="issue"`); n != issues {
		t.Errorf("html issue blocks = %d, model = %d", n, issues)
	}
	// The severity totals the documents show are the projection's, not recomputed prose.
	for _, s := range DisplaySeverities {
		w := fmt.Sprintf("| &nbsp;&nbsp;%s | %d |", s, c.Severity[s])
		if !strings.Contains(md, w) {
			t.Errorf("markdown lacks the severity row %q", w)
		}
	}
	// Order agreement (FR-001).
	assertOrder(t, "markdown", md, []string{hdrSummary, hdrPriority, hdrIssues, hdrDetails, hdrNeedsRev, hdrScanDetail, hdrDismissed})
	assertOrder(t, "html", h, []string{`id="summary"`, `id="priority"`, `id="issues"`, `id="details"`, `id="needs-review"`, `id="scan-details"`, `id="dismissed"`})
	// The opening prose is the same text on every surface.
	if !strings.Contains(md, m.Presentation.Opening.RiskSummary) {
		t.Error("markdown opening differs from the model")
	}
	if !strings.Contains(h, html.EscapeString(m.Presentation.Opening.RiskSummary)) {
		t.Error("html opening differs from the model")
	}
}
