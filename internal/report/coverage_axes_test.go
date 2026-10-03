package report

import (
	"strings"
	"testing"
)

// T053 (FR-015/019): "Coverage and limitations" carries the semantics label and,
// for v2 records, the axes table; v1 records say exposure equals completion.
func TestCoverageAxesTableInReport(t *testing.T) {
	in := replayInput(t)
	in.Coverage = &CoverageView{Completed: 20, Exposed: 171, Total: 171, SemanticsVersion: 2,
		Axes: &CoverageAxes{Discovered: 171, SupportedInventory: 171, Assigned: 170, Attempted: 168, SourceExposed: 171, CompletedReview: 20, Verified: 9}}
	in.CoverageLabel = "validated handler dispositions (v2)"
	m := BuildModel(in)
	if m.Counts.SourceReview.Axes == nil || m.Counts.SourceReview.Axes.SourceExposed != 171 {
		t.Fatalf("model axes = %+v", m.Counts.SourceReview.Axes)
	}
	md := renderMarkdownModel(in, m)
	h := renderHTMLModel(in, m)
	// Feature 016 (T036): the coverage block moved from "Coverage and limitations" into
	// the operator-facing "Scan details" section. The axis assertions below are unchanged
	// — only the section this test reads them from.
	cov := sectionOf(t, md, hdrScanDetail)
	for _, want := range []string{"### Source review coverage", "validated handler dispositions (v2)", "| Source exposed | 171 |", "| Completed review | 20 |", "| Verified | 9 |", "No axis is derived from another"} {
		if !strings.Contains(cov, want) {
			t.Errorf("markdown coverage section lacks %q", want)
		}
	}
	for _, want := range []string{">Source review coverage</h3>", "validated handler dispositions (v2)", `<td class="num">171</td>`, `axes-table`} {
		if !strings.Contains(h, want) {
			t.Errorf("html lacks %q", want)
		}
	}

	// v1: no axes; the block says exposure equals completion.
	in1 := replayInput(t)
	m1 := BuildModel(in1)
	md1 := renderMarkdownModel(in1, m1)
	if !strings.Contains(md1, "read-overlap evidence (v1)") || !strings.Contains(md1, "exposure equals completion") || strings.Contains(md1, "| Source exposed |") {
		t.Error("v1 report must carry the v1 label and no axes table")
	}
}
