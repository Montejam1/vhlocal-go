package report

import (
	"strings"
	"testing"
)

// T022 (FR-001, C-P1): the default document presents report identity, executive summary
// with severity totals and a compact scope note, up to five prioritized actions, the
// vulnerability index, issue details, Needs review, and Scan details, in that order.
// Dismissed candidates and technical diagnostics come after them as secondary sections.
func TestDefaultDocumentOrder(t *testing.T) {
	in := fixture016Input(t)
	m := BuildModel(in)

	// Markdown: headings in order.
	md := renderMarkdownModel(in, m)
	mdOrder := []string{hdrSummary, hdrPriority, hdrIssues, hdrDetails, hdrNeedsRev, hdrScanDetail, hdrDismissed}
	assertOrder(t, "markdown", md, mdOrder)

	// Identity precedes everything, including the summary.
	idIdx := strings.Index(md, m.Presentation.Identity.Application)
	if idIdx < 0 {
		t.Fatalf("markdown never names the application %q", m.Presentation.Identity.Application)
	}
	if sIdx := strings.Index(md, hdrSummary); sIdx >= 0 && idIdx > sIdx {
		t.Error("the report does not identify what it is about before summarising it")
	}

	// Severity totals and the scope note live inside the summary, not in a later section.
	summary := sectionOf(t, md, hdrSummary)
	if !strings.Contains(summary, "High") || !strings.Contains(summary, "Medium") {
		t.Error("the executive summary carries no severity totals")
	}
	if !strings.Contains(summary, "Review scope:") {
		t.Error("the executive summary carries no scope note")
	}

	// Standalone HTML: the same sequence, by section id so wording changes do not break it.
	h := renderHTMLModel(in, m)
	assertOrder(t, "standalone html", h, []string{
		`id="summary"`, `id="priority"`, `id="issues"`, `id="details"`,
		`id="needs-review"`, `id="scan-details"`, `id="dismissed"`,
	})
}

// T022 (FR-001, C-P1): diagnostics are reachable but secondary. They never appear before
// the vulnerability content, and the markdown marks them as supporting material.
func TestDiagnosticsAreSecondaryNotLeading(t *testing.T) {
	in := fixture016Input(t)
	m := BuildModel(in)
	md := renderMarkdownModel(in, m)

	issues := strings.Index(md, hdrIssues)
	for _, later := range []string{hdrScanDetail, hdrDismissed} {
		i := strings.Index(md, later)
		if i < 0 {
			t.Errorf("%q is missing; diagnostics must stay reachable, not be deleted", later)
			continue
		}
		if i < issues {
			t.Errorf("%q appears before the vulnerability list", later)
		}
	}
	// Scan details is where the operator-facing facts live, so it must actually carry them.
	scan := sectionOf(t, md, hdrScanDetail)
	for _, want := range []string{"candidates examined", "Model", "Execution"} {
		if !strings.Contains(scan, want) && !strings.Contains(strings.ToLower(scan), strings.ToLower(want)) {
			t.Errorf("Scan details does not record %q; the fact was dropped rather than moved", want)
		}
	}
	// The HTML keeps them collapsed by default rather than expanded in the reading flow.
	h := renderHTMLModel(in, m)
	if !strings.Contains(h, `<details`) {
		t.Error("standalone html renders no on-demand section for secondary material")
	}
}
