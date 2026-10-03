package report

import (
	"regexp"
	"strings"
	"testing"
)

// T014 (FR-001, FR-004, C-A6) — the LEGACY document order.
//
// Feature 016 (T036) replaced the default document order; this test now describes the
// legacy renderer, which is what a report saved before feature 016 renders through
// (FR-026, C-C7). Every assertion is unchanged. The new document's order is asserted in
// document_order_test.go, and the two properties worth keeping on the new path — no
// candidate identifier before the summary, and the long failure explanation exactly once —
// are asserted in TestPresentationOrderKeepsSummaryFirst below.
func TestLegacyRenderOrderSummaryFirst(t *testing.T) {
	in := replayInput(t)
	m := BuildModel(in)
	md := renderMarkdownLegacy(in, m)
	html := renderHTMLLegacy(in, m)

	mdOrder := []string{"## Executive summary", "## Outcome metrics", "## Findings index", "## Findings", "## Coverage and limitations", "## Appendix A — Candidates", "## Appendix B — Execution"}
	assertOrder(t, "markdown", md, mdOrder)
	htmlOrder := []string{">Executive summary</h2>", ">Outcome metrics</h2>", ">Findings index</h2>", ">Findings</h2>", ">Coverage and limitations</h2>", ">Appendix A — Candidates</h2>", ">Appendix B — Execution</h2>"}
	assertOrder(t, "html", html, htmlOrder)

	// Summary before any candidate id / agent label / session record mention.
	for name, doc := range map[string]string{"markdown": md, "html": html} {
		summaryAt := strings.Index(doc, "Executive summary")
		for _, marker := range []string{"CAND-", "hunt:sg-", "verify:", "verification_sessions"} {
			if i := strings.Index(doc, marker); i >= 0 && i < summaryAt {
				t.Errorf("%s: %q appears before the executive summary", name, marker)
			}
		}
	}
	// One-line run-status warning: the banner line has no per-reason bullets following it.
	lines := strings.Split(md, "\n")
	for i, ln := range lines {
		if strings.HasPrefix(ln, "> ⚠ **Incomplete run.**") {
			if i+1 < len(lines) && strings.HasPrefix(lines[i+1], ">   - ") {
				t.Error("run-status warning must be one line; reasons belong to Coverage and limitations")
			}
		}
	}
	// The long per-candidate failure explanation appears exactly once (Appendix A).
	if len(m.Appendix.UnresolvedFailed) == 0 {
		t.Fatal("fixture has no failed candidates")
	}
	msg := m.Appendix.UnresolvedFailed[0].Message
	if n := strings.Count(md, msg); n != 1 {
		t.Errorf("failure explanation rendered %d times in markdown, want 1", n)
	}
	// Heading hierarchy: sections are ## and each supported finding is ###.
	if !regexp.MustCompile(`(?m)^### CAND-[0-9a-f]+ — `).MatchString(md) {
		t.Error("supported findings must be ### headings under ## Findings")
	}
	if strings.Contains(md, "### Supported findings") {
		t.Error("the old sibling heading '### Supported findings' must not appear (hierarchy)")
	}
}

// T036 (FR-001, FR-003): the two properties above that must hold for the NEW document
// too — no internal candidate identifier before the opening is read, and one copy of each
// long failure explanation, in the operator section.
func TestPresentationOrderKeepsSummaryFirst(t *testing.T) {
	in := replayInput(t)
	m := BuildModel(in)
	bodies := map[string]string{
		"markdown":        renderMarkdownModel(in, m),
		"standalone html": renderHTMLModel(in, m),
	}
	for name, doc := range bodies {
		summaryAt := strings.Index(doc, "Summary")
		if summaryAt < 0 {
			t.Fatalf("%s has no summary", name)
		}
		for _, marker := range []string{"CAND-", "hunt:sg-", "verify:", "verification_sessions"} {
			if i := strings.Index(doc, marker); i >= 0 && i < summaryAt {
				t.Errorf("%s: %q appears before the summary", name, marker)
			}
		}
	}
	if len(m.Appendix.UnresolvedFailed) == 0 {
		t.Fatal("fixture has no failed candidates")
	}
	msg := m.Appendix.UnresolvedFailed[0].Message
	md := bodies["markdown"]
	if n := strings.Count(md, msg); n != 1 {
		t.Errorf("failure explanation rendered %d times in the new markdown, want 1", n)
	}
	// It belongs to Scan details, not to the vulnerability content.
	if i := strings.Index(md, msg); i >= 0 && i < strings.Index(md, hdrScanDetail) {
		t.Error("a verification failure explanation appears before Scan details")
	}
}

func assertOrder(t *testing.T, name, doc string, markers []string) {
	t.Helper()
	last := -1
	for _, mk := range markers {
		i := strings.Index(doc, mk)
		if i < 0 {
			t.Errorf("%s: missing %q", name, mk)
			continue
		}
		if i < last {
			t.Errorf("%s: %q out of order", name, mk)
		}
		last = i
	}
}
