package report

import (
	"strings"
	"testing"

	"vhlocal/internal/consolidate"
)

// zeroFindingInput derives a records-shaped Input with no candidates at all, keeping the
// recorded status axes of the frozen corpus. Nothing is read or written outside the
// fixture and t.TempDir() (FR-028).
func zeroFindingInput(t *testing.T, execution string) Input {
	t.Helper()
	in := fixture016Input(t)
	in.Doc.Findings = nil
	in.Doc.Counts = map[string]int{}
	in.Doc.ClassCounts = map[consolidate.Class]int{}
	in.Doc.SeveritySupported = map[string]int{}
	in.Doc.SeverityCandidates = map[string]int{}
	in.Doc.RunStatus.ExecutionStatus = execution
	in.Groups = nil
	return in
}

// T021 (FR-005, C-P10): a scan that found nothing while review was incomplete says both
// things. Absence within the reviewed scope is not an assurance about the rest, and no
// reassuring conclusion appears anywhere.
func TestZeroFindingsWithIncompleteReviewDistinguishesAbsenceFromIgnorance(t *testing.T) {
	in := zeroFindingInput(t, consolidate.ExecPartial)
	m := BuildModel(in)
	p := m.Presentation
	if p == nil {
		t.Fatal("no presentation projection")
	}
	if p.Counts.IssuesToFix != 0 {
		t.Fatalf("fixture precondition: expected a zero-finding corpus, got %d issues", p.Counts.IssuesToFix)
	}
	if p.Scope.Execution == "Complete" {
		t.Fatalf("fixture precondition: expected an incomplete run, scope reads %q", p.Scope.Execution)
	}
	if p.Scope.GapSentence == "" {
		t.Error("with review incomplete and nothing found, the unreviewed remainder must be stated")
	}

	bodies := map[string]string{
		"markdown":        renderMarkdownModel(in, m),
		"standalone html": renderHTMLModel(in, m),
	}
	for name, body := range bodies {
		low := strings.ToLower(body)
		// Both halves of the honest statement.
		if !strings.Contains(low, "reviewed") {
			t.Errorf("%s does not scope the result to what was reviewed", name)
		}
		if !strings.Contains(low, "not completed") && !strings.Contains(low, "incomplete") {
			t.Errorf("%s does not say the review was incomplete", name)
		}
		// No assurance, in words or in colour.
		// Phrases chosen so an innocent word ("cleanup", "bypassed") cannot trip them.
		for _, phrase := range []string{
			"no vulnerabilities", "is secure", "all clear", "zero risk", "clean bill",
			"no issues were found", "nothing to fix", "congratulations",
		} {
			if strings.Contains(low, phrase) {
				t.Errorf("%s offers reassurance %q on an incomplete scan", name, phrase)
			}
		}
	}
	// The HTML must not paint the headline with a success colour.
	html := bodies["standalone html"]
	for _, cls := range []string{"sev-none", "status-ok", "badge-success", "all-clear"} {
		if strings.Contains(html, cls) {
			t.Errorf("standalone html styles the result as a success state via %q", cls)
		}
	}
}

// T021 (FR-005): the same zero-finding records with review COMPLETE may state absence
// within the reviewed scope, and still must not generalise beyond it.
func TestZeroFindingsWithCompleteReviewStatesAbsenceWithinScope(t *testing.T) {
	in := zeroFindingInput(t, consolidate.ExecComplete)
	m := BuildModel(in)
	if m.Presentation.Scope.Execution != "Complete" {
		t.Fatalf("fixture precondition: execution reads %q", m.Presentation.Scope.Execution)
	}
	md := renderMarkdownModel(in, m)
	low := strings.ToLower(md)
	// Scoped absence is permitted; an unqualified security claim is not.
	for _, phrase := range []string{"the application is secure", "no vulnerabilities exist", "zero risk"} {
		if strings.Contains(low, phrase) {
			t.Errorf("a complete review with no findings still cannot claim %q", phrase)
		}
	}
	// Coverage on this corpus is 40 of 100, so even a complete execution leaves scope
	// unreviewed and the report must keep saying so.
	if m.Presentation.Scope.CoverageComplete < m.Presentation.Scope.CoverageTotal &&
		!strings.Contains(low, "not completed") && !strings.Contains(low, "remaining") {
		t.Error("coverage is partial; the report must still bound the result to the reviewed code")
	}
}
