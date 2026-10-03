package report

import (
	"strings"
	"testing"

	"vhlocal/internal/consolidate"
)

// T015 (FR-003, C-A4): honesty of the executive summary on degenerate runs.
func TestSummaryHonestyOnEmptyAndPartialRuns(t *testing.T) {
	partial := Input{
		Target: "empty-app", Doc: consolidate.Doc{
			Meta:      map[string]any{"phases_requested": []any{"1", "2", "2b"}, "phases_completed": []any{"1"}},
			RunStatus: consolidate.RunStatus{ExecutionStatus: "partial", CoverageStatus: "degraded", ValidationMode: "static_reasoning", CoverageDegradedReasons: []string{"hunt produced no candidates (pipeline incomplete, not a clean result)"}},
			Findings:  []map[string]any{},
		},
	}
	m := BuildModel(partial)
	if !strings.HasPrefix(m.Summary.Narrative, "Limitation first:") {
		t.Errorf("zero supported + partial must lead with the limitation: %q", m.Summary.Narrative)
	}
	for _, s := range []string{m.Summary.Narrative, strings.Join(m.Summary.Limitations, " ")} {
		if claimsClean(s) {
			t.Errorf("summary must never claim clean: %q", s)
		}
	}
	// Feature 016 (T036): the opening is now "## Summary", bounded at 180 words, and is
	// followed by "## Priority actions". The honesty assertions below are unchanged.
	md := RenderMarkdown(partial)
	summary := sectionBetween(md, "## Summary", "## Priority actions")
	if claimsClean(summary) || strings.Contains(summary, "finished successfully") || strings.Contains(summary, "confirmed by execution") {
		t.Errorf("rendered summary misstates the run:\n%s", summary)
	}

	// A terminated job with partial execution never reads as complete.
	done := partial
	done.Doc.Meta["job_status"] = "done"
	md = RenderMarkdown(done)
	summary = sectionBetween(md, "## Summary", "## Priority actions")
	if strings.Contains(summary, "execution complete") || strings.Contains(strings.ToLower(summary), "successfully") {
		t.Errorf("job termination must not imply completion:\n%s", summary)
	}

	// Static reasoning is never presented as an executed exploit.
	full := replayInput(t)
	md = RenderMarkdown(full)
	summary = sectionBetween(md, "## Summary", "## Priority actions")
	// The same guarantee in the new document's words: the method is named and the opening
	// states that the application was not run.
	if !strings.Contains(summary, "Source-code analysis") || !strings.Contains(summary, "never executed") {
		t.Errorf("summary must state that support is by source-code analysis, not execution:\n%s", summary)
	}
}

func sectionBetween(doc, from, to string) string {
	i := strings.Index(doc, from)
	if i < 0 {
		return ""
	}
	rest := doc[i:]
	if j := strings.Index(rest, to); j > 0 {
		return rest[:j]
	}
	return rest
}

// claimsClean reports whether text asserts cleanliness — any "clean" that is not
// part of the engine's own honest negation "not a clean result/target".
func claimsClean(s string) bool {
	l := strings.ToLower(s)
	for i := strings.Index(l, "clean"); i >= 0; {
		if !strings.HasSuffix(l[:i], "not a ") {
			return true
		}
		j := strings.Index(l[i+5:], "clean")
		if j < 0 {
			break
		}
		i = i + 5 + j
	}
	return false
}
