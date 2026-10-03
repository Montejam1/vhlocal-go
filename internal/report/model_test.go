package report

import (
	"encoding/json"
	"strings"
	"testing"
)

// T013 (SC-001, C-A2, C-A3): the model built from the 171-candidate replay carries
// the honest counts, supported-only severity totals, a bounded summary whose
// leading items resolve to index anchors, and no queue job status.
func TestReplayModelCountsAndSummaryBounds(t *testing.T) {
	m := BuildModel(replayInput(t))
	c := m.Counts
	if c.Supported != 43 || c.Rejected != 7 || c.UnresolvedExplicit != 8 || c.UnresolvedFailed != 113 || c.TotalCandidates != 171 {
		t.Errorf("counts = %+v, want 43/7/8/113 = 171", c)
	}
	sum := 0
	for _, n := range m.SeveritySupported {
		sum += n
	}
	if sum != 43 {
		t.Errorf("Σ severity_supported = %d, want 43 (%v)", sum, m.SeveritySupported)
	}
	candSum := 0
	for _, n := range m.SeverityCandidates {
		candSum += n
	}
	if candSum != 171 {
		t.Errorf("Σ severity_candidates = %d, want 171", candSum)
	}
	if m.Summary.Words > MaxSummaryWords || m.Summary.Words == 0 {
		t.Errorf("summary words = %d, want 1..%d", m.Summary.Words, MaxSummaryWords)
	}
	if len(m.Summary.Leading) > MaxLeading || len(m.Summary.Leading) == 0 {
		t.Errorf("leading = %d, want 1..%d", len(m.Summary.Leading), MaxLeading)
	}
	anchors := map[string]bool{}
	for _, row := range m.Index {
		anchors[row.Anchor] = true
	}
	for _, l := range m.Summary.Leading {
		if !anchors[l.Ref] {
			t.Errorf("leading ref %q does not resolve to an index row", l.Ref)
		}
	}
	if len(m.Index) != 43 || len(m.Findings) != 43 {
		t.Errorf("index/findings = %d/%d, want 43", len(m.Index), len(m.Findings))
	}
	if len(m.Appendix.Rejected) != 7 || len(m.Appendix.UnresolvedExplicit) != 8 || len(m.Appendix.UnresolvedFailed) != 113 {
		t.Errorf("appendix sizes = %d/%d/%d", len(m.Appendix.Rejected), len(m.Appendix.UnresolvedExplicit), len(m.Appendix.UnresolvedFailed))
	}
	// Failed rows carry the session's failure class from the outcome block.
	classed := 0
	for _, r := range m.Appendix.UnresolvedFailed {
		if r.Class != "" {
			classed++
		}
	}
	if classed == 0 {
		t.Error("failed candidates must carry their failure class")
	}
	// Evidence quotes are present on supported findings.
	withEv := 0
	for _, f := range m.Findings {
		if len(f.Evidence) > 0 && f.Evidence[0].Quote != "" {
			withEv++
		}
	}
	if withEv == 0 {
		t.Error("supported findings must carry their captured evidence quotes")
	}
	b, _ := json.Marshal(m)
	for _, bad := range []string{"job_terminal", "\"terminated\"", "\"done\""} {
		if strings.Contains(string(b), bad) {
			t.Errorf("model must not carry a queue job status (%q)", bad)
		}
	}
	if m.Counts.SourceReview.Total != 100 || m.CoverageSemanticsLabel != "read-overlap evidence (v1)" {
		t.Errorf("source review = %+v label %q", m.Counts.SourceReview, m.CoverageSemanticsLabel)
	}
	// Persist + reload round-trips.
	dir := t.TempDir()
	if _, err := WriteModel(m, dir); err != nil {
		t.Fatal(err)
	}
	m2, err := LoadModel(dir)
	if err != nil || m2.Counts != m.Counts {
		t.Errorf("round-trip mismatch: %v %+v", err, m2.Counts)
	}
}
