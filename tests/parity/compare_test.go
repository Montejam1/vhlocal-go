package parity

import "testing"

// C-D3 (feature 006, FR-006): incidental differences do NOT fail the comparison; a
// semantic difference does. A small line shift maps to the same normalized identity
// (the projector's normalization), while a changed disposition/tier is surfaced with
// its dimension + candidate.
func TestNormIDPreservesNearbySites(t *testing.T) {
	base := NormID("app/db.py:21", "CWE-89")
	if base == NormID("app/db.py:23", "CWE-89") {
		t.Errorf("nearby distinct locations must not collapse into one norm_id")
	}
	if base == NormID("app/db.py:21", "CWE-78") {
		t.Errorf("a different CWE must change the norm_id")
	}
	if base == NormID("app/other.py:21", "CWE-89") {
		t.Errorf("a different file must change the norm_id")
	}
	if base == NormID("app/db.py:80", "CWE-89") {
		t.Errorf("a far line (different bucket) must change the norm_id")
	}
}

func TestCompareSemanticVsIncidental(t *testing.T) {
	id := NormID("app/db.py:21", "CWE-89")
	mk := func(disp, tier string) Projection {
		return Projection{
			Dispatch:     []DispatchUnit{{"sg-1", "inj"}},
			Passes:       []string{"sink"},
			Candidates:   []ProjCandidate{{NormID: id, CWE: "CWE-89", Location: "app/db.py:21"}},
			Dispositions: map[string]string{id: disp},
			Tiers:        map[string]string{id: tier},
			Coverage:     map[string]string{"ROUTE /api/search": "finding_emitted"},
			RunStatus:    RunStatusProj{Execution: "complete", Coverage: "complete", ValidationMode: "static_only"},
		}
	}
	// Identical projections → parity.
	if d := Compare(mk("supported", "statically_supported"), mk("supported", "statically_supported")); len(d) != 0 {
		t.Errorf("identical projections must not diverge, got %v", d)
	}
	// A flipped disposition → one divergence naming the candidate + dimension.
	d := Compare(mk("rejected", "hypothesis"), mk("supported", "statically_supported"))
	if len(d) == 0 {
		t.Fatal("a flipped verdict/tier must diverge")
	}
	sawDisp := false
	for _, dv := range d {
		if dv.Dimension == "dispositions" && dv.Detail == id && dv.Got == "rejected" && dv.Want == "supported" {
			sawDisp = true
		}
	}
	if !sawDisp {
		t.Errorf("expected a dispositions divergence for %s, got %v", id, d)
	}
}
