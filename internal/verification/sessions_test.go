package verification

import "testing"

// CB-9/CB-10 (feature 007, FR-023): a candidate whose session ended without a
// decision is reported unresolved with an ACTIONABLE reason naming the stop cause
// and the attempt/failure counts — never fabricated as supported.
func TestEnrichReasonsNamesStopCause(t *testing.T) {
	rc := &Reconciliation{
		Results: []DecisionResult{
			{CandidateID: "CAND-a", Status: "unresolved", Reason: "No verification decision supplied"},
			{CandidateID: "CAND-b", Status: "unresolved", Reason: "explicit unresolved: needs a runtime check"},
			{CandidateID: "CAND-c", Status: "supported", Reason: "confirmed"},
		},
	}
	sessions := map[string]SessionOutcome{
		"CAND-a": {CandidateID: "CAND-a", StopReason: "tool_repair", Turns: 6, Failures: 3},
	}
	EnrichReasons(rc, sessions)

	if rc.Results[0].Reason == "No verification decision supplied" {
		t.Errorf("a no-decision candidate with a session outcome must get an actionable reason")
	}
	for _, want := range []string{"tool_repair", "3 recoverable tool failure", "6 turn"} {
		if !contains(rc.Results[0].Reason, want) {
			t.Errorf("reason %q must mention %q", rc.Results[0].Reason, want)
		}
	}
	// An explicit unresolved reason is preserved (not overwritten).
	if rc.Results[1].Reason != "explicit unresolved: needs a runtime check" {
		t.Errorf("explicit unresolved reason must be preserved, got %q", rc.Results[1].Reason)
	}
	// Supported is never touched, and no candidate is fabricated.
	if rc.Results[2].Status != "supported" {
		t.Errorf("supported disposition must be unchanged")
	}
}

func contains(s, sub string) bool {
	return len(sub) == 0 || (len(s) >= len(sub) && indexOf(s, sub) >= 0)
}
func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
