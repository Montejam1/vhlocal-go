package engine

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"vhlocal/internal/verification"
)

// Live-run regression (2026-09-29 operator scan): a candidate whose verifier
// SUBMITTED an `unresolved` verdict must be classed `unresolved_verdict`, not by an
// incidental tool-failure count from earlier in its session; candidates with no
// decision keep the session's dominant failure class; cancelled and never-attempted
// sessions get their own labels. Recovery steps about tool contracts are only
// emitted for real failure classes.
func TestOutcomeClassifiesUnresolvedVerdictSeparately(t *testing.T) {
	dir := t.TempDir()
	recon := verification.Reconciliation{
		Counts: map[string]int{"supported": 1, "rejected": 0, "unresolved": 4},
		Results: []verification.DecisionResult{
			{CandidateID: "CAND-ok", Status: "supported"},
			{CandidateID: "CAND-verdict", Status: "unresolved", Reason: "impact unclear", Record: &verification.Decision{Verdict: "unresolved"}},
			{CandidateID: "CAND-args", Status: "unresolved", Reason: "no decision submitted"},
			{CandidateID: "CAND-cancel", Status: "unresolved", Reason: "no decision submitted"},
			{CandidateID: "CAND-never", Status: "unresolved", Reason: "No verification decision supplied"},
		},
	}
	sessions := []verification.SessionOutcome{
		{CandidateID: "CAND-verdict", StopReason: "complete", Turns: 12, FailuresByClass: map[string]int{verification.FailInvalidToolArgs: 4}},
		{CandidateID: "CAND-args", StopReason: "tool_repair", Turns: 9, FailuresByClass: map[string]int{verification.FailInvalidToolArgs: 3}},
		{CandidateID: "CAND-cancel", StopReason: "cancelled", Turns: 2},
	}
	write := func(name string, v any) {
		b, _ := json.Marshal(v)
		if err := os.WriteFile(filepath.Join(dir, name), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(verification.ReconciliationFile, recon)
	write(verification.SessionsFile, sessions)

	rec := &RunRecord{PhasesRequested: []string{"1", "2", "2b"}, PhasesCompleted: []string{"1", "2", "2b"}}
	o := buildOutcome(ScanSpec{ResultsDir: dir}, rec, nil)

	got := map[string]string{}
	for _, fc := range o.FailedCandidates {
		got[fc.CandidateID] = fc.Class
	}
	want := map[string]string{
		"CAND-verdict": ClassUnresolvedVerdict,
		"CAND-args":    verification.FailInvalidToolArgs,
		"CAND-cancel":  "cancelled",
		"CAND-never":   "not_attempted",
	}
	for id, cls := range want {
		if got[id] != cls {
			t.Errorf("%s class = %q, want %q", id, got[id], cls)
		}
	}
	if len(o.FailedCandidates) != 4 || o.Candidates.Unresolved != 4 || o.Candidates.Supported != 1 {
		t.Errorf("counts: failed=%d candidates=%+v", len(o.FailedCandidates), o.Candidates)
	}
	// The verdict candidate keeps the model's own rationale as its reason.
	for _, fc := range o.FailedCandidates {
		if fc.CandidateID == "CAND-verdict" && fc.Reason != "impact unclear" {
			t.Errorf("verdict reason = %q", fc.Reason)
		}
	}
	// Tool-contract recovery step is present (CAND-args) — and would be absent if only
	// verdicts were unresolved.
	joined := ""
	for _, s := range o.RecoverySteps {
		joined += s + "|"
	}
	if !contains(joined, "tool contract") {
		t.Errorf("expected a tool-contract recovery step: %v", o.RecoverySteps)
	}
	recon.Results = recon.Results[:2]
	recon.Counts["unresolved"] = 1
	write(verification.ReconciliationFile, recon)
	o2 := buildOutcome(ScanSpec{ResultsDir: dir}, rec, nil)
	for _, s := range o2.RecoverySteps {
		if contains(s, "tool contract") || contains(s, "turn limit") {
			t.Errorf("an unresolved VERDICT must not trigger failure-class recovery steps: %q", s)
		}
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
