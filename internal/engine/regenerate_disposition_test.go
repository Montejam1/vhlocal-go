package engine

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"vhlocal/internal/consolidate"
	"vhlocal/internal/verification"
)

// T025 / CB-5: re-deriving findings (as resume/regeneration does via
// loadVerifiedFindings) preserves the distinct dispositions AND the actionable
// "no decision" reason from the recorded session outcome — deterministically.
func TestRederivePreservesDispositionsAndReasons(t *testing.T) {
	repo := t.TempDir()
	os.MkdirAll(filepath.Join(repo, "app"), 0o755)
	os.WriteFile(filepath.Join(repo, "app", "db.py"), []byte("def q(x):\n    return conn.execute(x)\n"), 0o644)
	os.WriteFile(filepath.Join(repo, "app", "safe.py"), []byte("def q(x):\n    return sanitize(x)\n"), 0o644)
	results := t.TempDir()

	sup := consolidate.NewFinding("V1")
	sup.CWE, sup.Location, sup.EntryPoint, sup.DataFlow = "CWE-89", "app/db.py:2", "GET /s", "x -> execute()"
	consolidate.ApplyKnowledge(&sup)
	miss := consolidate.NewFinding("V2")
	miss.CWE, miss.Location = "CWE-89", "app/safe.py:2"
	consolidate.ApplyKnowledge(&miss)

	man, err := verification.BuildManifest(results, repo, "rev1", []consolidate.Finding{sup, miss})
	if err != nil {
		t.Fatal(err)
	}
	// Map ids by location.
	var supID, missID string
	for _, c := range man.Candidates {
		if c.Finding.Location == "app/db.py:2" {
			supID = c.ID
		} else {
			missID = c.ID
		}
	}
	// A valid supported decision for the sink; NO decision for the other (→ unresolved).
	b, _ := os.ReadFile(filepath.Join(repo, "app", "db.py"))
	lines := strings.Split(string(b), "\n")
	quote := strings.Join(lines[0:2], "\n")
	decs := []verification.Decision{{
		CandidateID: supID, Verdict: "supported", Rationale: "reaches execute unsanitized",
		EntryPoint: "GET /s", AttackerControl: "query", Preconditions: "none",
		DefensesReviewed: "none", SecurityImpact: "data exfiltration", Revision: "rev1",
		Reviewer: "phase2b-model",
		Evidence: []verification.Evidence{{ID: "EV-x", Path: "app/db.py", StartLine: 1, EndLine: 2, Quote: quote}},
	}}
	writeJSONFile(t, filepath.Join(results, verification.DecisionsFile), decs)
	writeJSONFile(t, filepath.Join(results, verification.SessionsFile),
		[]verification.SessionOutcome{{CandidateID: missID, StopReason: "max_turns", Turns: 20, Failures: 3}})

	assertDispositions := func(tag string) {
		fs, ok := loadVerifiedFindings(results, repo)
		if !ok {
			t.Fatalf("%s: loadVerifiedFindings failed", tag)
		}
		byID := map[string]consolidate.Finding{}
		for _, f := range fs {
			byID[f.ID] = f
		}
		if s := byID[supID]; s.VerificationStatus != "supported" || !s.FromConfirmed {
			t.Errorf("%s: supported candidate not preserved: %+v", tag, s)
		}
		m := byID[missID]
		if m.VerificationStatus != "unresolved" {
			t.Errorf("%s: missing-decision candidate must be unresolved, got %q", tag, m.VerificationStatus)
		}
		if !strings.Contains(m.VerificationReason, "session ended: max_turns") {
			t.Errorf("%s: enriched no-decision reason not preserved: %q", tag, m.VerificationReason)
		}
	}
	assertDispositions("first")
	assertDispositions("re-derived") // deterministic across repeated derivation (as regeneration does)
}

func writeJSONFile(t *testing.T, path string, v any) {
	t.Helper()
	b, _ := json.MarshalIndent(v, "", "  ")
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}
}
