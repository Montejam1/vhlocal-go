package engine

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// runStatusExec reads execution_status from findings.json's run_status.
func runStatusExec(t *testing.T, resultsDir string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(resultsDir, "findings.json"))
	if err != nil {
		return ""
	}
	var doc map[string]any
	if json.Unmarshal(b, &doc) != nil {
		return ""
	}
	rs, _ := doc["run_status"].(map[string]any)
	s, _ := rs["execution_status"].(string)
	return s
}

// Feature 013 (FR-019): a run with phases=all but the optional threat-model toggle
// OFF must not be marked incomplete/partial merely because 1t did not run. 1t is
// still recorded as skipped honestly, but it is not a required deliverable.
func TestThreatModelOffNotFalselyIncomplete(t *testing.T) {
	repo := filepath.Join(repoRoot(t), "testdata", "vulnapp")
	results := t.TempDir()
	spec := brokenSpec(repo, results)
	// Use phases whose non-1t members all complete with the offline fake, so the
	// ONLY thing that could make the run partial is the deliberately-off 1t phase.
	spec.Phases = []string{"1", "1t", "4"}
	spec.ThreatModel = false // optional phase deliberately off

	rec, err := Execute(context.Background(), spec, Providers{Hunt: &pathWriter{model: "m"}}, staticSkill{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	// 1t is honestly recorded as skipped...
	skipped := false
	for _, p := range rec.PhasesSkipped {
		if p == "1t" {
			skipped = true
		}
	}
	if !skipped {
		t.Error("1t should be recorded as skipped when threat model is off")
	}
	// ...but the run must not read as incomplete solely because of it.
	if es := runStatusExec(t, results); es == ExecIncompleteStr || es == ExecPartialStr {
		t.Errorf("phases=all with threat-model off must not be %q (FR-019)", es)
	}
}

// Mirror the consolidate status constants for the test assertion.
const (
	ExecIncompleteStr = "incomplete"
	ExecPartialStr    = "partial"
)
