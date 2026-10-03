package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Feature 014 (FR-020, SC-008, T042): a supported candidate with no reproduction
// disposition and an unregistered artifact each stay visible in artifact_errors and
// block false completeness; the orphan file is retained; the report labels
// artifacts not executed. (Reproduction behavior is unchanged — this pins it.)
func TestReproductionIntegrityBlocksFalseCompleteness(t *testing.T) {
	repo, routes, spans := coverageFixture(t)
	all := make([]string, 0, len(spans))
	for _, s := range spans {
		all = append(all, s)
	}
	rw := newReadingWriter(all)
	plans := map[string]verifyPlan{}
	hs := newHandlerSpans(repo)
	for _, r := range routes {
		if r.File == "svc02/routes.py" && r.Path == "/svc02/items" {
			sc := hs.scopeFor(r)
			loc := fmt.Sprintf("%s:%d", r.File, sc.Start+1)
			entry := r.Method + " " + r.Path
			rw.findings[r.File] = plantedFinding{Location: loc, CWE: "CWE-862", EntryPoint: entry, Title: "Missing authorization on " + entry}
			plans[loc] = verifyPlan{File: r.File, Start: sc.Start, End: sc.End, EntryPoint: entry}
		}
	}
	results := t.TempDir()
	// An orphan artifact planted where the manifest walk looks — must be reported, kept.
	os.MkdirAll(filepath.Join(results, "poc"), 0o755)
	stray := filepath.Join(results, "poc", "stray_test.py")
	os.WriteFile(stray, []byte("# not registered\n"), 0o644)

	spec := coverageSpec(repo, results)
	spec.Phases = []string{"1", "2", "2b", "3"} // reproduction runs; the double writes no repro disposition
	rec, err := Execute(context.Background(), spec, Providers{Hunt: newVerifyingWriter(rw, plans)}, staticSkill{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(rec.ArtifactErrors, " | ")
	if !strings.Contains(joined, "no reproduction disposition for ") {
		t.Errorf("missing disposition must be visible in artifact_errors: %v", rec.ArtifactErrors)
	}
	if !strings.Contains(joined, "unregistered artifact: poc/stray_test.py") {
		t.Errorf("unregistered artifact must be visible in artifact_errors: %v", rec.ArtifactErrors)
	}
	if _, err := os.Stat(stray); err != nil {
		t.Error("orphan artifact must never be deleted to pass validation")
	}
	if containsStr(rec.PhasesCompleted, "3") {
		t.Error("phase 3 must not count as completed with artifact errors")
	}
	// The report never implies execution.
	b, _ := os.ReadFile(filepath.Join(results, "SCAN_REPORT.md"))
	if !strings.Contains(strings.ToLower(string(b)), "never executed") && !strings.Contains(strings.ToLower(string(b)), "not executed") {
		t.Error("report must state artifacts were not executed")
	}
	// findings.json run_status stays honest (execution not complete).
	fb, _ := os.ReadFile(filepath.Join(results, "findings.json"))
	var doc struct {
		RunStatus struct {
			ExecutionStatus string `json:"execution_status"`
		} `json:"run_status"`
	}
	_ = json.Unmarshal(fb, &doc)
	if doc.RunStatus.ExecutionStatus == "complete" {
		t.Error("execution_status must not be complete with a missing reproduction disposition")
	}
}
