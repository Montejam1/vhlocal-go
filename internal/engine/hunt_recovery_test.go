package engine

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func huntExecOf(t *testing.T, results string) huntExecution {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(results, "hunt_execution.json"))
	if err != nil {
		t.Fatal(err)
	}
	var h huntExecution
	if err := json.Unmarshal(b, &h); err != nil {
		t.Fatal(err)
	}
	return h
}

// Feature 014 (FR-017, SC-006, T039): a provider that stops NORMALLY without writing
// reproduces the audited missing-hunt-file failure. The engine records the agent's
// normal stop and the assignment's failure SEPARATELY (produced=false), runs exactly
// one bounded re-run, and — when that also fails — names the exact missing path and
// leaves the run partial. A normal stop alone never passes.
func TestMissingDeliverableIsFailedAssignmentAfterOneRerun(t *testing.T) {
	repo := filepath.Join(repoRoot(t), "testdata", "vulnapp")
	results := t.TempDir()
	spec := brokenSpec(repo, results)
	spec.Phases = []string{"1", "2"}
	rec, err := Execute(context.Background(), spec, Providers{Hunt: silentProvider{}}, staticSkill{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	// Agent stop vs assignment success are separate facts.
	huntAgents, retries, producedTrue := 0, 0, 0
	for _, a := range rec.Agents {
		if a.Phase != "2" {
			continue
		}
		huntAgents++
		if a.StoppedReason != "complete" {
			t.Errorf("silent provider should stop 'complete', got %q for %s", a.StoppedReason, a.Label)
		}
		if a.Produced {
			producedTrue++
		}
		if len(a.Label) > 7 && a.Label[len(a.Label)-7:] == ".retry1" {
			retries++
		}
	}
	if huntAgents == 0 {
		t.Fatal("no hunt agents ran")
	}
	if producedTrue != 0 {
		t.Errorf("no agent wrote anything, yet produced=true on %d records", producedTrue)
	}
	if retries == 0 {
		t.Error("expected bounded re-runs (.retry1 agents) for missing deliverables")
	}
	h := huntExecOf(t, results)
	if h.Complete {
		t.Error("hunt must not be complete with missing deliverables")
	}
	missing, twoAttempts := 0, 0
	for _, f := range h.Detail {
		if f.Status == HuntFileMissing {
			missing++
		}
		if f.Attempts == 2 {
			twoAttempts++
		}
	}
	if missing == 0 {
		t.Error("hunt_execution.json must name the missing deliverables")
	}
	if twoAttempts == 0 {
		t.Error("per-file detail must record attempts=2 after the re-run")
	}
	ru := reviewUnitsOf(t, results)
	if ru.Counts.Failed == 0 && ru.Counts.Skipped == 0 {
		t.Errorf("routes of failed assignments must be failed/skipped, got %+v", ru.Counts)
	}
	if containsStr(rec.PhasesCompleted, "2") {
		t.Error("phase 2 must not count as completed")
	}
}

// FR-017: when the bounded re-run succeeds, the deliverable is valid, attempts=2, and
// the assignment is a success (retry recorded, not hidden).
func TestMissingDeliverableRecoveredByRerun(t *testing.T) {
	repo := filepath.Join(repoRoot(t), "testdata", "vulnapp")
	results := t.TempDir()
	spec := brokenSpec(repo, results)
	spec.Phases = []string{"1", "2"}
	rec, err := Execute(context.Background(), spec, Providers{Hunt: newRetryOnceWriter()}, staticSkill{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	h := huntExecOf(t, results)
	valid, twoAttempts := 0, 0
	for _, f := range h.Detail {
		if f.Status == HuntFileValid {
			valid++
		}
		if f.Attempts == 2 {
			twoAttempts++
		}
	}
	if valid == 0 || twoAttempts == 0 {
		t.Errorf("re-run should recover deliverables: valid=%d attempts2=%d detail=%+v", valid, twoAttempts, h.Detail)
	}
	if !containsStr(rec.PhasesCompleted, "2") {
		t.Error("phase 2 should complete once all deliverables are recovered")
	}
}

// FR-017: an unplanned file under results/ is reported as misplaced and NOT deleted.
func TestMisplacedHuntOutputReportedNotDeleted(t *testing.T) {
	repo := filepath.Join(repoRoot(t), "testdata", "vulnapp")
	results := t.TempDir()
	os.MkdirAll(filepath.Join(results, "results"), 0o755)
	stray := filepath.Join(results, "results", "stray_output.md")
	os.WriteFile(stray, []byte("# stray"), 0o644)
	spec := brokenSpec(repo, results)
	spec.Phases = []string{"1", "2"}
	if _, err := Execute(context.Background(), spec, Providers{Hunt: &pathWriter{model: "m"}}, staticSkill{}, nil); err != nil {
		t.Fatal(err)
	}
	h := huntExecOf(t, results)
	found := false
	for _, f := range h.Detail {
		if f.Path == "results/stray_output.md" && f.Status == HuntFileMisplaced {
			found = true
		}
	}
	if !found {
		t.Errorf("stray file must be reported misplaced: %+v", h.Detail)
	}
	if _, err := os.Stat(stray); err != nil {
		t.Error("misplaced file must never be deleted to pass validation")
	}
}
