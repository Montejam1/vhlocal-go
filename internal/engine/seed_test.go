package engine

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Feature 013 (FR-008/009, SC-001): route seeding injects the deterministic
// multi-language inventory into Phase-1 recon when on, omits it when off, and
// records honest provenance. HTTP 201 alone is not sufficient — the seeded
// context must actually reach the recon task.
func TestRouteSeedAppliedAndOmitted(t *testing.T) {
	repo := filepath.Join(repoRoot(t), "testdata", "vulnapp")

	// On: seed reaches the task and provenance is recorded.
	recOn := &RunRecord{}
	specOn := ScanSpec{Repo: repo, Phases: []string{"1", "2"}, SeedRoutes: true}
	taskOn := applyRouteSeed(recOn, specOn, "BASE TASK")
	if !strings.Contains(taskOn, "Seeded entry-point inventory") {
		t.Error("seed context was not injected into the recon task")
	}
	if !recOn.SeedRoutesRequested || !recOn.SeedRoutesApplied || recOn.SeedRoutesCount == 0 {
		t.Errorf("route-seed provenance not recorded: %+v", recOn)
	}
	// Bounded, source-grounded: never claims to be complete.
	if !strings.Contains(taskOn, "NOT a complete") {
		t.Error("seed must disclose it is not a complete attack surface")
	}

	// Off: nothing injected, no provenance.
	recOff := &RunRecord{}
	specOff := ScanSpec{Repo: repo, Phases: []string{"1", "2"}, SeedRoutes: false}
	taskOff := applyRouteSeed(recOff, specOff, "BASE TASK")
	if taskOff != "BASE TASK" {
		t.Error("seed_routes=false must not inject any context")
	}
	if recOff.SeedRoutesRequested || recOff.SeedRoutesApplied {
		t.Error("seed_routes=false must record no seeding")
	}
}

// FR-009: seed requested but recon not selected is recorded not-applicable, and no
// extra phase is launched (verified via Execute with a non-recon phase plan).
func TestRouteSeedNotApplicableWithoutRecon(t *testing.T) {
	repo := filepath.Join(repoRoot(t), "testdata", "vulnapp")
	spec := brokenSpec(repo, t.TempDir())
	spec.Phases = []string{"4"} // no recon phase
	spec.SeedRoutes = true
	rec, err := Execute(context.Background(), spec, Providers{Hunt: &pathWriter{model: "m"}}, staticSkill{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !rec.SeedRoutesRequested {
		t.Error("requested seed should be recorded even when not applicable")
	}
	if rec.SeedRoutesApplied {
		t.Error("seed must not be applied when no recon phase is selected")
	}
	if rec.SeedRoutesUnavailable == "" {
		t.Error("not-applicable seed must record a reason")
	}
	// No recon phase should appear in the executed phases.
	for _, p := range rec.PhasesCompleted {
		if p == "1" || p == "1t" {
			t.Errorf("seeding must not silently launch a recon phase: %v", rec.PhasesCompleted)
		}
	}
}

// FR-008: empty inventory yields no seed and is disclosed, never presented as a
// complete list.
func TestRouteSeedEmptyInventoryDisclosed(t *testing.T) {
	empty := t.TempDir()
	_ = os.WriteFile(filepath.Join(empty, "README.md"), []byte("# nothing to scan"), 0o644)
	rec := &RunRecord{}
	spec := ScanSpec{Repo: empty, Phases: []string{"1"}, SeedRoutes: true}
	task := applyRouteSeed(rec, spec, "BASE")
	if task != "BASE" {
		t.Error("empty inventory must not inject a fake seed")
	}
	if !rec.SeedRoutesRequested || rec.SeedRoutesApplied || rec.SeedRoutesUnavailable == "" {
		t.Errorf("empty inventory must be disclosed as unavailable: %+v", rec)
	}
}
