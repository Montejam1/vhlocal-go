package engine

import (
	"context"
	"path/filepath"
	"testing"
)

// Feature 013 (FR-022): resume with a COMPATIBLE config reuses prior work; resume
// with an incompatible change (here, a different model) discards the stale state
// and replans — recorded explicitly, never silently reusing incompatible work.
func TestResumeCompatibility(t *testing.T) {
	repo := filepath.Join(repoRoot(t), "testdata", "vulnapp")
	results := t.TempDir()

	// Initial run establishes scan_meta.json + completed state.
	base := brokenSpec(repo, results)
	if _, err := Execute(context.Background(), base, Providers{Hunt: &pathWriter{model: "m"}}, staticSkill{}, nil); err != nil {
		t.Fatal(err)
	}

	t.Run("compatible resume reuses work", func(t *testing.T) {
		spec := brokenSpec(repo, results)
		spec.Resume = true
		rec, err := Execute(context.Background(), spec, Providers{Hunt: &pathWriter{model: "m"}}, staticSkill{}, nil)
		if err != nil {
			t.Fatal(err)
		}
		if rec.ResumeInvalidated != "" {
			t.Errorf("compatible resume must not invalidate: %q", rec.ResumeInvalidated)
		}
		// At least one phase should have been skipped (reused).
		if len(rec.PhasesSkipped) == 0 {
			t.Error("compatible resume should reuse (skip) at least one completed phase")
		}
	})

	t.Run("incompatible resume invalidates and replans", func(t *testing.T) {
		spec := brokenSpec(repo, results)
		spec.Resume = true
		spec.Model = "different-model" // invalidating change (provenance + content)
		rec, err := Execute(context.Background(), spec, Providers{Hunt: &pathWriter{model: "different-model"}}, staticSkill{}, nil)
		if err != nil {
			t.Fatal(err)
		}
		if rec.ResumeInvalidated == "" {
			t.Error("an incompatible model change must invalidate the resume explicitly")
		}
		// Stale work was discarded → nothing skipped for resume reason on this run.
		for _, p := range rec.PhasesSkipped {
			if p != "1t" { // 1t is skipped because threat model is off, not resume-reuse
				t.Errorf("incompatible resume must not reuse phase %q", p)
			}
		}
	})
}
