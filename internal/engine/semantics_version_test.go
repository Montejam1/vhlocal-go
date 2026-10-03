package engine

import (
	"os"
	"path/filepath"
	"testing"

	"vhlocal/internal/reports"
)

// Feature 015 (FR-019, T010): a feature-014 review_units.json (no semantics_version)
// loads as version 1 with the read-overlap label; reports expose the version.
func TestReviewUnitsLegacyRecordLoadsAsV1(t *testing.T) {
	dir := t.TempDir()
	src, err := os.ReadFile(filepath.Join(repoRoot(t), "testdata", "replay-171", "review_units.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ReviewUnitsFile), src, 0o644); err != nil {
		t.Fatal(err)
	}
	ru, ok := loadReviewUnits(dir)
	if !ok {
		t.Fatal("legacy record failed to load")
	}
	if ru.SemanticsVersion != CoverageSemanticsV1 {
		t.Errorf("semantics_version = %d, want 1 for a record without the field", ru.SemanticsVersion)
	}
	if ru.Label() != "read-overlap evidence (v1)" {
		t.Errorf("label = %q", ru.Label())
	}
	if ru.Counts.ReviewedNoIssue != 93 {
		t.Errorf("legacy counts must load unchanged: %+v", ru.Counts)
	}
	// reports.Load exposes the version (dir must look like a report dir).
	rdir := filepath.Join(t.TempDir(), "app_VULNHUNT_RESULTS_m_2026-09-29-000000")
	os.MkdirAll(rdir, 0o755)
	os.WriteFile(filepath.Join(rdir, ReviewUnitsFile), src, 0o644)
	os.WriteFile(filepath.Join(rdir, "README.md"), []byte("# r\n"), 0o644)
	r, ok := reports.Load(rdir)
	if !ok || r.CoverageSemantics != 1 {
		t.Errorf("reports.Load coverage_semantics = %d (ok=%v), want 1", r.CoverageSemantics, ok)
	}
	if (&ReviewUnits{}).Label() == "" || SemanticsLabel(CoverageSemanticsV2) != "validated handler dispositions (v2)" {
		t.Error("semantics labels incomplete")
	}
}
