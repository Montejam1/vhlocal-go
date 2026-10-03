package reports

import (
	"os"
	"path/filepath"
	"testing"
)

// C-P1/C-P2 (US2): the report index rejects directories that are neither
// results-named nor hold a recognized deliverable (the phantom source), while
// accepting real report dirs — preserving report-only discovery.
func TestReportDirGuard(t *testing.T) {
	dir := t.TempDir()

	// A stray directory with no deliverable → NOT a report (C-P1).
	stray := filepath.Join(dir, "random-notes")
	os.MkdirAll(stray, 0o755)
	os.WriteFile(filepath.Join(stray, "notes.txt"), []byte("not a scan\n"), 0o644)

	// A results-named dir (even empty) → a report.
	named := filepath.Join(dir, "app_VULNHUNT_RESULTS_m_2026-09-01-000000")
	os.MkdirAll(named, 0o755)

	// A non-results-named dir that holds a deliverable → a report (report-only
	// discovery preserved, C-P2).
	deliv := filepath.Join(dir, "custom-out")
	os.MkdirAll(deliv, 0o755)
	os.WriteFile(filepath.Join(deliv, "README.md"), []byte("# report\n"), 0o644)

	if _, ok := Load(stray); ok {
		t.Errorf("a stray non-report directory must not load as a report")
	}
	if _, ok := Load(named); !ok {
		t.Errorf("a results-named directory must load as a report")
	}
	if _, ok := Load(deliv); !ok {
		t.Errorf("a directory holding a recognized deliverable must load as a report")
	}

	// Index must include the two real reports and exclude the stray.
	rs, _ := Index(dir)
	got := map[string]bool{}
	for _, r := range rs {
		got[filepath.Base(r.Path)] = true
	}
	if got["random-notes"] {
		t.Errorf("Index must exclude the stray directory")
	}
	if !got["custom-out"] || !got[filepath.Base(named)] {
		t.Errorf("Index must include real report dirs; got %v", got)
	}
}
