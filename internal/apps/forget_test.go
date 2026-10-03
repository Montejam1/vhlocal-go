package apps

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"vhlocal/internal/server/testsupport"
)

// C-A3 (US3): forgetting an application removes it from the list but preserves its
// report files on disk, and re-scanning (Register) un-hides it.
func TestForgetPreservesReportsAndRescanUnhides(t *testing.T) {
	base := t.TempDir()
	t.Setenv("VHLOCAL_LEDGER_DIR", filepath.Join(base, "ledger"))
	reportsDir := filepath.Join(base, "reports")
	os.MkdirAll(reportsDir, 0o755)
	repo := "/repos/echo"

	reportPath := testsupport.SeedReport(t, reportsDir, testsupport.ReportSeed{
		Name: "echo", Repo: repo, Created: time.Unix(1000, 0), Readme: true,
		Findings: []map[string]any{{"severity": "High", "classification": "statically_supported"}},
	})
	if _, err := Register(repo); err != nil {
		t.Fatal(err)
	}
	slug := SlugFor(repo)

	if err := Forget(slug); err != nil {
		t.Fatal(err)
	}
	for _, s := range ListSummaries(reportsDir) {
		if s.Slug == slug {
			t.Errorf("forgotten application must not appear in the list")
		}
	}
	// Report files preserved on disk.
	if _, err := os.Stat(filepath.Join(reportPath, "scan_meta.json")); err != nil {
		t.Errorf("forget must preserve report files: %v", err)
	}
	// Re-scan (Register) un-hides.
	if _, err := Register(repo); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, s := range ListSummaries(reportsDir) {
		if s.Slug == slug {
			found = true
		}
	}
	if !found {
		t.Errorf("re-registering must un-hide the application")
	}
}
