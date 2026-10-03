package apps

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"vhlocal/internal/server/testsupport"
)

// C-P3 (US2): stray non-report subdirectories under the reports dir do not become
// applications, and the real set is stable across re-derivation (as a restart does).
func TestPhantomApplicationsExcluded(t *testing.T) {
	base := t.TempDir()
	t.Setenv("VHLOCAL_LEDGER_DIR", filepath.Join(base, "ledger"))
	reportsDir := filepath.Join(base, "reports")
	os.MkdirAll(reportsDir, 0o755)

	// Two real applications (report-only discovery, no registry/ledger).
	testsupport.SeedReport(t, reportsDir, testsupport.ReportSeed{
		Name: "alpha", Repo: "/repos/alpha", Created: time.Unix(1000, 0), Readme: true,
		Findings: []map[string]any{{"severity": "High", "classification": "statically_supported"}},
	})
	testsupport.SeedReport(t, reportsDir, testsupport.ReportSeed{
		Name: "bravo", Repo: "/repos/bravo", Created: time.Unix(2000, 0), Readme: true,
		Findings: []map[string]any{{"severity": "Low", "classification": "hypothesis"}},
	})
	// Stray non-report directories that previously became phantom apps.
	testsupport.SeedStrayDir(t, reportsDir, "leftover")
	testsupport.SeedStrayDir(t, reportsDir, ".cache")

	first := ListSummaries(reportsDir)
	if len(first) != 2 {
		var names []string
		for _, s := range first {
			names = append(names, s.Slug+"("+s.Name+")")
		}
		t.Fatalf("expected exactly 2 real applications, got %d: %v", len(first), names)
	}
	// Re-derivation (what a restart does) yields the same set — no new empties.
	if second := ListSummaries(reportsDir); len(second) != 2 {
		t.Errorf("application count not stable across re-derivation: %d", len(second))
	}
	// Neither phantom appears.
	for _, s := range first {
		if s.Name == "leftover" || s.Slug == "" || (s.Scans == 0 && !s.Named && s.OpenFindings == nil) {
			t.Errorf("a phantom/empty application leaked: %+v", s)
		}
	}
}
