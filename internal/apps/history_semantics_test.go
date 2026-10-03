package apps

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"vhlocal/internal/server/testsupport"
)

// T054 (FR-019): application history rows carry the review-unit evidence standard
// of each scan (2 for a v2 record, 1 for a 014-era record, absent without one).
func TestHistoryRowsCarryCoverageSemantics(t *testing.T) {
	reportsDir, _ := setup(t)
	repo := "/repos/echo"
	if _, err := Register(repo); err != nil {
		t.Fatal(err)
	}
	d1 := testsupport.SeedReport(t, reportsDir, testsupport.ReportSeed{
		Name: "echo", Repo: repo, Stamp: "2026-09-01-000000", Created: time.Unix(1000, 0),
		Findings: []map[string]any{}, CoverageStatus: "complete",
	})
	os.WriteFile(filepath.Join(d1, "review_units.json"), []byte(`{"revision":"r","counts":{"total":1},"gaps":[]}`), 0o644)
	d2 := testsupport.SeedReport(t, reportsDir, testsupport.ReportSeed{
		Name: "echo", Repo: repo, Stamp: "2026-09-16-000000", Created: time.Unix(2000, 0),
		Findings: []map[string]any{}, CoverageStatus: "complete",
	})
	os.WriteFile(filepath.Join(d2, "review_units.json"), []byte(`{"semantics_version":2,"revision":"r","counts":{"total":1},"axes":{},"gaps":[]}`), 0o644)
	os.WriteFile(filepath.Join(d2, "remediation_groups.json"), []byte(`{"version":1,"groups":[],"raw_supported":4,"grouped":2}`), 0o644)
	testsupport.SeedReport(t, reportsDir, testsupport.ReportSeed{
		Name: "echo", Repo: repo, Stamp: "2026-09-20-000000", Created: time.Unix(3000, 0),
		Findings: []map[string]any{}, CoverageStatus: "complete",
	})
	d, ok := BuildDetail(SlugFor(repo), reportsDir)
	if !ok || len(d.ScanHistory) != 3 {
		t.Fatalf("detail ok=%v rows=%d", ok, len(d.ScanHistory))
	}
	got := map[string]int{}
	for _, r := range d.ScanHistory {
		got[r.ID] = r.CoverageSemantics
	}
	if got[filepath.Base(d1)] != 1 || got[filepath.Base(d2)] != 2 {
		t.Errorf("coverage_semantics by row = %v (want d1=1, d2=2)", got)
	}
	for _, r := range d.ScanHistory {
		if r.ID == filepath.Base(d2) && r.Groups != 2 {
			t.Errorf("history row must carry the remediation group count: %+v", r)
		}
	}
	for _, r := range d.ScanHistory {
		if r.ID != filepath.Base(d1) && r.ID != filepath.Base(d2) && r.CoverageSemantics != 0 {
			t.Errorf("a scan without a record must not claim a semantics version: %d", r.CoverageSemantics)
		}
	}
}
