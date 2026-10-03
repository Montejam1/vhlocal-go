package server

import (
	"os"
	"path/filepath"
	"testing"

	seed "vhlocal/internal/server/testsupport"
)

// T047 (FR-054, SC-009): the analyst-workspace additions must not regress the
// features 007–009 behavior. Forgetting an application still keeps its reports on
// disk and removes it from the list; clearing a ledger keeps reports; the
// dashboard metrics remain served. (The legacy served UI and its Table/List
// toggle are browser-verified, operator-owned.)
func TestForgetApplicationPreservesReports(t *testing.T) {
	dir := t.TempDir()
	ledgerDir := filepath.Join(t.TempDir(), "ledger")
	t.Setenv("VHLOCAL_LEDGER_DIR", ledgerDir)
	t.Setenv("VHLOCAL_REVIEWS_DIR", t.TempDir())

	repo := "/r/app"
	reportDir := seed.SeedReport(t, dir, seed.ReportSeed{
		Name: "app", Model: "m1", Stamp: "2026-09-01-000000", Repo: repo,
		Findings: []map[string]any{{"id": "F1", "stable_identity": "s1", "severity": "High", "severity_rank": 2}},
	})
	h := (&Server{cfg: Config{ReportsDir: dir}}).Handler()

	// The application is listed (discovery via its report).
	_, m := do(t, h, "GET", "/api/applications", nil)
	apps, _ := m["applications"].([]any)
	if len(apps) == 0 {
		t.Fatalf("application not discovered from its report: %v", m)
	}
	slug, _ := apps[0].(map[string]any)["slug"].(string)
	if slug == "" {
		t.Fatal("application has no slug")
	}

	// Forget it.
	w, _ := do(t, h, "DELETE", "/api/applications/"+slug, nil)
	if w.Code != 200 {
		t.Fatalf("forget code=%d", w.Code)
	}

	// Reports on disk are preserved (feature 009 semantics unchanged).
	if !dirExists(reportDir) {
		t.Fatal("forgetting an application must KEEP its report files on disk")
	}
	// It is gone from the list (hidden), not the reports.
	_, m2 := do(t, h, "GET", "/api/applications", nil)
	if apps2, _ := m2["applications"].([]any); len(apps2) != 0 {
		t.Fatalf("forgotten application still listed: %v", m2["applications"])
	}

	// The dashboard still serves its preserved metrics over the same reports.
	sm := statsOf(t, dir)
	if numf(t, sm, "scans") != 1 {
		t.Fatalf("stats.scans=%v want 1 (report preserved)", sm["scans"])
	}
	for _, k := range requiredStatsKeys {
		if _, ok := sm[k]; !ok {
			t.Fatalf("preserved metric %q missing after forget", k)
		}
	}
}

func dirExists(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.IsDir()
}
