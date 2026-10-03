package server

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"vhlocal/internal/apps"
	"vhlocal/internal/server/testsupport"
)

// C-P4 / C-X2 (Polish, SC-006/SC-007): using the feature's views — stats, the
// report-dir guard (via ListSummaries), a forget, and a ledger clear — never removes
// or alters real report files, and report-only apps stay discoverable.
func TestFeature008Preservation(t *testing.T) {
	base := t.TempDir()
	ledgerDir := filepath.Join(base, "ledger")
	t.Setenv("VHLOCAL_LEDGER_DIR", ledgerDir)
	reportsDir := filepath.Join(base, "reports")
	os.MkdirAll(reportsDir, 0o755)

	// Two real applications (report-only), a stray dir, and two ledgers.
	testsupport.SeedReport(t, reportsDir, testsupport.ReportSeed{
		Name: "alpha", Repo: "/repos/alpha", Created: time.Unix(1000, 0), Readme: true,
		PromptTokens: 1000, CompletionTokens: 100, StartedAt: 10, FinishedAt: 40,
		Findings: []map[string]any{{"severity": "High", "classification": "statically_supported"}},
	})
	testsupport.SeedReport(t, reportsDir, testsupport.ReportSeed{
		Name: "bravo", Repo: "/repos/bravo", Created: time.Unix(2000, 0), Readme: true,
		Findings: []map[string]any{{"severity": "Low", "classification": "hypothesis"}},
	})
	testsupport.SeedStrayDir(t, reportsDir, "leftover")
	testsupport.SeedLedger(t, ledgerDir, apps.SlugFor("/repos/alpha"), "/repos/alpha", 2)
	testsupport.SeedLedger(t, ledgerDir, "keep-33333333", "/repos/keep", 1)

	before := hashTree(t, reportsDir)

	// Exercise the feature's read/aggregation + one delete of each kind.
	_ = statsOf(t, reportsDir)
	_ = apps.ListSummaries(reportsDir)
	if err := apps.Forget(apps.SlugFor("/repos/alpha")); err != nil {
		t.Fatal(err)
	}
	s := &Server{cfg: Config{ReportsDir: reportsDir}}
	req := httptest.NewRequest("DELETE", "/api/ledgers/keep-33333333", nil)
	req.SetPathValue("slug", "keep-33333333")
	s.handleClearLedger(httptest.NewRecorder(), req)

	// Report files are byte-identical (nothing overwritten/deleted).
	if after := hashTree(t, reportsDir); !equalMaps(after, before) {
		t.Errorf("report files changed:\nbefore=%v\nafter=%v", before, after)
	}
	// Report-only app 'bravo' still discoverable (guard didn't over-suppress).
	found := false
	for _, s := range apps.ListSummaries(reportsDir) {
		if s.Slug == apps.SlugFor("/repos/bravo") {
			found = true
		}
	}
	if !found {
		t.Errorf("report-only application must remain discoverable (C-P2/SC-007)")
	}
}
