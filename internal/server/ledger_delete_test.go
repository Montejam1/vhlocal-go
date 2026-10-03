package server

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"vhlocal/internal/server/testsupport"
)

// C-L3 (US4): deleting a ledger removes only its tracking file; other ledgers and
// all report files are unaffected.
func TestClearLedgerPreservesOthersAndReports(t *testing.T) {
	base := t.TempDir()
	ledgerDir := filepath.Join(base, "ledger")
	t.Setenv("VHLOCAL_LEDGER_DIR", ledgerDir)
	reportsDir := filepath.Join(base, "reports")
	os.MkdirAll(reportsDir, 0o755)

	testsupport.SeedLedger(t, ledgerDir, "alpha-11111111", "/repos/alpha", 3)
	testsupport.SeedLedger(t, ledgerDir, "bravo-22222222", "/repos/bravo", 1)
	reportPath := testsupport.SeedReport(t, reportsDir, testsupport.ReportSeed{
		Name: "alpha", Repo: "/repos/alpha", Created: time.Unix(1000, 0), Readme: true,
	})

	s := &Server{cfg: Config{ReportsDir: reportsDir}}
	req := httptest.NewRequest("DELETE", "/api/ledgers/alpha-11111111", nil)
	req.SetPathValue("slug", "alpha-11111111")
	w := httptest.NewRecorder()
	s.handleClearLedger(w, req)
	if w.Code != 200 {
		t.Fatalf("clear ledger status=%d body=%s", w.Code, w.Body.String())
	}

	if _, err := os.Stat(filepath.Join(ledgerDir, "alpha-11111111.json")); err == nil {
		t.Errorf("deleted ledger json must be gone")
	}
	if _, err := os.Stat(filepath.Join(ledgerDir, "bravo-22222222.json")); err != nil {
		t.Errorf("other ledger must be unaffected: %v", err)
	}
	if _, err := os.Stat(filepath.Join(reportPath, "scan_meta.json")); err != nil {
		t.Errorf("report files must be preserved after a ledger delete: %v", err)
	}
}
