package apps

import (
	"os"
	"testing"

	"vhlocal/internal/testisolate"
)

// TestMain isolates this package's tests from the operator's real stores (feature
// 014, FR-027 / SC-011): HOME and every VHLOCAL_* store variable point at a temp
// root for the whole binary, so nothing here can append to ~/.vhlocal/vhlocal.log
// or touch the real registry, ledger, jobs, activity, reviews or reports.
func TestMain(m *testing.M) {
	_, _, cleanup := testisolate.Isolate("vhlocal-apps-test-home-")
	code := m.Run()
	cleanup()
	os.Exit(code)
}
