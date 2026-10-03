package authz

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func moduleRoot(t *testing.T) string {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}

func TestBuildAuthzMapOnFixture(t *testing.T) {
	repo := filepath.Join(moduleRoot(t), "testdata", "vulnapp")
	m := Build(repo)
	if m.Total < 5 {
		t.Fatalf("expected >=5 endpoints, got %d", m.Total)
	}
	// main.py has a session check (VULN-E "if 'uid' not in session"), so its
	// routes are marked protected; gaps must be a strict subset of total.
	if m.Protected == 0 {
		t.Errorf("expected some protected endpoints (main.py has a session check)")
	}
	if len(m.Gaps) > m.Total {
		t.Errorf("gaps (%d) exceed total (%d)", len(m.Gaps), m.Total)
	}
	if m.Protected+len(m.Gaps) != m.Total {
		t.Errorf("protected(%d)+gaps(%d) != total(%d)", m.Protected, len(m.Gaps), m.Total)
	}
}

func TestWriteAuthzMap(t *testing.T) {
	repo := filepath.Join(moduleRoot(t), "testdata", "vulnapp")
	dir := t.TempDir()
	path, err := Write(repo, dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err != nil || filepath.Base(path) != "authz_map.json" {
		t.Fatalf("authz_map.json not written: %v", err)
	}
}
