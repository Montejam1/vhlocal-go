package cli

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

func TestSbomCmd(t *testing.T) {
	repo := filepath.Join(moduleRoot(t), "testdata", "vulnapp")
	out := filepath.Join(t.TempDir(), "sbom.cdx.json")
	if code := sbomCmd([]string{"--out", out, repo}); code != ExitOK {
		t.Fatalf("sbom exit %d", code)
	}
	if _, err := os.Stat(out); err != nil {
		t.Errorf("sbom output missing: %v", err)
	}
}

func TestReportRegenerate(t *testing.T) {
	// Build a minimal results dir with scan_meta + a phase2b finding, then
	// regenerate — expect findings.json + SCAN_REPORT.* to appear.
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "scan_meta.json"),
		[]byte(`{"repo":"","results_dir":"","model":"m","num_ctx":4096,"phases_requested":["2b"],"phases_completed":["2b"],"engine_version":"0.1.0","quality_strictness":"balanced"}`), 0o644)
	os.WriteFile(filepath.Join(dir, "phase2b_output.md"),
		[]byte("### [VULN-001] SQLi\n- **CWE**: CWE-89\n- **Severity**: High\n- **Location**: db.py:1 execute()\n- **Entry point**: GET /s?q=\n- **Data flow**: q -> execute()\n"), 0o644)

	if code := reportCmd([]string{dir}); code != ExitOK {
		t.Fatalf("report regenerate exit %d", code)
	}
	for _, name := range []string{"findings.json", "SCAN_REPORT.md", "SCAN_REPORT.html", "findings.sarif"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Errorf("regenerate did not produce %s", name)
		}
	}
}

func TestReportDeleteGuard(t *testing.T) {
	reportsDir := t.TempDir()
	outside := t.TempDir()
	// deleting a dir outside the reports dir is refused
	if code := reportCmd([]string{"--delete", "--yes", "--reports-dir", reportsDir, outside}); code == ExitOK {
		t.Error("delete outside reports dir should be refused")
	}
}

func TestLogsCmdMissingFileOK(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "nope.log")
	if code := logsCmd([]string{"--log-file", missing}); code != ExitOK {
		t.Errorf("logs on missing file should be OK, got %d", code)
	}
}
