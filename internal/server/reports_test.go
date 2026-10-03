package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"vhlocal/internal/apps"
	"vhlocal/internal/server/testsupport"
)

// reportsServer builds a handler over reportsDir with no job store (read-only APIs).
func reportsServer(reportsDir string) http.Handler {
	s := &Server{cfg: Config{ReportsDir: reportsDir}}
	return s.Handler()
}

// req issues a request with an optional raw JSON body and returns the recorder.
func req(t *testing.T, h http.Handler, method, path, raw string) *httptest.ResponseRecorder {
	t.Helper()
	var body any
	if raw != "" {
		var m map[string]any
		if err := json.Unmarshal([]byte(raw), &m); err != nil {
			t.Fatal(err)
		}
		body = m
	}
	w, _ := do(t, h, method, path, body)
	return w
}

// T053 (FR-025): report-file endpoints keep 404 (absent) distinct from 5xx (error):
// a missing file is 404; a file that exists but cannot be read is 500; an unknown
// report id is 404; the application detail is 404 for an unknown slug.
func TestReportFileAbsentVersusError(t *testing.T) {
	base := t.TempDir()
	t.Setenv("VHLOCAL_LEDGER_DIR", filepath.Join(base, "ledger"))
	reportsDir := filepath.Join(base, "reports")
	os.MkdirAll(reportsDir, 0o755)
	dir := testsupport.SeedReport(t, reportsDir, testsupport.ReportSeed{
		Name: "shop", Repo: "/repos/shop", Created: time.Unix(1000, 0), ThreatModel: "ok", Readme: true,
	})
	id := filepath.Base(dir)
	s := reportsServer(reportsDir)

	if w := req(t, s, "GET", "/api/reports/"+id+"/file?path=threat_model.md", ""); w.Code != 200 {
		t.Fatalf("present file: %d %s", w.Code, w.Body.String())
	}
	if w := req(t, s, "GET", "/api/reports/"+id+"/file?path=sbom.cdx.json", ""); w.Code != 404 {
		t.Errorf("absent file must be 404, got %d", w.Code)
	}
	if w := req(t, s, "GET", "/api/reports/nope_VULNHUNT_RESULTS_m_2026-01-01-000000/file?path=README.md", ""); w.Code != 404 {
		t.Errorf("unknown report must be 404, got %d", w.Code)
	}
	if w := req(t, s, "GET", "/api/applications/"+apps.SlugFor("/repos/missing"), ""); w.Code != 404 {
		t.Errorf("unknown application must be 404, got %d", w.Code)
	}
	// Unreadable file → 5xx, never 404 (skipped when running as root, who can read anything).
	if os.Geteuid() == 0 {
		t.Skip("permission-denied cannot be simulated as root")
	}
	locked := filepath.Join(dir, "locked.md")
	if err := os.WriteFile(locked, []byte("secret"), 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(locked, 0o644) })
	w := req(t, s, "GET", "/api/reports/"+id+"/file?path=locked.md", "")
	if w.Code < 500 || w.Code > 599 {
		t.Errorf("unreadable file must be a 5xx server error, got %d %s", w.Code, w.Body.String())
	}
}

// FR-025/026 on the API: /api/applications/{slug} carries the newest-valid artifact
// selection with disclosure, and /api/config carries the build identity (SC-012).
func TestApplicationArtifactsAndBuildIdentityOnAPI(t *testing.T) {
	base := t.TempDir()
	t.Setenv("VHLOCAL_LEDGER_DIR", filepath.Join(base, "ledger"))
	reportsDir := filepath.Join(base, "reports")
	os.MkdirAll(reportsDir, 0o755)
	testsupport.SeedReport(t, reportsDir, testsupport.ReportSeed{
		Name: "shop", Repo: "/repos/shop", Stamp: "2026-09-01-000000", Created: time.Unix(1000, 0),
		PhasesRequested: []string{"1", "1t"}, PhasesCompleted: []string{"1", "1t"}, ThreatModel: "ok", GitCommit: "abc", Readme: true,
	})
	testsupport.SeedReport(t, reportsDir, testsupport.ReportSeed{
		Name: "shop", Repo: "/repos/shop", Stamp: "2026-09-02-000000", Created: time.Unix(2000, 0),
		PhasesRequested: []string{"1", "1t"}, PhasesCompleted: []string{"1"}, PhasesSkipped: []string{"1t"}, Readme: true,
	})
	s := reportsServer(reportsDir)
	w := req(t, s, "GET", "/api/applications/"+apps.SlugFor("/repos/shop"), "")
	if w.Code != 200 {
		t.Fatalf("detail: %d %s", w.Code, w.Body.String())
	}
	var d map[string]any
	json.Unmarshal(w.Body.Bytes(), &d)
	arts, _ := d["artifacts"].(map[string]any)
	tm, _ := arts["threat_model"].(map[string]any)
	if tm["valid"] != true || tm["revision"] != "abc" || tm["older_than_latest"] != true {
		t.Errorf("threat_model selection on API = %v", tm)
	}
	sb, _ := arts["sbom"].(map[string]any)
	if sb["valid"] != false || sb["reason"] == "" {
		t.Errorf("sbom absence must be explained on API = %v", sb)
	}

	w = req(t, s, "GET", "/api/config", "")
	var cfg map[string]any
	json.Unmarshal(w.Body.Bytes(), &cfg)
	b, _ := cfg["build"].(map[string]any)
	if b == nil || b["version"] == "" || b["embedded_assets_hash"] == "" || b["built_at_source"] == "" {
		t.Errorf("/api/config build identity incomplete: %v", b)
	}
}

// FR-028 on the API: preview is read-only; apply needs the exact token (400
// otherwise, nothing changes); the literal /cleanup route wins over {slug}.
func TestCleanupAPI(t *testing.T) {
	base := t.TempDir()
	t.Setenv("VHLOCAL_LEDGER_DIR", filepath.Join(base, "ledger"))
	reportsDir := filepath.Join(base, "reports")
	os.MkdirAll(reportsDir, 0o755)
	if _, err := apps.Register("/tmp/TestLeak77/001"); err != nil {
		t.Fatal(err)
	}
	if _, err := apps.SetName(apps.SlugFor("/repos/keep"), "Keep", "/repos/keep"); err != nil {
		t.Fatal(err)
	}
	s := reportsServer(reportsDir)
	w := req(t, s, "GET", "/api/applications/cleanup", "")
	if w.Code != 200 {
		t.Fatalf("preview: %d %s", w.Code, w.Body.String())
	}
	var pv apps.CleanupPreview
	json.Unmarshal(w.Body.Bytes(), &pv)
	if len(pv.Candidates) != 1 || pv.PreservedCount != 1 || pv.PreviewToken == "" {
		t.Fatalf("preview = %+v", pv)
	}
	if w := req(t, s, "POST", "/api/applications/cleanup", `{}`); w.Code != 400 {
		t.Errorf("apply without token must be 400, got %d", w.Code)
	}
	if w := req(t, s, "POST", "/api/applications/cleanup", `{"confirm":"wrong"}`); w.Code != 400 {
		t.Errorf("apply with wrong token must be 400, got %d", w.Code)
	}
	if len(apps.List()) != 2 {
		t.Fatal("refused apply changed the registry")
	}
	w = req(t, s, "POST", "/api/applications/cleanup", `{"confirm":"`+pv.PreviewToken+`"}`)
	if w.Code != 200 {
		t.Fatalf("apply: %d %s", w.Code, w.Body.String())
	}
	var res apps.CleanupResult
	json.Unmarshal(w.Body.Bytes(), &res)
	if len(res.Removed) != 1 || res.BackupPath == "" {
		t.Errorf("apply result = %+v", res)
	}
	if _, err := os.Stat(res.BackupPath); err != nil {
		t.Errorf("backup missing: %v", err)
	}
	if l := apps.List(); len(l) != 1 || l[0].Name != "Keep" {
		t.Errorf("registry after apply = %+v", l)
	}
}
