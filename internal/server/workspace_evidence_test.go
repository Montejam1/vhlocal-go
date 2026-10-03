package server

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"vhlocal/internal/server/testsupport"
)

// patchJSON merges extra keys into an existing JSON object file.
func patchJSON(t *testing.T, path string, extra map[string]any) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("unmarshal %s: %v", path, err)
	}
	for k, v := range extra {
		m[k] = v
	}
	nb, _ := json.MarshalIndent(m, "", "  ")
	if err := os.WriteFile(path, nb, 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// T017 (API-F3): the evidence endpoint returns an occurrence's revision-bound
// source state and narrative. With no accessible repo, source is unavailable but
// the request still succeeds (200), preserving access to other evidence.
func TestEvidenceEndpoint(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("VHLOCAL_REVIEWS_DIR", t.TempDir())
	testsupport.SeedReport(t, dir, testsupport.ReportSeed{
		Name: "app", Model: "m1", Stamp: "2026-09-01-000000", Repo: "/r/app",
		Findings: []map[string]any{{"id": "F1", "stable_identity": "s1", "severity": "High",
			"severity_rank": 1, "location": "a.go:1", "verification_record": map[string]any{"entry_point": "GET /x"}}},
	})
	h := (&Server{cfg: Config{ReportsDir: dir}}).Handler()
	_, m := do(t, h, "GET", "/api/findings", nil)
	occ := m["rows"].([]any)[0].(map[string]any)["occurrence"].(string)

	w, ev := do(t, h, "GET", "/api/findings/"+occ+"/evidence", nil)
	if w.Code != 200 {
		t.Fatalf("evidence code=%d", w.Code)
	}
	src, _ := ev["source"].(map[string]any)
	if src == nil || src["available"] != false {
		t.Fatalf("expected unavailable source (no repo at revision): %v", ev["source"])
	}
	narr, _ := ev["narrative"].(map[string]any)
	if narr == nil || narr["entry_point"] != "GET /x" {
		t.Fatalf("narrative missing entry_point: %v", ev["narrative"])
	}
}

// API-F3: when the repo is at the recorded commit, source is served bound to it.
func TestEvidenceServesRecordedRevision(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("VHLOCAL_REVIEWS_DIR", t.TempDir())
	repo := t.TempDir()
	const sha = "0123456789abcdef0123456789abcdef01234567"
	_ = os.MkdirAll(filepath.Join(repo, ".git"), 0o755)
	_ = os.WriteFile(filepath.Join(repo, ".git", "HEAD"), []byte(sha+"\n"), 0o644)
	_ = os.WriteFile(filepath.Join(repo, "a.go"), []byte("one\ntwo\nboom\n"), 0o644)

	// Seed a report whose scan_meta records repo + git_commit == sha.
	scan := testsupport.SeedReport(t, dir, testsupport.ReportSeed{
		Name: "app", Model: "m1", Stamp: "2026-09-01-000000", Repo: repo,
		Findings: []map[string]any{{"id": "F1", "stable_identity": "s1", "severity": "High", "severity_rank": 1, "location": "a.go:3"}},
	})
	// Patch scan_meta.json to add git_commit (SeedReport doesn't set it).
	metaPath := filepath.Join(scan, "scan_meta.json")
	patchJSON(t, metaPath, map[string]any{"git_commit": sha, "git_dirty": false})

	h := (&Server{cfg: Config{ReportsDir: dir}}).Handler()
	_, m := do(t, h, "GET", "/api/findings", nil)
	occ := m["rows"].([]any)[0].(map[string]any)["occurrence"].(string)
	_, ev := do(t, h, "GET", "/api/findings/"+occ+"/evidence", nil)
	src, _ := ev["source"].(map[string]any)
	if src == nil || src["available"] != true || src["focus_line"].(float64) != 3 {
		t.Fatalf("expected available source at line 3: %v", ev["source"])
	}
}

// API-C1: the comparison endpoint reports no-baseline honestly.
func TestComparisonEndpointNoBaseline(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("VHLOCAL_REVIEWS_DIR", t.TempDir())
	testsupport.SeedReport(t, dir, testsupport.ReportSeed{
		Name: "app", Model: "m1", Stamp: "2026-09-01-000000", Repo: "/r/app",
		Findings: []map[string]any{{"id": "F1", "stable_identity": "s1", "severity": "High", "severity_rank": 1, "location": "a.go:1"}},
	})
	h := (&Server{cfg: Config{ReportsDir: dir}}).Handler()
	_, m := do(t, h, "GET", "/api/findings", nil)
	occ := m["rows"].([]any)[0].(map[string]any)["occurrence"].(string)
	w, c := do(t, h, "GET", "/api/findings/"+occ+"/comparison?baseline=none", nil)
	if w.Code != 200 || c["comparable"] != false || c["reason"] != "no-baseline" {
		t.Fatalf("expected no-baseline comparison: code=%d body=%v", w.Code, c)
	}
}
