package server

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testServer(t *testing.T) (*Server, string) {
	t.Helper()
	base := t.TempDir()
	reports := filepath.Join(base, "reports")
	os.MkdirAll(reports, 0o755)
	t.Setenv("VHLOCAL_LEDGER_DIR", filepath.Join(base, "ledger"))
	s, err := New(Config{
		Host: "127.0.0.1", Port: 8420, ReportsDir: reports,
		AllowRoots: []string{base}, StatePath: filepath.Join(base, "jobs.json"),
		Version: "0.1.0-test",
	})
	if err != nil {
		t.Fatal(err)
	}
	// A submitted job's worker may still be persisting when the test returns; let it
	// go idle before t.TempDir() removes the tree (otherwise the cleanup races the
	// worker under -race: "directory not empty").
	t.Cleanup(func() { waitJobsIdle(t, s.store) })
	return s, base
}

func TestConfigEndpointShape(t *testing.T) {
	s, _ := testServer(t)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/api/config", nil))
	if rec.Code != 200 {
		t.Fatalf("status %d", rec.Code)
	}
	var d map[string]any
	json.Unmarshal(rec.Body.Bytes(), &d)
	for _, k := range []string{"skill_dir", "reports_dir", "allow_roots", "phases", "defaults"} {
		if _, ok := d[k]; !ok {
			t.Errorf("config missing %q", k)
		}
	}
	phases := d["phases"].([]any)
	if len(phases) != 7 { // incl 1t
		t.Errorf("expected 7 phases, got %d", len(phases))
	}
	defs := d["defaults"].(map[string]any)
	if defs["model"] != "gpt-oss:120b" || defs["num_ctx"] != float64(131072) {
		t.Errorf("defaults wrong: %v", defs)
	}
}

func TestScansListAndProfilesAndReports(t *testing.T) {
	s, _ := testServer(t)
	h := s.Handler()
	for _, ep := range []string{"/api/scans", "/api/profiles", "/api/reports", "/api/ledgers", "/api/stats", "/api/applications"} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("GET", ep, nil))
		if rec.Code != 200 {
			t.Errorf("%s status %d", ep, rec.Code)
		}
	}
	// scans shape
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/api/scans", nil))
	var d map[string]any
	json.Unmarshal(rec.Body.Bytes(), &d)
	if _, ok := d["jobs"]; !ok {
		t.Error("scans missing jobs")
	}
	if _, ok := d["busy"]; !ok {
		t.Error("scans missing busy")
	}
	// profiles has the 4 built-ins
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/api/profiles", nil))
	json.Unmarshal(rec.Body.Bytes(), &d)
	if len(d["profiles"].([]any)) < 4 {
		t.Error("expected >=4 profiles")
	}
}

func TestCreateScanValidation(t *testing.T) {
	s, base := testServer(t)
	h := s.Handler()
	post := func(bodyJSON string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("POST", "/api/scans", strings.NewReader(bodyJSON))
		h.ServeHTTP(rec, req)
		return rec
	}
	// missing repo -> 400
	if rec := post(`{}`); rec.Code != 400 {
		t.Errorf("missing repo: status %d", rec.Code)
	}
	// repo outside allow-roots -> 403
	if rec := post(`{"repo":"/"}`); rec.Code != 403 {
		t.Errorf("root repo: status %d body %s", rec.Code, rec.Body.String())
	}
	// bad phases -> 400
	repo := filepath.Join(base, "app")
	os.MkdirAll(repo, 0o755)
	if rec := post(`{"repo":"` + repo + `","phases":"9z"}`); rec.Code != 400 {
		t.Errorf("bad phases: status %d", rec.Code)
	}
	// valid -> 201 with a job id
	rec := post(`{"repo":"` + repo + `","phases":"1"}`)
	if rec.Code != 201 {
		t.Fatalf("valid create: status %d body %s", rec.Code, rec.Body.String())
	}
	var job map[string]any
	json.Unmarshal(rec.Body.Bytes(), &job)
	if job["id"] == nil || job["status"] == nil {
		t.Errorf("job shape: %v", job)
	}
}

func TestSecurityBindGuard(t *testing.T) {
	s := &Server{cfg: Config{Host: "0.0.0.0", Port: 8420}}
	if err := s.Serve(); err == nil {
		t.Fatal("non-loopback bind without --unsafe-bind should be refused")
	} else if !strings.Contains(err.Error(), "unsafe-bind") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestFileTraversalRefused(t *testing.T) {
	s, base := testServer(t)
	// create a fake job with a results dir and a secret sibling
	results := filepath.Join(base, "res")
	os.MkdirAll(results, 0o755)
	os.WriteFile(filepath.Join(base, "secret.txt"), []byte("TOP"), 0o644)
	os.WriteFile(filepath.Join(results, "ok.md"), []byte("fine"), 0o644)
	id := s.store.Submit(map[string]any{"repo": base})
	// force the job's results dir + terminal status via a direct set is not exposed;
	// instead test serveConfined directly (the handler delegates to it).
	rec := httptest.NewRecorder()
	serveConfined(rec, results, "../secret.txt")
	if rec.Code != 403 {
		t.Errorf("traversal should be 403, got %d", rec.Code)
	}
	rec = httptest.NewRecorder()
	serveConfined(rec, results, "ok.md")
	if rec.Code != 200 || rec.Body.String() != "fine" {
		t.Errorf("confined read failed: %d %q", rec.Code, rec.Body.String())
	}
	_ = id
}

func TestSSEReplaysBacklogAndClosesOnJobEnd(t *testing.T) {
	s, base := testServer(t)
	repo := filepath.Join(base, "app")
	os.MkdirAll(repo, 0o755)
	os.WriteFile(filepath.Join(repo, "a.py"), []byte("x=1\n"), 0o644)
	// Submit a scan; the fake ollama host is unreachable so it aborts fast and
	// emits job_end — the SSE stream should replay and close.
	id := s.store.Submit(map[string]any{"repo": repo, "phases": "1", "host": "http://127.0.0.1:1", "num_ctx": 2048})
	// wait for terminal
	waitTerminal(t, s, id)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/scans/"+id+"/events?offset=0", nil)
	ctx, cancel := context.WithCancel(req.Context())
	defer cancel()
	req = req.WithContext(ctx)
	done := make(chan struct{})
	go func() { s.Handler().ServeHTTP(rec, req); close(done) }()
	select {
	case <-done:
	case <-timeoutC(t):
		t.Fatal("SSE did not close on job_end")
	}
	body := rec.Body.String()
	if !strings.Contains(body, "data: ") || !strings.Contains(body, "job_end") {
		t.Errorf("SSE body missing events/job_end: %q", firstN(body, 200))
	}
}

func TestUnknownJobEvents404(t *testing.T) {
	s, _ := testServer(t)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/api/scans/nope/events", nil))
	if rec.Code != 404 {
		t.Errorf("status %d", rec.Code)
	}
}
