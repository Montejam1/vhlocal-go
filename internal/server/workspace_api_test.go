package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"vhlocal/internal/server/testsupport"
)

// wsServer builds a server over a seeded reports dir with per-test review/view
// stores (env-redirected), and returns its handler.
func wsServer(t *testing.T) (http.Handler, string) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("VHLOCAL_REVIEWS_DIR", t.TempDir())
	t.Setenv("VHLOCAL_VIEWS_DIR", t.TempDir())
	testsupport.SeedReport(t, dir, testsupport.ReportSeed{
		Name: "app", Model: "m1", Stamp: "2026-09-01-000000", Repo: "/r/app",
		Findings: []map[string]any{
			{"id": "F1", "stable_identity": "s1", "severity": "High", "severity_rank": 1,
				"location": "a.go:10", "verification_status": "supported"},
		},
	})
	s := &Server{cfg: Config{ReportsDir: dir}}
	return s.Handler(), dir
}

func do(t *testing.T, h http.Handler, method, url string, body any) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	var r *http.Request
	if body != nil {
		b, _ := json.Marshal(body)
		r = httptest.NewRequest(method, url, bytes.NewReader(b))
	} else {
		r = httptest.NewRequest(method, url, nil)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	var m map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &m)
	return w, m
}

// T008 (API-F1/F2): the queue lists occurrences and detail round-trips.
func TestFindingsQueueAndDetailAPI(t *testing.T) {
	h, _ := wsServer(t)
	w, m := do(t, h, "GET", "/api/findings", nil)
	if w.Code != 200 {
		t.Fatalf("GET /api/findings code=%d", w.Code)
	}
	rows, _ := m["rows"].([]any)
	if len(rows) != 1 {
		t.Fatalf("want 1 row, got %d (%v)", len(rows), m)
	}
	occ, _ := rows[0].(map[string]any)["occurrence"].(string)
	if occ == "" {
		t.Fatal("row missing occurrence id")
	}
	// Detail
	w2, m2 := do(t, h, "GET", "/api/findings/"+occ, nil)
	if w2.Code != 200 || m2["finding"] == nil || m2["raw"] == nil {
		t.Fatalf("detail code=%d body=%v", w2.Code, m2)
	}
	// Missing occurrence → 404.
	w3, _ := do(t, h, "GET", "/api/findings/nope~x", nil)
	if w3.Code != 404 {
		t.Fatalf("missing occurrence code=%d want 404", w3.Code)
	}
}

// T017 (API-R2 / FR-018/FR-021): submit enforces rationale and version conflict.
func TestReviewSubmitRationaleAndConflictAPI(t *testing.T) {
	h, _ := wsServer(t)

	// Dismiss without rationale → 400.
	w, _ := do(t, h, "POST", "/api/findings/source-v1:s1/review",
		map[string]any{"disposition": "dismissed", "base_version": 0})
	if w.Code != 400 {
		t.Fatalf("dismiss w/o rationale code=%d want 400", w.Code)
	}

	// Dismiss with rationale → 200, head version 1.
	w2, m2 := do(t, h, "POST", "/api/findings/source-v1:s1/review",
		map[string]any{"disposition": "dismissed", "rationale": "constant input", "base_version": 0})
	if w2.Code != 200 {
		t.Fatalf("dismiss w/ rationale code=%d", w2.Code)
	}
	hist, _ := m2["history"].([]any)
	if len(hist) != 1 {
		t.Fatalf("history len=%d want 1", len(hist))
	}

	// Stale write (base_version still 0) → 409 with current record.
	w3, m3 := do(t, h, "POST", "/api/findings/source-v1:s1/review",
		map[string]any{"disposition": "resolved", "rationale": "y", "base_version": 0})
	if w3.Code != 409 || m3["current"] == nil {
		t.Fatalf("stale write code=%d body=%v want 409+current", w3.Code, m3)
	}

	// GET review reflects the head.
	w4, m4 := do(t, h, "GET", "/api/findings/source-v1:s1/review", nil)
	if w4.Code != 200 {
		t.Fatalf("get review code=%d", w4.Code)
	}
	if m4["stable_id"] != "source-v1:s1" {
		t.Fatalf("review record stable_id=%v", m4["stable_id"])
	}
}

// API-V1 (FR-006): saved views round-trip through the API.
func TestSavedViewsAPI(t *testing.T) {
	h, _ := wsServer(t)
	w, m := do(t, h, "POST", "/api/views",
		map[string]any{"name": "Open Criticals", "filters": map[string]any{"severity": "Critical"}})
	if w.Code != 200 || m["id"] != "open-criticals" {
		t.Fatalf("save view code=%d body=%v", w.Code, m)
	}
	w2, m2 := do(t, h, "GET", "/api/views", nil)
	if w2.Code != 200 {
		t.Fatalf("list views code=%d", w2.Code)
	}
	if vs, _ := m2["views"].([]any); len(vs) != 1 {
		t.Fatalf("want 1 view, got %v", m2["views"])
	}
	w3, _ := do(t, h, "DELETE", "/api/views/open-criticals", nil)
	if w3.Code != 200 {
		t.Fatalf("delete view code=%d", w3.Code)
	}
	w4, m4 := do(t, h, "GET", "/api/views", nil)
	if vs, _ := m4["views"].([]any); w4.Code != 200 || len(vs) != 0 {
		t.Fatalf("views not empty after delete: %v", m4["views"])
	}
}

// sanity: occurrence ids carry no '#'/'/' that would break path routing.
func TestOccurrenceIDPathSafe(t *testing.T) {
	h, _ := wsServer(t)
	_, m := do(t, h, "GET", "/api/findings", nil)
	rows, _ := m["rows"].([]any)
	occ, _ := rows[0].(map[string]any)["occurrence"].(string)
	if strings.ContainsAny(occ, "#/\\") {
		t.Fatalf("occurrence id not path-safe: %q", occ)
	}
}
