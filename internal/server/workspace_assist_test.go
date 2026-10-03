package server

import (
	"testing"

	"vhlocal/internal/client"
	"vhlocal/internal/client/testsupport"
	seed "vhlocal/internal/server/testsupport"
)

// T036 (API-A1/A2/FR-042): the assist endpoints run a bound action via the
// injected provider, persist it, serve it back, and do not resubmit on repeat.
func TestAssistEndpoints(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("VHLOCAL_REVIEWS_DIR", t.TempDir())
	t.Setenv("VHLOCAL_ASSIST_DIR", t.TempDir())
	seed.SeedReport(t, dir, seed.ReportSeed{
		Name: "app", Model: "m1", Stamp: "2026-09-01-000000", Repo: "/r/app",
		Findings: []map[string]any{{"id": "F1", "stable_identity": "s1", "severity": "High", "severity_rank": 2, "location": "a.go:1", "verification_status": "supported"}},
	})
	fp := &testsupport.FakeProvider{Backend_: "fake", Endpoint_: "fake://local",
		Script: []client.ChatResponse{testsupport.AssistantText("explanation")}}
	s := &Server{cfg: Config{ReportsDir: dir}, assistProvider: fp}
	h := s.Handler()

	// occurrence id
	_, m := do(t, h, "GET", "/api/findings", nil)
	occ := m["rows"].([]any)[0].(map[string]any)["occurrence"].(string)

	// Run an action.
	w, res := do(t, h, "POST", "/api/findings/"+occ+"/assist",
		map[string]any{"action": "explain-flow", "request_id": "r1", "model": "m1"})
	if w.Code != 200 || res["status"] != "succeeded" || res["output"] != "explanation" {
		t.Fatalf("assist run: code=%d body=%v", w.Code, res)
	}
	if res["label"] != "generated-analysis" {
		t.Fatalf("missing generated label: %v", res)
	}
	if len(fp.Calls) != 1 {
		t.Fatalf("provider called %d times, want 1", len(fp.Calls))
	}

	// Repeat with the SAME request_id → served from store, provider NOT called again.
	w2, _ := do(t, h, "POST", "/api/findings/"+occ+"/assist",
		map[string]any{"action": "explain-flow", "request_id": "r1", "model": "m1"})
	if w2.Code != 200 || len(fp.Calls) != 1 {
		t.Fatalf("repeat resubmitted: calls=%d", len(fp.Calls))
	}

	// GET retrieves the stored result.
	w3, g := do(t, h, "GET", "/api/findings/"+occ+"/assist?action=explain-flow", nil)
	if w3.Code != 200 || g["output"] != "explanation" {
		t.Fatalf("assist get: code=%d body=%v", w3.Code, g)
	}
}

// FR-041: with no configured provider and none injected, the endpoint fails
// explicitly rather than silently falling back.
func TestAssistNoProviderExplicit(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("VHLOCAL_REVIEWS_DIR", t.TempDir())
	t.Setenv("VHLOCAL_ASSIST_DIR", t.TempDir())
	seed.SeedReport(t, dir, seed.ReportSeed{
		Name: "app", Model: "m1", Stamp: "2026-09-01-000000", Repo: "/r/app",
		Findings: []map[string]any{{"id": "F1", "stable_identity": "s1", "severity": "High", "severity_rank": 2, "location": "a.go:1"}},
	})
	s := &Server{cfg: Config{ReportsDir: dir}} // no injected provider
	h := s.Handler()
	_, m := do(t, h, "GET", "/api/findings", nil)
	occ := m["rows"].([]any)[0].(map[string]any)["occurrence"].(string)

	// An unknown backend must be an explicit 400, not a silent substitution.
	w, _ := do(t, h, "POST", "/api/findings/"+occ+"/assist",
		map[string]any{"action": "challenge", "request_id": "r1", "provider": "definitely-not-a-backend"})
	if w.Code != 400 {
		t.Fatalf("unknown provider code=%d want 400 (explicit, no fallback)", w.Code)
	}
}
