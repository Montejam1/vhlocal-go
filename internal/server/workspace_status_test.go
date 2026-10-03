package server

import (
	"testing"

	"vhlocal/internal/server/testsupport"
)

// T025 (API-S1/FR-025/026): the status endpoint carries the three independent
// axes and per-phase outcomes.
func TestScanStatusEndpoint(t *testing.T) {
	dir := t.TempDir()
	scan := testsupport.SeedReport(t, dir, testsupport.ReportSeed{
		Name: "app", Model: "m1", Stamp: "2026-09-01-000000", Repo: "/r/app",
		ExecutionStatus: "partial", CoverageStatus: "degraded", ValidationMode: "static_reasoning",
		PhasesRequested: []string{"1", "2", "2b", "4"}, PhasesCompleted: []string{"1", "2"},
		Findings: []map[string]any{{"id": "F1", "stable_identity": "s1", "severity": "High", "severity_rank": 1}},
	})
	id := lastSeg(scan)
	h := (&Server{cfg: Config{ReportsDir: dir}}).Handler()

	w, m := do(t, h, "GET", "/api/scans/"+id+"/status", nil)
	if w.Code != 200 {
		t.Fatalf("status code=%d", w.Code)
	}
	if m["execution_status"] != "partial" || m["coverage_status"] != "degraded" || m["validation_mode"] != "static_reasoning" {
		t.Fatalf("axes not surfaced: %v", m)
	}
	po, _ := m["phase_outcomes"].([]any)
	if len(po) != 4 {
		t.Fatalf("phase_outcomes len=%d want 4 (one per requested phase)", len(po))
	}
	// A completed job status must never be inferred here — 2b was requested but not completed.
	var found bool
	for _, row := range po {
		r := row.(map[string]any)
		if r["phase"] == "2b" {
			found = true
			if r["completed"] != false {
				t.Fatalf("phase 2b should be incomplete: %v", r)
			}
		}
	}
	if !found {
		t.Fatal("phase 2b outcome missing")
	}
}

// T025 (API-S2): the manifest endpoint returns validated artifact states.
func TestScanManifestEndpoint(t *testing.T) {
	dir := t.TempDir()
	scan := testsupport.SeedReport(t, dir, testsupport.ReportSeed{
		Name: "app", Model: "m1", Stamp: "2026-09-01-000000", Repo: "/r/app",
		PhasesRequested: []string{"1", "1t", "4"}, PhasesCompleted: []string{"1", "1t", "4"},
		ThreatModel: "ok", Sbom: "ok", Readme: true,
		Findings: []map[string]any{{"id": "F1", "stable_identity": "s1", "severity": "High", "severity_rank": 1}},
	})
	id := lastSeg(scan)
	h := (&Server{cfg: Config{ReportsDir: dir}}).Handler()

	w, m := do(t, h, "GET", "/api/scans/"+id+"/manifest", nil)
	if w.Code != 200 {
		t.Fatalf("manifest code=%d", w.Code)
	}
	arts, _ := m["artifacts"].([]any)
	if len(arts) == 0 {
		t.Fatalf("no artifacts: %v", m)
	}
	states := map[string]string{}
	for _, a := range arts {
		e := a.(map[string]any)
		states[e["key"].(string)] = e["state"].(string)
	}
	if states["threat_model"] != "available" || states["sbom"] != "available" || states["readme"] != "available" {
		t.Fatalf("expected available artifacts: %v", states)
	}
	// 404 for an unknown scan.
	w2, _ := do(t, h, "GET", "/api/scans/nope/manifest", nil)
	if w2.Code != 404 {
		t.Fatalf("unknown scan manifest code=%d want 404", w2.Code)
	}
}

func lastSeg(p string) string {
	for i := len(p) - 1; i >= 0; i-- {
		if p[i] == '/' {
			return p[i+1:]
		}
	}
	return p
}
