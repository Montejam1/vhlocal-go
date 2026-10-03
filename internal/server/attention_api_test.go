package server

import (
	"testing"

	"vhlocal/internal/server/testsupport"
)

// T031 (API-Q1/FR-037): the attention endpoint is served independently of
// /api/stats — an empty/degraded reports dir still yields a 200 attention section
// AND a usable /api/stats. Queue filters never touch the stats population.
func TestAttentionEndpointIndependentOfStats(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("VHLOCAL_REVIEWS_DIR", t.TempDir())
	testsupport.SeedReport(t, dir, testsupport.ReportSeed{
		Name: "app", Model: "m1", Stamp: "2026-09-01-000000", Repo: "/r/app",
		ExecutionStatus: "partial",
		Findings: []map[string]any{
			{"id": "F1", "stable_identity": "s1", "severity": "High", "severity_rank": 2, "verification_status": "supported"},
		},
	})
	h := (&Server{cfg: Config{ReportsDir: dir}}).Handler()

	// Attention section renders with all six queues.
	w, m := do(t, h, "GET", "/api/attention", nil)
	if w.Code != 200 {
		t.Fatalf("attention code=%d", w.Code)
	}
	qs, _ := m["queues"].([]any)
	if len(qs) != 6 {
		t.Fatalf("want 6 queues, got %d", len(qs))
	}
	if sd, _ := m["stale_days"].(float64); sd != 7 {
		t.Fatalf("default stale_days=%v want 7", sd)
	}

	// /api/stats is unaffected and still reports the preserved metrics.
	sm := statsOf(t, dir)
	if numf(t, sm, "scans") != 1 {
		t.Fatalf("stats.scans=%v want 1 (attention must not alter stats population)", sm["scans"])
	}
	for _, k := range requiredStatsKeys {
		if _, ok := sm[k]; !ok {
			t.Fatalf("stats missing preserved metric %q after attention call", k)
		}
	}
}

// FR-035: stale_days is operator-editable via the query.
func TestAttentionStaleDaysOverride(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("VHLOCAL_REVIEWS_DIR", t.TempDir())
	h := (&Server{cfg: Config{ReportsDir: dir}}).Handler()
	_, m := do(t, h, "GET", "/api/attention?stale_days=30", nil)
	if sd, _ := m["stale_days"].(float64); sd != 30 {
		t.Fatalf("stale_days override = %v, want 30", sd)
	}
}
