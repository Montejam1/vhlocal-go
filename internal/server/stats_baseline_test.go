package server

import (
	"math"
	"testing"

	"vhlocal/internal/server/testsupport"
)

// requiredStatsKeys is the feature-008 dashboard metric set that feature 010 MUST
// preserve unchanged (FR-033/034, SC-001). This test is the preservation baseline:
// it fails if any metric is dropped or renamed.
var requiredStatsKeys = []string{
	"scans", "findings", "avg_findings_per_scan",
	"prompt_tokens", "completion_tokens", "total_tokens", "with_usage",
	"avg_tokens_per_scan", "total_seconds", "avg_seconds_per_scan", "by_model",
}

// T003 (SC-001): every preserved metric is present, the headline average findings
// is a whole number, and populated history reports sane values.
func TestDashboardPreservationBaseline(t *testing.T) {
	dir := t.TempDir()
	testsupport.SeedReport(t, dir, testsupport.ReportSeed{
		Name: "a", Model: "m1", Stamp: "2026-09-01-000000", Repo: "/r/a",
		Findings:     []map[string]any{{"severity": "High"}, {"severity": "Low"}, {"severity": "Low"}},
		PromptTokens: 1000, CompletionTokens: 200, StartedAt: 100, FinishedAt: 130,
	})
	// A run with no usage/timing (older shape): must not break aggregation (008).
	testsupport.SeedReport(t, dir, testsupport.ReportSeed{
		Name: "b", Model: "m2", Stamp: "2026-09-02-000000", Repo: "/r/b",
		Findings: []map[string]any{{"severity": "High"}},
	})

	m := statsOf(t, dir)
	for _, k := range requiredStatsKeys {
		if _, ok := m[k]; !ok {
			t.Errorf("preserved metric %q is missing from /api/stats", k)
		}
	}
	// Headline average findings must be a whole number (4 findings / 2 scans = 2).
	avg := numf(t, m, "avg_findings_per_scan")
	if avg != math.Trunc(avg) || avg != 2 {
		t.Errorf("avg_findings_per_scan=%v, want whole-number 2", avg)
	}
}

// T003 (SC-001): zero scans render a clean zero state (no NaN / divide-by-zero).
func TestDashboardPreservationZeroScans(t *testing.T) {
	m := statsOf(t, t.TempDir())
	for _, k := range requiredStatsKeys {
		if _, ok := m[k]; !ok {
			t.Errorf("zero-scan stats missing %q", k)
		}
	}
	for _, k := range []string{"scans", "findings", "avg_findings_per_scan", "avg_tokens_per_scan", "avg_seconds_per_scan"} {
		if v := numf(t, m, k); v != 0 || math.IsNaN(v) {
			t.Errorf("zero-scan %q=%v, want clean 0", k, v)
		}
	}
}
