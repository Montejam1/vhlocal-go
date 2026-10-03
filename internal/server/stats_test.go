package server

import (
	"encoding/json"
	"net/http/httptest"
	"testing"

	"vhlocal/internal/server/testsupport"
)

func statsOf(t *testing.T, reportsDir string) map[string]any {
	t.Helper()
	s := &Server{cfg: Config{ReportsDir: reportsDir}}
	w := httptest.NewRecorder()
	s.handleStats(w, httptest.NewRequest("GET", "/api/stats", nil))
	var m map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &m); err != nil {
		t.Fatalf("stats not JSON: %v", err)
	}
	return m
}

func numf(t *testing.T, m map[string]any, key string) float64 {
	t.Helper()
	f, ok := m[key].(float64)
	if !ok {
		t.Fatalf("stats[%q] is not a number: %v", key, m[key])
	}
	return f
}

// C-M1/C-M2/C-M3/C-M5 (US1): the aggregate returns real token/time metrics, an
// integer findings average over all scans, token averages over runs WITH usage, and
// real per-model tokens.
func TestStatsFullMetricSet(t *testing.T) {
	dir := t.TempDir()
	testsupport.SeedReport(t, dir, testsupport.ReportSeed{
		Name: "a", Model: "m1", Stamp: "2026-09-01-000000", Repo: "/r/a",
		Findings:     []map[string]any{{"severity": "High", "classification": "statically_supported"}, {"severity": "Low", "classification": "statically_supported"}, {"severity": "Low", "classification": "statically_supported"}},
		PromptTokens: 1000, CompletionTokens: 200, StartedAt: 100, FinishedAt: 130, // 30s, 3 findings
	})
	testsupport.SeedReport(t, dir, testsupport.ReportSeed{
		Name: "b", Model: "m2", Stamp: "2026-09-02-000000", Repo: "/r/b",
		Findings:     []map[string]any{{"severity": "High", "classification": "reviewed"}, {"severity": "High", "classification": "reviewed"}, {"severity": "Medium", "classification": "reviewed"}, {"severity": "Low", "classification": "reviewed"}},
		PromptTokens: 3000, CompletionTokens: 400, StartedAt: 200, FinishedAt: 260, // 60s, 4 findings
	})
	// A run with no usage/timing (older shape): counts toward scans/findings only.
	testsupport.SeedReport(t, dir, testsupport.ReportSeed{
		Name: "c", Model: "m1", Stamp: "2026-09-03-000000", Repo: "/r/c",
		Findings: []map[string]any{},
	})

	m := statsOf(t, dir)
	if numf(t, m, "scans") != 3 {
		t.Errorf("scans=%v want 3", m["scans"])
	}
	if numf(t, m, "findings") != 7 {
		t.Errorf("findings=%v want 7", m["findings"])
	}
	if numf(t, m, "total_tokens") != 4600 || numf(t, m, "prompt_tokens") != 4000 || numf(t, m, "completion_tokens") != 600 {
		t.Errorf("token totals wrong: %v/%v/%v", m["total_tokens"], m["prompt_tokens"], m["completion_tokens"])
	}
	if numf(t, m, "with_usage") != 2 {
		t.Errorf("with_usage=%v want 2", m["with_usage"])
	}
	if numf(t, m, "avg_tokens_per_scan") != 2300 { // 4600 / 2 runs with usage
		t.Errorf("avg_tokens_per_scan=%v want 2300", m["avg_tokens_per_scan"])
	}
	if numf(t, m, "total_seconds") != 90 || numf(t, m, "avg_seconds_per_scan") != 45 { // over 2 with duration
		t.Errorf("time metrics wrong: total=%v avg=%v", m["total_seconds"], m["avg_seconds_per_scan"])
	}
	// C-M2: integer average (7/3 = 2.33 → 2), not a decimal.
	avg := m["avg_findings_per_scan"].(float64)
	if avg != 2 || avg != float64(int(avg)) {
		t.Errorf("avg_findings_per_scan=%v want integer 2", m["avg_findings_per_scan"])
	}
	// C-M5: per-model tokens are real (m2 = 3000+400 = 3400), not hardcoded 0.
	bm := m["by_model"].(map[string]any)
	m2 := bm["m2"].(map[string]any)
	if m2["tokens"].(float64) != 3400 {
		t.Errorf("by_model[m2].tokens=%v want 3400", m2["tokens"])
	}
}

// C-M4 (US1): zero scans → all-zero, no NaN/divide-by-zero.
func TestStatsZeroScans(t *testing.T) {
	m := statsOf(t, t.TempDir())
	for _, k := range []string{"scans", "findings", "total_tokens", "with_usage", "avg_tokens_per_scan", "avg_findings_per_scan", "total_seconds", "avg_seconds_per_scan"} {
		if numf(t, m, k) != 0 {
			t.Errorf("zero-scan stats[%q]=%v want 0", k, m[k])
		}
	}
}
