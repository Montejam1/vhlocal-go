package reports

import (
	"os"
	"path/filepath"
	"testing"
)

// Feature 015 (FR-002/FR-032, T012): Supported/Rejected/Unresolved come from the
// single Classify rule while the legacy Findings/Hypotheses counts stay unchanged.
func TestLoadClassifiedCountsKeepLegacyCounts(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "app_VULNHUNT_RESULTS_m_2026-09-29-000000")
	os.MkdirAll(dir, 0o755)
	doc := `{"findings":[
	  {"id":"A","severity":"High","verification_status":"supported"},
	  {"id":"B","severity":"Low","classification":"hypothesis"},
	  {"id":"C","severity":"Low","verification_status":"rejected"},
	  {"id":"D","severity":"Medium","verification_status":"unresolved","verification_record":{"verdict":"unresolved"}},
	  {"id":"E","severity":"High","verification_status":"supported","duplicate_of":"A"}
	],"run_status":{"execution_status":"complete","coverage_status":"complete","validation_mode":"static_reasoning","coverage_degraded_reasons":[]}}`
	os.WriteFile(filepath.Join(dir, "findings.json"), []byte(doc), 0o644)
	r, ok := Load(dir)
	if !ok {
		t.Fatal("not loaded")
	}
	if r.Findings != 4 || r.Hypotheses != 1 || r.Severities["High"] != 1 || r.Severities["Low"] != 2 {
		t.Errorf("legacy counts changed: findings=%d hypotheses=%d severities=%v", r.Findings, r.Hypotheses, r.Severities)
	}
	if r.Supported != 1 || r.Rejected != 1 || r.Unresolved != 2 {
		t.Errorf("classified counts = %d/%d/%d, want 1/1/2", r.Supported, r.Rejected, r.Unresolved)
	}
	if r.CoverageSemantics != 0 {
		t.Errorf("no review_units.json ⇒ coverage_semantics 0, got %d", r.CoverageSemantics)
	}
}
