package server

import (
	"encoding/json"
	"os"
	"testing"
	"time"

	"vhlocal/internal/server/testsupport"
)

// CB-1 / CB-3 (US3, SC-003): a partial run yields distinct engine axes and
// phase_outcomes marking the unfinished phases incomplete with reasons — the queue
// status is never conflated with execution completion.
func TestScanStatusPartialRun(t *testing.T) {
	reportsDir := t.TempDir()
	dir := testsupport.SeedReport(t, reportsDir, testsupport.ReportSeed{
		Name: "logistics", Repo: "/repos/logistics", Created: time.Unix(1000, 0),
		PhasesRequested: []string{"1", "1t", "2", "2b", "3", "3d", "4"},
		PhasesCompleted: []string{"1", "1t", "2", "3d", "4"},
		ExecutionStatus: "partial", CoverageStatus: "degraded",
		Findings: []map[string]any{{"severity": "High", "classification": "statically_supported"}},
	})
	// Inject a phase-tagged degraded reason (as the engine records it).
	injectReason(t, dir, "phase 3: artifact lacks canonical candidate ID or source location")

	st := scanStatus(dir)
	if st == nil {
		t.Fatal("expected status")
	}
	if st["execution_status"] != "partial" {
		t.Errorf("execution_status = %v want partial", st["execution_status"])
	}
	if st["coverage_status"] != "degraded" {
		t.Errorf("coverage_status = %v want degraded", st["coverage_status"])
	}
	if st["validation_mode"] != "static_reasoning" {
		t.Errorf("validation_mode = %v want static_reasoning", st["validation_mode"])
	}
	outcomes, _ := st["phase_outcomes"].([]map[string]any)
	if len(outcomes) != 7 {
		t.Fatalf("expected 7 phase outcomes, got %d", len(outcomes))
	}
	byPhase := map[string]map[string]any{}
	for _, o := range outcomes {
		byPhase[o["phase"].(string)] = o
	}
	// 2b and 3 requested-but-not-completed → incomplete with a reason; never "produced".
	for _, p := range []string{"2b", "3"} {
		o := byPhase[p]
		if o["completed"] != false || o["produced"] != false {
			t.Errorf("phase %s must be incomplete/not-produced, got %+v", p, o)
		}
		if r, _ := o["reason"].(string); r == "" {
			t.Errorf("phase %s must carry an incompletion reason", p)
		}
	}
	if byPhase["3"]["reason"] != "artifact lacks canonical candidate ID or source location" {
		t.Errorf("phase 3 reason not surfaced from degraded reasons: %v", byPhase["3"]["reason"])
	}
	// Completed phases show completed=true.
	if byPhase["1"]["completed"] != true || byPhase["4"]["completed"] != true {
		t.Errorf("completed phases must read completed=true")
	}
}

// injectReason appends a phase-tagged degraded reason to a seeded findings.json.
func injectReason(t *testing.T, dir, reason string) {
	t.Helper()
	m := readJSONMap(dir + "/findings.json")
	rs, _ := m["run_status"].(map[string]any)
	rs["coverage_degraded_reasons"] = []any{reason}
	m["run_status"] = rs
	b, _ := json.MarshalIndent(m, "", "  ")
	if err := os.WriteFile(dir+"/findings.json", b, 0o644); err != nil {
		t.Fatal(err)
	}
}

// Feature 014 (FR-016/FR-021, T038/T051): the scan view carries the completion block
// and the review-unit gaps read from the records, next to — never inside — the
// queue job status; a pre-014 run without those records exposes neither key.
func TestScanStatusExposesOutcomeAndReviewGapsSeparately(t *testing.T) {
	reportsDir := t.TempDir()
	dir := testsupport.SeedReport(t, reportsDir, testsupport.ReportSeed{
		Name: "shop", Repo: "/repos/shop", Created: time.Unix(1000, 0),
		PhasesRequested: []string{"1", "2", "2b"}, PhasesCompleted: []string{"1", "2b"},
		ExecutionStatus: "partial", CoverageStatus: "degraded",
	})
	if st := scanStatus(dir); st["outcome"] != nil || st["review_units"] != nil {
		t.Fatalf("pre-014 records must not invent outcome/review_units: %v", st)
	}
	// Inject the engine-shaped block + record.
	m := readJSONMap(dir + "/findings.json")
	rs := m["run_status"].(map[string]any)
	rs["outcome"] = map[string]any{
		"units": map[string]any{"total": 10, "not_reviewed": 2}, "candidates": map[string]any{"supported": 1, "unresolved": 1},
		"failed_assignments": []any{map[string]any{"unit_id": "hunt:sg-2:inj", "path": "results/sg-2_inj.md", "reason": "deliverable never written after 2 attempt(s)"}},
		"failed_candidates":  []any{map[string]any{"candidate_id": "CAND-1", "class": "turn_exhaustion", "reason": "no decision"}},
		"missing_artifacts":  []any{}, "disabled_optional_phases": []any{"1t (threat_model=false)"}, "recovery_steps": []any{"re-run"},
	}
	m["run_status"] = rs
	b, _ := json.MarshalIndent(m, "", "  ")
	if err := os.WriteFile(dir+"/findings.json", b, 0o644); err != nil {
		t.Fatal(err)
	}
	ru := map[string]any{"revision": "abc", "counts": map[string]any{"total": 10, "not_reviewed": 2}, "follow_up_ran": false,
		"gaps": []any{map[string]any{"route_id": "a.py:1 GET /a", "reason": "assignment_failure"}, map[string]any{"route_id": "a.py:9 GET /b", "reason": "not_attempted"}}}
	b, _ = json.Marshal(ru)
	if err := os.WriteFile(dir+"/review_units.json", b, 0o644); err != nil {
		t.Fatal(err)
	}

	job := map[string]any{"id": "j1", "status": "terminated", "results_dir": dir}
	out := enrichScan(job)
	if out["status"] != "terminated" {
		t.Errorf("queue status must stay the job's own field, got %v", out["status"])
	}
	oc, _ := out["outcome"].(map[string]any)
	if oc == nil {
		t.Fatal("outcome block missing on scan detail")
	}
	if fa, _ := oc["failed_assignments"].([]any); len(fa) != 1 {
		t.Errorf("failed_assignments not passed through verbatim: %v", oc["failed_assignments"])
	}
	if _, has := oc["status"]; has {
		t.Error("outcome must not carry a job status")
	}
	rv, _ := out["review_units"].(map[string]any)
	if rv == nil {
		t.Fatal("review_units missing on scan detail")
	}
	gaps, _ := rv["unreviewed"].([]any)
	if len(gaps) != 2 {
		t.Errorf("unreviewed gaps = %d, want 2", len(gaps))
	}
	if g0, _ := gaps[0].(map[string]any); g0["reason"] != "assignment_failure" {
		t.Errorf("gap reason not surfaced: %v", gaps[0])
	}
	if out["execution_status"] != "partial" || out["coverage_status"] != "degraded" {
		t.Errorf("engine axes changed: %v / %v", out["execution_status"], out["coverage_status"])
	}
}

// Feature 015 (T011): the scan view passes new record presence/state through
// additively — report model presence, diagram states, coverage semantics — and
// never invents them for older runs.
func TestScanStatusPassesFeature015RecordsThrough(t *testing.T) {
	reportsDir := t.TempDir()
	dir := testsupport.SeedReport(t, reportsDir, testsupport.ReportSeed{
		Name: "shop", Repo: "/repos/shop", Created: time.Unix(1000, 0),
		PhasesRequested: []string{"1", "2"}, PhasesCompleted: []string{"1", "2"},
	})
	st := scanStatus(dir)
	if st["report_model_present"] != false || st["diagram"] != nil || st["coverage_semantics"] != nil {
		t.Fatalf("pre-015 records must not invent fields: %v", st)
	}
	os.WriteFile(dir+"/report_model.json", []byte(`{"version":1}`), 0o644)
	os.WriteFile(dir+"/threat_model_diagram.json", []byte(`{"version":1,"renderer_version":"11.17.2","diagrams":[{"index":0,"state":"invalid","errors":[{"line":48,"code":"E_EDGE_LABEL_UNTERMINATED","message":"x"}]}]}`), 0o644)
	os.WriteFile(dir+"/review_units.json", []byte(`{"revision":"r","counts":{}}`), 0o644)
	st = scanStatus(dir)
	if st["report_model_present"] != true {
		t.Error("report_model_present should be true")
	}
	dg, _ := st["diagram"].(map[string]any)
	ds, _ := dg["diagrams"].([]any)
	if len(ds) != 1 || ds[0].(map[string]any)["state"] != "invalid" || ds[0].(map[string]any)["error"] == nil {
		t.Errorf("diagram summary = %v", dg)
	}
	if st["coverage_semantics"] != 1 {
		t.Errorf("coverage_semantics = %v, want 1 for a record without the field", st["coverage_semantics"])
	}
}

// T076 (FR-021, C-C16): the scan view distinguishes issues to fix, items that need review
// and scanner diagnostics by passing the persisted projection through verbatim. A report
// saved before feature 016 carries no projection, and nothing is invented for it.
func TestScanStatusPassesPresentationSeparationThrough(t *testing.T) {
	reportsDir := t.TempDir()
	dir := testsupport.SeedReport(t, reportsDir, testsupport.ReportSeed{
		Name: "shop", Repo: "/repos/shop", Created: time.Unix(1000, 0),
		PhasesRequested: []string{"1", "2"}, PhasesCompleted: []string{"1", "2"},
	})
	// Pre-016: a model with no projection yields no presentation block.
	os.WriteFile(dir+"/report_model.json", []byte(`{"version":1}`), 0o644)
	if st := scanStatus(dir); st["presentation"] != nil {
		t.Fatalf("a pre-016 model must not produce a presentation block: %v", st["presentation"])
	}

	os.WriteFile(dir+"/report_model.json", []byte(`{"version":1,"presentation":{"version":1,
		"counts":{"issues_to_fix":34,"needs_review":7,"needs_review_inconclusive":1,"needs_review_incomplete":6,
		"dismissed":8,"detections":49,"candidates_examined":64,"severity":{"High":13,"Medium":19,"Low":2}},
		"issues":[{"ref":"ISSUE-001"},{"ref":"ISSUE-002"}],
		"review_items":[{"ref":"REVIEW-001"}],
		"dismissed":[{"ref":"DISMISSED-001"},{"ref":"DISMISSED-002"}],
		"grouping_notes":["recorded group RG-x was not used"]}}`), 0o644)
	st := scanStatus(dir)
	ps, ok := st["presentation"].(map[string]any)
	if !ok {
		t.Fatalf("no presentation block: %v", st["presentation"])
	}
	if ps["version"] != float64(1) {
		t.Errorf("version = %v", ps["version"])
	}
	if ps["review_items"] != 1 || ps["dismissed"] != 2 || ps["issues"] != 2 || ps["grouping_notes"] != 1 {
		t.Errorf("separation lengths = %v", ps)
	}
	c, _ := ps["counts"].(map[string]any)
	// Verbatim pass-through: the server performs no arithmetic on these.
	if c["issues_to_fix"] != float64(34) || c["needs_review"] != float64(7) ||
		c["dismissed"] != float64(8) || c["detections"] != float64(49) || c["candidates_examined"] != float64(64) {
		t.Errorf("counts were not passed through verbatim: %v", c)
	}
	if c["needs_review_inconclusive"] != float64(1) || c["needs_review_incomplete"] != float64(6) {
		t.Errorf("the needs-review split was not passed through: %v", c)
	}
}
