package consolidate

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestApplyKnowledgeNormalizesSeverityAndCWE(t *testing.T) {
	f := NewFinding("VULN-001")
	f.CWE = "CWE-639" // sibling of Broken Access Control
	f.Severity = "Critical"
	ApplyKnowledge(&f)
	if f.NormalizedCWE != "CWE-284" || f.CanonicalName != "Broken Access Control" {
		t.Fatalf("normalized cwe/name: %q / %q", f.NormalizedCWE, f.CanonicalName)
	}
	// access-control baseline is High -> severity replaced, raw preserved.
	if f.Severity != "High" || f.ReportedSeverity != "Critical" {
		t.Fatalf("severity=%q reported=%q", f.Severity, f.ReportedSeverity)
	}
	if f.CVE != CVENotApplicable {
		t.Errorf("cve = %q", f.CVE)
	}
}

func TestRootCauseKeyAndDedup(t *testing.T) {
	// Two SQLi at the same sink but different input params must NOT dedup
	// (distinct flow signatures) — the "q and status reach one execute()" case.
	a := NewFinding("VULN-001")
	a.CWE, a.Location, a.EntryPoint, a.DataFlow = "CWE-89", "app/db.py:42", "GET /api/search?q=", "q -> build_search_query -> execute()"
	b := NewFinding("VULN-002")
	b.CWE, b.Location, b.EntryPoint, b.DataFlow = "CWE-89", "app/db.py:42", "GET /api/search?status=", "status -> build_search_query -> execute()"
	// A true duplicate of a (same params/flow).
	c := NewFinding("VULN-003")
	c.CWE, c.Location, c.EntryPoint, c.DataFlow = "CWE-89", "app/db.py:42", "GET /api/search?q=", "q -> build_search_query -> execute()"

	findings := []Finding{a, b, c}
	Prepare(findings)

	if findings[0].DuplicateOf != nil {
		t.Error("first finding should be canonical")
	}
	if findings[1].DuplicateOf != nil {
		t.Errorf("VULN-002 (different param) must not be a duplicate; key=%q vs %q",
			findings[1].RootCauseKey, findings[0].RootCauseKey)
	}
	if findings[2].DuplicateOf == nil || *findings[2].DuplicateOf != "VULN-001" {
		t.Errorf("VULN-003 should duplicate VULN-001, got %v", findings[2].DuplicateOf)
	}
}

func TestComputeRunStatusThreeAxes(t *testing.T) {
	// A full-execution run that reviewed nothing must report execution=complete
	// but coverage=degraded — the axes are independent (Principle II).
	rs := ComputeRunStatus(StatusInput{
		PhasesRequested: []string{"1", "2"}, PhasesCompleted: []string{"1", "2"},
		CoverageKnown: true, CoverageComplete: false, NotReviewed: 5,
	})
	if rs.ExecutionStatus != ExecComplete {
		t.Errorf("execution = %q want complete", rs.ExecutionStatus)
	}
	if rs.CoverageStatus != CovDegraded || len(rs.CoverageDegradedReasons) == 0 {
		t.Errorf("coverage = %q reasons=%v want degraded+reasons", rs.CoverageStatus, rs.CoverageDegradedReasons)
	}
	if rs.ValidationMode != ValidationStatic {
		t.Errorf("validation = %q want static (no bash)", rs.ValidationMode)
	}
}

func TestBuildAndWriteFindingsJSON(t *testing.T) {
	f := NewFinding("VULN-001")
	f.CWE, f.Severity, f.Title, f.Location = "CWE-89", "High", "SQLi in search", "app/db.py:42"
	f.Classification = ClassStaticallySupported
	f.Assessment = AssessSupported
	findings := Prepare([]Finding{f})

	doc := Build(findings, Options{
		Meta: map[string]any{"model": "gpt-oss:120b"}, EngineVersion: "0.1.0",
		HuntModel: "gpt-oss:120b",
		Status:    ComputeRunStatus(StatusInput{PhasesRequested: []string{"1"}, PhasesCompleted: []string{"1"}}),
		Coverage:  &CoverageInfo{TotalEntryPoints: 5, Reviewed: 5, Complete: true},
	})
	if doc.Attribution.Orchestrator != "vhlocal 0.1.0" {
		t.Errorf("orchestrator = %q", doc.Attribution.Orchestrator)
	}
	if doc.Counts["High"] != 1 || doc.VulnerabilityCounts["High"] != 1 {
		t.Errorf("counts=%v vuln=%v", doc.Counts, doc.VulnerabilityCounts)
	}
	if doc.Assessment.Candidates != 1 || doc.Assessment.StaticallySupported != 1 {
		t.Errorf("assessment=%+v", doc.Assessment)
	}

	dir := t.TempDir()
	path, err := doc.Write(dir)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(path)
	var back map[string]any
	if json.Unmarshal(b, &back) != nil {
		t.Fatal("findings.json not valid JSON")
	}
	for _, key := range []string{"meta", "attribution", "run_status", "coverage", "counts",
		"assessment", "lifecycle", "application_intelligence", "findings"} {
		if _, ok := back[key]; !ok {
			t.Errorf("findings.json missing top-level block %q", key)
		}
	}
	if filepath.Base(path) != "findings.json" {
		t.Errorf("path = %s", path)
	}
	// per-finding to_dict appends potential_severity
	fs := back["findings"].([]any)
	fm := fs[0].(map[string]any)
	if _, ok := fm["potential_severity"]; !ok {
		t.Error("finding missing potential_severity")
	}
}
