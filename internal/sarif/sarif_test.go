package sarif

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"vhlocal/internal/consolidate"
)

func supported(id, cwe, sev, title, loc string) consolidate.Finding {
	f := consolidate.NewFinding(id)
	f.CWE, f.Severity, f.Title, f.Location = cwe, sev, title, loc
	f.Classification = consolidate.ClassStaticallySupported
	consolidate.ApplyKnowledge(&f)
	return f
}

func TestBuildSARIFShape(t *testing.T) {
	fs := []consolidate.Finding{
		supported("VULN-001", "CWE-89", "High", "SQLi", "app/db.py:42"),
	}
	status := consolidate.RunStatus{ExecutionStatus: consolidate.ExecComplete}
	doc := Build(fs, status, "0.1.0", "/x/vulnapp", "gpt-oss:120b")

	if doc["version"] != "2.1.0" || doc["$schema"] != Schema {
		t.Fatalf("header wrong: %v / %v", doc["version"], doc["$schema"])
	}
	runs := doc["runs"].([]map[string]any)
	run := runs[0]
	driver := run["tool"].(map[string]any)["driver"].(map[string]any)
	if driver["name"] != "vhlocal" {
		t.Errorf("driver name = %v", driver["name"])
	}
	results := run["results"].([]map[string]any)
	if len(results) != 1 {
		t.Fatalf("want 1 result, got %d", len(results))
	}
	r := results[0]
	if r["level"] != "error" { // High -> error, substantiated
		t.Errorf("level = %v want error", r["level"])
	}
	if r["kind"] != "fail" {
		t.Errorf("kind = %v want fail", r["kind"])
	}
	if r["ruleId"] != "CWE-89" {
		t.Errorf("ruleId = %v want CWE-89", r["ruleId"])
	}
	locs := r["locations"].([]map[string]any)
	pl := locs[0]["physicalLocation"].(map[string]any)
	if pl["artifactLocation"].(map[string]any)["uri"] != "app/db.py" {
		t.Errorf("uri = %v", pl["artifactLocation"])
	}
}

func TestUnsubstantiatedIsReviewNote(t *testing.T) {
	f := consolidate.NewFinding("VULN-9")
	f.CWE, f.Severity, f.Title = "CWE-89", "High", "maybe"
	f.Classification = consolidate.ClassHypothesis // not substantiated
	consolidate.ApplyKnowledge(&f)
	doc := Build([]consolidate.Finding{f}, consolidate.RunStatus{}, "0.1.0", "", "")
	r := doc["runs"].([]map[string]any)[0]["results"].([]map[string]any)[0]
	if r["kind"] != "review" || r["level"] != "note" {
		t.Fatalf("unsubstantiated should be review/note, got kind=%v level=%v", r["kind"], r["level"])
	}
}

func TestDegradedReasonsBecomeNotifications(t *testing.T) {
	status := consolidate.RunStatus{ExecutionStatus: consolidate.ExecPartial, CoverageDegradedReasons: []string{"shallow run"}}
	doc := Build(nil, status, "", "", "")
	run := doc["runs"].([]map[string]any)[0]
	inv := run["invocations"].([]map[string]any)[0]
	if inv["executionSuccessful"] != false {
		t.Error("partial execution should be executionSuccessful=false")
	}
	if _, ok := inv["toolExecutionNotifications"]; !ok {
		t.Error("degraded reasons should surface as notifications")
	}
}

func TestWriteValidJSON(t *testing.T) {
	dir := t.TempDir()
	path, err := Write([]consolidate.Finding{supported("V1", "CWE-79", "Medium", "xss", "a.py:1")},
		consolidate.RunStatus{}, "0.1.0", "/r", "m", dir)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(path)
	var back map[string]any
	if json.Unmarshal(b, &back) != nil {
		t.Fatal("not valid JSON")
	}
	if filepath.Base(path) != "findings.sarif" {
		t.Errorf("path = %s", path)
	}
}
