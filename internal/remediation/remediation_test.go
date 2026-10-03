package remediation

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWriteRemediationTree(t *testing.T) {
	dir := t.TempDir()
	fvs := []FindingView{
		{ID: "VULN-001", Title: "SQLi", CWE: "CWE-89", Location: "app/db.py:42", Severity: "High", Fix: "parameterize"},
		{ID: "VULN-002", Title: "dup", CWE: "CWE-89", Location: "app/db.py:42", Duplicate: true},
		{ID: "VULN-003", Title: "XSS", CWE: "CWE-79", Location: "a.py:1", CanonicalName: "Cross-Site Scripting"},
	}
	n, err := Write(dir, fvs)
	if err != nil || n != 2 { // duplicate skipped
		t.Fatalf("n=%d err=%v", n, err)
	}
	// per-finding files exist
	for _, id := range []string{"VULN-001", "VULN-003"} {
		if _, err := os.Stat(filepath.Join(dir, "remediation", id, "remediate.json")); err != nil {
			t.Errorf("missing remediate.json for %s", id)
		}
		if _, err := os.Stat(filepath.Join(dir, "remediation", id, "summary.md")); err != nil {
			t.Errorf("missing summary.md for %s", id)
		}
	}
	// index.json
	b, _ := os.ReadFile(filepath.Join(dir, "remediation", "index.json"))
	var idx map[string]any
	json.Unmarshal(b, &idx)
	if idx["count"] != float64(2) {
		t.Errorf("index count = %v", idx["count"])
	}
	// finding with no explicit fix gets generated guidance
	fb, _ := os.ReadFile(filepath.Join(dir, "remediation", "VULN-003", "remediate.json"))
	var dto DTO
	json.Unmarshal(fb, &dto)
	if dto.Guidance == "" {
		t.Error("expected generated guidance")
	}
	// T050 (C-R5, C-R13): the guidance is weakness-specific, not the old universal answer,
	// and it declares where it came from.
	if strings.Contains(dto.Guidance, "Apply the standard remediation") ||
		strings.Contains(dto.Guidance, "validate/encode untrusted input at the sink") {
		t.Errorf("VULN-003 still gets the universal fallback:\n%s", dto.Guidance)
	}
	if dto.GuidanceProvenance != "general" {
		t.Errorf("VULN-003 provenance = %q, want general", dto.GuidanceProvenance)
	}
	if !strings.Contains(dto.Guidance, "implemented or tested") {
		t.Error("the guidance must disclose that nothing has been implemented or tested")
	}
	// A recorded fix is used as recorded, and declared as such.
	sb, _ := os.ReadFile(filepath.Join(dir, "remediation", "VULN-001", "remediate.json"))
	var sqli DTO
	json.Unmarshal(sb, &sqli)
	if sqli.GuidanceProvenance != "recorded" || !strings.Contains(sqli.Guidance, "parameterize") {
		t.Errorf("VULN-001 lost its recorded fix: provenance=%q\n%s", sqli.GuidanceProvenance, sqli.Guidance)
	}
	// Two different weaknesses do not get the same advice.
	if dto.Guidance == sqli.Guidance {
		t.Error("XSS and SQL injection received identical guidance")
	}
}
