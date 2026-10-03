package consolidate

import "testing"

func TestExtractFindings(t *testing.T) {
	md := "" +
		"## Findings\n\n" +
		"### [VULN-001] SQL injection in search\n\n" +
		"- **CWE**: CWE-89\n- **Severity**: High\n- **Location**: app/db.py:42\n" +
		"- **Entry point**: GET /api/search?q=\n- **Data flow**: q -> execute()\n- **Fix**: parameterize\n\n" +
		"### NAV-01 — Broken object authorization — HIGH\n\n" +
		"| **CWE** | CWE-639 |\n| **Location** | app/main.py:17 |\n"

	got := ExtractFindings(md, "phase2b_output.md")
	if len(got) != 2 {
		t.Fatalf("want 2 findings, got %d: %+v", len(got), got)
	}
	if got[0].ID != "VULN-001" || got[0].CWE != "CWE-89" || got[0].Severity != "High" {
		t.Errorf("f0 = %+v", got[0])
	}
	if got[0].Location != "app/db.py:42" || got[0].Source != "phase2b_output.md" {
		t.Errorf("f0 loc/source = %q / %q", got[0].Location, got[0].Source)
	}
	// second finding: renumbered to VULN-002, source_id preserved, table-form fields
	if got[1].ID != "VULN-002" || got[1].SourceID != "NAV-01" || got[1].CWE != "CWE-639" {
		t.Errorf("f1 = %+v", got[1])
	}
}

func TestExtractHandlesTypographicHyphen(t *testing.T) {
	// header id written with a non-breaking hyphen must still parse after normalize.
	md := "### VULN" + string(rune(0x2011)) + "007 — Path traversal\n- **CWE**: CWE-22\n"
	got := ExtractFindings(md, "s")
	if len(got) != 1 || got[0].CWE != "CWE-22" {
		t.Fatalf("got %+v", got)
	}
}

func TestExtractEmptyReturnsNil(t *testing.T) {
	if ExtractFindings("no findings here", "s") != nil {
		t.Error("expected nil for no finding headers")
	}
}
