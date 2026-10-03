package verification

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"vhlocal/internal/consolidate"
)

// T071 (C-C1, C-C4, C-C8): older Markdown artifacts import through the same
// validator; normalized citations keep their original; a decision on an
// invalid_citation candidate is rejected with a clear error.
func TestManifestCitationValidationAndReconcile(t *testing.T) {
	repo, root := t.TempDir(), t.TempDir()
	os.MkdirAll(filepath.Join(repo, "app"), 0o755)
	os.WriteFile(filepath.Join(repo, "app", "db.py"), []byte(strings.Repeat("x = 1\n", 60)), 0o644)
	md := "## Findings\n\n### [VULN-001] A\n\n- **CWE**: CWE-89\n- **Location**: `app/db.py:42` - execute\n- **Entry Point**: GET /a\n\n" +
		"### [VULN-002] B\n\n- **CWE**: CWE-79\n- **Location**: render function, line 10-12 in app/db.py\n- **Entry Point**: GET /b\n\n" +
		"### [VULN-003] C\n\n- **CWE**: CWE-22\n- **Location**: app/db.py:400\n- **Entry Point**: GET /c\n"
	fs := consolidate.ExtractFindings(md, "results/x.md")
	if len(fs) != 3 {
		t.Fatalf("extracted %d", len(fs))
	}
	m, err := BuildManifest(root, repo, "rev1", fs)
	if err != nil {
		t.Fatal(err)
	}
	if m.SchemaVersion != ManifestSchema || m.RawCount != 3 || len(m.Candidates) != 3 || m.Counts[CitationValid] != 1 || m.Counts[CitationInvalid] != 2 {
		t.Fatalf("manifest = schema %d raw %d cands %d counts %v", m.SchemaVersion, m.RawCount, len(m.Candidates), m.Counts)
	}
	var valid, ambiguous, oob Candidate
	for _, c := range m.Candidates {
		switch c.Finding.SourceID {
		case "VULN-001":
			valid = c
		case "VULN-002":
			ambiguous = c
		case "VULN-003":
			oob = c
		}
	}
	if valid.Citation.Status != CitationValid || valid.Finding.Location != "app/db.py:42" || valid.Citation.Original != "app/db.py:42 - execute" || len(valid.Citation.Parsed.Normalization) == 0 {
		t.Errorf("normalized candidate = %+v loc=%s", valid.Citation, valid.Finding.Location)
	}
	if ambiguous.Citation.Status != CitationInvalid || ambiguous.Citation.Error.Code != "E_CITATION_AMBIGUOUS" || ambiguous.Finding.Location == "app/db.py:10-12" {
		t.Errorf("ambiguous candidate must stay invalid and unshifted: %+v", ambiguous.Citation)
	}
	if oob.Citation.Status != CitationInvalid || oob.Citation.Error.Code != "E_RANGE_OUT_OF_BOUNDS" || oob.Citation.Error.Aids.FileLength != 60 || oob.Finding.Location != "app/db.py:400" {
		t.Errorf("out-of-bounds candidate must not be clamped: %+v loc=%s", oob.Citation, oob.Finding.Location)
	}
	// Reconcile: invalid candidates are explained (no error) — a decision on one is
	// rejected explicitly; the valid candidate still needs its decision.
	rc := Reconcile(m, nil, repo)
	if rc.Counts["invalid_citation"] != 2 || rc.Counts["unresolved"] != 3 {
		t.Errorf("counts = %v", rc.Counts)
	}
	for _, r := range rc.Results {
		if (r.CandidateID == ambiguous.ID || r.CandidateID == oob.ID) && !strings.HasPrefix(r.Reason, "invalid citation (") {
			t.Errorf("reason = %q", r.Reason)
		}
	}
	if len(rc.Errors) != 1 || !strings.Contains(rc.Errors[0], valid.ID+": missing decision") {
		t.Errorf("only the valid candidate's missing decision is an error: %v", rc.Errors)
	}
	perfect := Decision{CandidateID: ambiguous.ID, Verdict: "supported", Rationale: "r", EntryPoint: "GET /b", AttackerControl: "a", Preconditions: "p",
		DefensesReviewed: "d", SecurityImpact: "s", Reviewer: "x", Revision: "rev1"}
	rc2 := Reconcile(m, []Decision{perfect}, repo)
	if rc2.Counts["supported"] != 0 {
		t.Error("a verdict on an invalid_citation candidate must never be accepted")
	}
	found := false
	for _, e := range rc2.Errors {
		if strings.Contains(e, ambiguous.ID) && strings.Contains(e, "invalid_citation") {
			found = true
		}
	}
	if !found {
		t.Errorf("errors must name the rejected decision: %v", rc2.Errors)
	}
	// Schema-1 manifests (pre-015 records) still reconcile.
	m.SchemaVersion = 1
	if rc3 := Reconcile(m, nil, repo); len(rc3.Results) != 3 {
		t.Error("schema 1 must still be accepted")
	}
}
