package membank

import (
	"path/filepath"
	"testing"

	"vhlocal/internal/consolidate"
)

func supported(id, cwe, loc, title string) consolidate.Finding {
	f := consolidate.NewFinding(id)
	f.CWE, f.Location, f.Title = cwe, loc, title
	f.Classification = consolidate.ClassStaticallySupported
	consolidate.ApplyKnowledge(&f)
	return f
}

func TestUpdateIdempotentAndConfidence(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("VHLOCAL_LEDGER_DIR", dir)
	target := filepath.Join(dir, "app")
	f := supported("V1", "CWE-89", "app/db.py:42 execute()", "SQLi")

	lg, err := Update(target, "run-1", "m", 1.0, []consolidate.Finding{f})
	if err != nil {
		t.Fatal(err)
	}
	if len(lg.Findings) != 1 || lg.Findings[0].Confidence != "provisional" {
		t.Fatalf("after run-1: %+v", lg.Findings)
	}
	// Re-record the SAME run id: must not double-count (idempotent).
	lg, _ = Update(target, "run-1", "m", 1.0, []consolidate.Finding{f})
	if len(lg.RunsRecorded) != 1 {
		t.Fatalf("run-1 recorded twice: %v", lg.RunsRecorded)
	}
	// A second distinct run confirms it → confidence rises to 'confirmed'.
	lg, _ = Update(target, "run-2", "m", 2.0, []consolidate.Finding{f})
	if lg.Findings[0].ConfirmedCount != 2 || lg.Findings[0].Confidence != "confirmed" {
		t.Fatalf("after run-2: count=%d conf=%s", lg.Findings[0].ConfirmedCount, lg.Findings[0].Confidence)
	}
	// Third run → reliable.
	lg, _ = Update(target, "run-3", "m", 3.0, []consolidate.Finding{f})
	if lg.Findings[0].Confidence != "reliable" {
		t.Fatalf("after run-3: conf=%s", lg.Findings[0].Confidence)
	}
}

func TestListAndLoadDetail(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("VHLOCAL_LEDGER_DIR", dir)
	target := filepath.Join(dir, "app")
	Update(target, "r1", "m", 1.0, []consolidate.Finding{supported("V1", "CWE-89", "db.py:1 q()", "SQLi")})

	sums, err := List()
	if err != nil || len(sums) != 1 {
		t.Fatalf("list: %v n=%d", err, len(sums))
	}
	if sums[0].Total != 1 {
		t.Errorf("summary total = %d", sums[0].Total)
	}
	detail, ok := LoadDetail(sums[0].Slug)
	if !ok {
		t.Fatal("detail not found")
	}
	if _, ok := detail["summary"]; !ok {
		t.Error("detail missing summary")
	}
}

func TestHypothesisNotLedgered(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("VHLOCAL_LEDGER_DIR", dir)
	h := consolidate.NewFinding("H1")
	h.CWE, h.Location = "CWE-89", "db.py:1 q()"
	h.Classification = consolidate.ClassHypothesis
	consolidate.ApplyKnowledge(&h)
	lg, _ := Update(filepath.Join(dir, "app"), "r1", "m", 1.0, []consolidate.Finding{h})
	if len(lg.Findings) != 0 {
		t.Errorf("hypotheses must not enter the ledger: %+v", lg.Findings)
	}
}
