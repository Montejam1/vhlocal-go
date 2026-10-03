package consolidate

import "testing"

func sinkFinding() Finding {
	f := NewFinding("V1")
	f.CWE, f.Location, f.EntryPoint, f.DataFlow = "CWE-89", "app/db.py:42", "GET /s?q=", "q -> execute()"
	f.FromConfirmed = true
	ApplyKnowledge(&f)
	return f
}

func TestQualityBalancedSinkNeedsSource(t *testing.T) {
	f := sinkFinding()
	ApplyQuality(&f, StrictBalanced, "")
	if f.Classification != ClassStaticallySupported {
		t.Fatalf("well-formed sink finding should clear balanced bar, got %q", f.Classification)
	}
	// Remove the source pattern → a sink finding no longer clears at balanced.
	f2 := sinkFinding()
	f2.DataFlow, f2.EntryPoint = "", ""
	ApplyQuality(&f2, StrictBalanced, "")
	if f2.Classification != ClassHypothesis {
		t.Errorf("sink finding without source should stay hypothesis, got %q", f2.Classification)
	}
	if f2.HypothesisReason == "" {
		t.Error("expected a hypothesis reason")
	}
}

func TestQualityLenientAndStrict(t *testing.T) {
	f := sinkFinding()
	f.DataFlow, f.EntryPoint = "", "" // only location+cwe
	ApplyQuality(&f, StrictLenient, "")
	if f.Classification != ClassStaticallySupported {
		t.Errorf("lenient should clear on any one signal, got %q", f.Classification)
	}
	f2 := sinkFinding()
	f2.FromConfirmed = false // strict requires corroboration for sink families
	ApplyQuality(&f2, StrictStrict, "")
	if f2.Classification != ClassHypothesis {
		t.Errorf("strict sink without corroboration should not clear, got %q", f2.Classification)
	}
}

func TestQualityChecksRecorded(t *testing.T) {
	f := sinkFinding()
	ApplyQuality(&f, StrictBalanced, "")
	if len(f.QualityChecks) != 6 {
		t.Fatalf("expected 6 quality checks, got %d", len(f.QualityChecks))
	}
	for _, c := range f.QualityChecks {
		if c["name"] == "" || (c["status"] != "pass" && c["status"] != "fail") {
			t.Errorf("bad check: %v", c)
		}
	}
}
