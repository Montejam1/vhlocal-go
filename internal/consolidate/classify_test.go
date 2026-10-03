package consolidate

import "testing"

// Feature 015 (FR-002, T008): one classification for every surface, and
// supported-only severity totals that sum to the supported count with Unrated
// explicit.
func TestClassifyEveryClass(t *testing.T) {
	dup := "F1"
	cases := []struct {
		name string
		f    map[string]any
		want Class
	}{
		{"duplicate wins", map[string]any{"duplicate_of": dup, "verification_status": "supported"}, ClassDuplicate},
		{"from_confirmed", map[string]any{"from_confirmed": true}, ClassSupported},
		{"verification supported", map[string]any{"verification_status": "supported"}, ClassSupported},
		{"reviewed classification", map[string]any{"classification": ClassReviewed}, ClassSupported},
		{"statically supported classification", map[string]any{"classification": ClassStaticallySupported}, ClassSupported},
		{"rejected", map[string]any{"verification_status": "rejected"}, ClassRejected},
		{"explicit unresolved verdict", map[string]any{"verification_status": "unresolved", "verification_record": map[string]any{"verdict": "unresolved"}}, ClassUnresolvedExplicit},
		{"unresolved without record", map[string]any{"verification_status": "unresolved"}, ClassUnresolvedFailed},
		{"hypothesis", map[string]any{"classification": ClassHypothesis}, ClassUnresolvedFailed},
		{"nil", nil, ClassUnresolvedFailed},
	}
	for _, c := range cases {
		if got := Classify(c.f); got != c.want {
			t.Errorf("%s: Classify = %s, want %s", c.name, got, c.want)
		}
	}
	// Typed and map classification agree.
	f := Finding{VerificationStatus: "unresolved", VerificationRecord: map[string]any{"verdict": "unresolved"}}
	if ClassifyFinding(f) != ClassUnresolvedExplicit || Classify(f.ToMap()) != ClassUnresolvedExplicit {
		t.Error("typed and map classification disagree for an explicit unresolved verdict")
	}
}

func TestBuildSeveritySupportedSumsToSupported(t *testing.T) {
	dup := "A"
	findings := []Finding{
		{ID: "A", Severity: "High", VerificationStatus: "supported", Assessment: AssessSupported},
		{ID: "B", Severity: "", FromConfirmed: true, Assessment: AssessSupported}, // Unrated, supported
		{ID: "C", Severity: "High", VerificationStatus: "rejected"},
		{ID: "D", Severity: "Medium", VerificationStatus: "unresolved", VerificationRecord: map[string]any{"verdict": "unresolved"}},
		{ID: "E", Severity: "Low", VerificationStatus: "unresolved"},
		{ID: "F", Severity: "High", VerificationStatus: "supported", DuplicateOf: &dup},
	}
	doc := Build(findings, Options{})
	sum := 0
	for _, n := range doc.SeveritySupported {
		sum += n
	}
	if sum != 2 || doc.SeveritySupported["High"] != 1 || doc.SeveritySupported[DefaultSeverity] != 1 {
		t.Errorf("severity_supported = %v, want High=1 Unrated=1 (sum 2)", doc.SeveritySupported)
	}
	if doc.SeverityCandidates["High"] != 2 || doc.SeverityCandidates["Medium"] != 1 || doc.SeverityCandidates["Low"] != 1 || doc.SeverityCandidates[DefaultSeverity] != 1 {
		t.Errorf("severity_candidates = %v (non-duplicate candidates of every class)", doc.SeverityCandidates)
	}
	// The legacy Counts map is retained unchanged (keyed by raw severity, duplicates skipped).
	if doc.Counts["High"] != 2 || doc.Counts[""] != 1 {
		t.Errorf("legacy counts changed: %v", doc.Counts)
	}
	if doc.ClassCounts[ClassSupported] != 2 || doc.ClassCounts[ClassRejected] != 1 || doc.ClassCounts[ClassUnresolvedExplicit] != 1 || doc.ClassCounts[ClassUnresolvedFailed] != 1 || doc.ClassCounts[ClassDuplicate] != 1 {
		t.Errorf("class_counts = %v", doc.ClassCounts)
	}
}
