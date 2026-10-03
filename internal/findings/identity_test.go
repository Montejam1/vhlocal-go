package findings

import "testing"

// T004: cross-scan identity is stable for the same finding across scans, distinct
// for different findings, and falls back to the finding id when no stable key exists.
func TestStableIDPrecedenceAndOccurrence(t *testing.T) {
	a := map[string]any{"stable_identity": "abc123", "id": "F1", "location": "app.go:10"}
	b := map[string]any{"stable_identity": "abc123", "id": "F9", "location": "app.go:10"}
	if StableID(a) != StableID(b) || StableID(a) != "source-v1:abc123" {
		t.Fatalf("same stable_identity must yield same key: %q vs %q", StableID(a), StableID(b))
	}
	c := map[string]any{"stable_identity": "different", "id": "F1"}
	if StableID(a) == StableID(c) {
		t.Fatal("different stable_identity must yield different keys")
	}

	// Occurrence id combines scan + stable id, and is URL-safe (no '#').
	occ := OccurrenceID("scanX", a, 0)
	if occ != "scanX~source-v1:abc123" {
		t.Fatalf("occurrence id = %q", occ)
	}
	// Fallback to finding id when no stable key can be derived.
	noKey := map[string]any{"id": "F7"}
	if got := OccurrenceID("scanX", noKey, 3); got != "scanX~id:F7" {
		t.Fatalf("fallback occurrence id = %q", got)
	}
	// Fallback to ordinal when neither stable key nor id exist.
	if got := OccurrenceID("scanX", map[string]any{}, 5); got != "scanX~ord:5" {
		t.Fatalf("ordinal occurrence id = %q", got)
	}
}

// T004: the evidence fingerprint changes when material evidence changes, so a
// later scan is not silently governed by a decision made on different evidence.
func TestEvidenceFingerprintChanges(t *testing.T) {
	base := map[string]any{"location": "app.go:10", "cwe": "CWE-89", "severity": "High"}
	same := map[string]any{"severity": "High", "cwe": "CWE-89", "location": "app.go:10"} // reordered
	if EvidenceFingerprint(base) != EvidenceFingerprint(same) {
		t.Fatal("fingerprint must be stable across key order")
	}
	moved := map[string]any{"location": "app.go:42", "cwe": "CWE-89", "severity": "High"}
	if EvidenceFingerprint(base) == EvidenceFingerprint(moved) {
		t.Fatal("fingerprint must change when the location changes")
	}
}
