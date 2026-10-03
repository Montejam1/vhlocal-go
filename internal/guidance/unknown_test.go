package guidance

import (
	"strings"
	"testing"
)

// T039 (C-R4): a weakness that belongs to no known family takes the investigate branch and
// never borrows another family's advice. The fixture's CWE-754 (improper check for an
// unusual condition) and CWE-90 (LDAP injection) belong to no family in the knowledge
// tables, so they are the real cases this must handle.
func TestUnknownWeaknessTakesInvestigateBranch(t *testing.T) {
	for _, cwe := range []string{"CWE-754", "CWE-90", "CWE-0", "", "not-a-cwe"} {
		rec := Resolve(Request{CWE: cwe})
		if rec.Provenance != ProvInvestigate {
			t.Errorf("%q: provenance = %q, want %q", cwe, rec.Provenance, ProvInvestigate)
		}
		if len(rec.Steps) == 0 {
			t.Errorf("%q: the investigate branch must still say what to do", cwe)
		}
		// It must not look like family advice: no mechanism claim borrowed from a family.
		joined := strings.ToLower(strings.Join(rec.Steps, " "))
		for _, borrowed := range []string{"deserializ", "parameterized", "allow-list of approved", "atomic"} {
			if strings.Contains(joined, borrowed) {
				t.Errorf("%q: investigate advice borrowed family wording %q: %s", cwe, borrowed, joined)
			}
		}
		if rec.Label == "" {
			t.Errorf("%q: the reader must be told this is not weakness-specific guidance", cwe)
		}
	}
}

// T039: a known family still resolves to its own general guidance, so the investigate
// branch is the exception rather than the default.
func TestKnownWeaknessResolvesToItsFamily(t *testing.T) {
	rec := Resolve(Request{CWE: "CWE-502"})
	if rec.Provenance != ProvGeneral {
		t.Fatalf("CWE-502 provenance = %q, want %q", rec.Provenance, ProvGeneral)
	}
	if !strings.Contains(strings.ToLower(strings.Join(rec.Steps, " ")), "deserializ") {
		t.Errorf("CWE-502 did not resolve to deserialization guidance: %v", rec.Steps)
	}
}
