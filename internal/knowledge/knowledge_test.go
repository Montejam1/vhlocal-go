package knowledge

import "testing"

func TestNormalizedCWEAndName(t *testing.T) {
	cases := []struct {
		cwe, wantCanon, wantName string
	}{
		{"CWE-89", "CWE-89", "SQL Injection"},
		{"89", "CWE-89", "SQL Injection"},
		// sibling rolls up to family canonical
		{"CWE-639", "CWE-284", "Broken Access Control"},
		{"CWE-862", "CWE-284", "Broken Access Control"},
		{"CWE-95", "CWE-94", "Code Injection"},
		{"CWE-77", "CWE-78", "OS Command Injection"},
		// unknown numeric -> passthrough, no name
		{"CWE-99999", "CWE-99999", ""},
		// non-CWE -> empty
		{"not-a-cwe", "", ""},
	}
	for _, c := range cases {
		if got := NormalizedCWE(c.cwe); got != c.wantCanon {
			t.Errorf("NormalizedCWE(%q)=%q want %q", c.cwe, got, c.wantCanon)
		}
		if got := CanonicalName(c.cwe); got != c.wantName {
			t.Errorf("CanonicalName(%q)=%q want %q", c.cwe, got, c.wantName)
		}
	}
}

func TestNormalizedSeverityBaseline(t *testing.T) {
	cases := []struct{ cwe, want string }{
		{"CWE-89", "High"},   // sql-injection
		{"CWE-94", "High+"},  // code-injection
		{"CWE-79", "Medium"}, // xss
		{"CWE-601", "Low"},   // open-redirect
		{"CWE-284", "High"},  // access-control
		{"CWE-99999", ""},    // unknown family
	}
	for _, c := range cases {
		if got := NormalizedSeverity(c.cwe, ""); got != c.want {
			t.Errorf("NormalizedSeverity(%q,'')=%q want %q", c.cwe, got, c.want)
		}
	}
}

func TestNormalizedSeverityGatedDropsOneTier(t *testing.T) {
	// High -> Medium when an auth precondition is present.
	if got := NormalizedSeverity("CWE-89", "requires a valid session token"); got != "Medium" {
		t.Errorf("gated sql = %q want Medium", got)
	}
	// High+ -> High
	if got := NormalizedSeverity("CWE-94", "authenticated user only"); got != "High" {
		t.Errorf("gated code-injection = %q want High", got)
	}
	// Low clamps at Informational (not below)
	if got := NormalizedSeverity("CWE-601", "requires login credential"); got != "Informational" {
		t.Errorf("gated open-redirect = %q want Informational", got)
	}
	// no gate -> baseline unchanged
	if got := NormalizedSeverity("CWE-89", "unauthenticated attacker"); got != "High" {
		t.Errorf("ungated sql = %q want High", got)
	}
}

func TestFirstFamilyWins(t *testing.T) {
	// CWE-346 appears only in cors; ensure a member maps to its family.
	if f := FamilyOf("CWE-942"); f == nil || f.Key != "cors" {
		t.Fatalf("CWE-942 family = %v", f)
	}
}
