package guidance

import (
	"regexp"
	"strings"
	"testing"
)

// T040 (FR-015, C-R7): where the fix depends on a policy or an invariant the records
// cannot establish, the recommendation NAMES the missing decision instead of inventing it.
// Broken access control and a race condition are the two cases the specification calls out:
// the scanner knows the check is missing, not what the rule should be.
func TestPolicyDependentFamiliesNameTheMissingDecision(t *testing.T) {
	cases := map[string][]string{
		"access-control": {"who", "policy", "permission"},
		"race-condition": {"invariant", "rule", "must hold"},
	}
	for family, wantAny := range cases {
		g, ok := For(family)
		if !ok {
			t.Errorf("no guidance for %q", family)
			continue
		}
		if strings.TrimSpace(g.RequiresDecision) == "" {
			t.Errorf("%s: the missing decision is not named", family)
			continue
		}
		low := strings.ToLower(g.RequiresDecision)
		hit := false
		for _, w := range wantAny {
			if strings.Contains(low, w) {
				hit = true
				break
			}
		}
		if !hit {
			t.Errorf("%s: the missing decision does not say what must be decided (wanted one of %v): %q", family, wantAny, g.RequiresDecision)
		}

		// The steps must not invent the policy: no concrete role, user or threshold.
		invented := []*regexp.Regexp{
			regexp.MustCompile(`(?i)\bonly (?:admins?|administrators?|owners?|managers?) (?:can|may|should)\b`),
			regexp.MustCompile(`(?i)\brestrict to the (?:tenant|owner|account) that\b`),
			regexp.MustCompile(`(?i)\b(?:at most|no more than) \d+\b`),
		}
		joined := strings.Join(g.Steps, " ")
		for _, re := range invented {
			if loc := re.FindString(joined); loc != "" {
				t.Errorf("%s: steps invent the policy (%q)", family, loc)
			}
		}
	}
}

// T040: the resolved recommendation carries the missing decision through to the reader, so
// a policy-dependent fix never reads as a mechanical change with no decision attached.
func TestResolveCarriesTheMissingDecision(t *testing.T) {
	// CWE-639 is a member of access-control; CWE-362 is the race-condition canonical.
	for _, cwe := range []string{"CWE-639", "CWE-362"} {
		rec := Resolve(Request{CWE: cwe})
		if rec.MissingDecision == "" {
			t.Errorf("%s: the resolved recommendation drops the missing decision", cwe)
		}
	}
	// A mechanism that needs no policy decision does not manufacture one.
	rec := Resolve(Request{CWE: "CWE-502"})
	if rec.MissingDecision != "" {
		t.Errorf("CWE-502 needs no policy decision, got %q", rec.MissingDecision)
	}
}
