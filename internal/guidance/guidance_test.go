package guidance

import (
	"strings"
	"testing"

	"vhlocal/internal/knowledge"
)

// T037 (FR-015, C-R6): the four families named in the specification receive different,
// mechanism-appropriate guidance. "Mechanism-appropriate" is checked by what the steps
// actually tell the reader to change, not by the family name being echoed back.
func TestFamilyGuidanceIsMechanismAppropriate(t *testing.T) {
	cases := []struct {
		family string
		// wantAny: at least one of these must appear in the steps.
		wantAny []string
		// wantNone: none of these may appear — advice for a different mechanism.
		wantNone []string
	}{
		{
			family:   "deserialization",
			wantAny:  []string{"do not deserialize", "stop deserializing", "without deserializing", "safe format"},
			wantNone: []string{"encode", "escape", "html-escape"},
		},
		{
			family:  "access-control",
			wantAny: []string{"authorization", "permission"},
			// Access control is not fixed by cleaning the input.
			wantNone: []string{"encode", "escape", "sanitize the input"},
		},
		{
			family:   "path-traversal",
			wantAny:  []string{"resolve", "approved", "base director"},
			wantNone: []string{"encode", "escape"},
		},
		{
			family:   "race-condition",
			wantAny:  []string{"atomic", "transaction", "lock"},
			wantNone: []string{"encode", "escape", "sanitize"},
		},
	}
	for _, tc := range cases {
		g, ok := For(tc.family)
		if !ok {
			t.Errorf("no guidance for family %q", tc.family)
			continue
		}
		if len(g.Steps) == 0 {
			t.Errorf("%s: no steps", tc.family)
			continue
		}
		steps := strings.ToLower(strings.Join(g.Steps, " "))
		hit := false
		for _, w := range tc.wantAny {
			if strings.Contains(steps, w) {
				hit = true
				break
			}
		}
		if !hit {
			t.Errorf("%s: steps address no part of the mechanism (wanted one of %v):\n%s", tc.family, tc.wantAny, steps)
		}
		for _, bad := range tc.wantNone {
			if strings.Contains(steps, bad) {
				t.Errorf("%s: steps carry advice for a different mechanism (%q):\n%s", tc.family, bad, steps)
			}
		}
		if strings.TrimSpace(g.Mechanism) == "" {
			t.Errorf("%s: no mechanism statement", tc.family)
		}
		if len(g.Checks) == 0 {
			t.Errorf("%s: no suggested checks", tc.family)
		}
	}
}

// T038 (C-R5, C-R12): no entry falls back to a universal "validate or encode untrusted
// input at the sink", and no two families share their steps.
func TestNoUniversalFallbackAndNoSharedSteps(t *testing.T) {
	universal := []string{
		"validate/encode untrusted input at the sink",
		"validate or encode untrusted input at the sink",
		"apply the standard remediation",
	}
	seen := map[string]string{}
	for _, key := range knowledge.Keys() {
		g, ok := For(key)
		if !ok {
			continue
		}
		joined := strings.ToLower(strings.Join(g.Steps, " | "))
		for _, u := range universal {
			if strings.Contains(joined, u) {
				t.Errorf("%s: carries the universal fallback %q", key, u)
			}
		}
		if other, dup := seen[joined]; dup {
			t.Errorf("%s and %s share identical steps; one mechanism's advice was reused", key, other)
		}
		seen[joined] = key
	}
	if len(seen) == 0 {
		t.Fatal("the guidance table is empty")
	}
}

// T048: the table covers every weakness family the knowledge tables define, so no family
// silently falls through to the investigate branch because an entry was forgotten.
func TestTableCoversEveryKnownFamily(t *testing.T) {
	keys := knowledge.Keys()
	if len(keys) != 27 {
		t.Fatalf("the knowledge table has %d families; this test and the guidance table were written against 27", len(keys))
	}
	for _, key := range keys {
		if _, ok := For(key); !ok {
			t.Errorf("no guidance entry for the known family %q", key)
		}
	}
	// And nothing in the guidance table names a family the knowledge tables do not define.
	known := map[string]bool{}
	for _, k := range keys {
		known[k] = true
	}
	for _, k := range Families() {
		if !known[k] {
			t.Errorf("guidance table carries %q, which is not a knowledge family key", k)
		}
	}
}
