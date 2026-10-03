package report

import (
	"strings"
	"testing"
)

// T008 (FR-009, C-P13): the severity mapping is a documented presentation choice. It
// never promotes, never guesses, and never loses the recorded rating.
func TestDisplaySeverityMapping(t *testing.T) {
	cases := []struct {
		recorded, want string
		recordedAtAll  bool
		diverges       bool
	}{
		{"Critical", SevCritical, true, false},
		{"High+", SevHigh, true, true}, // the whole point: High, never Critical
		{"High", SevHigh, true, false},
		{"Medium", SevMedium, true, false},
		{"Low", SevLow, true, false},
		{"Informational", SevInformational, true, false},
		{"Unrated", SevUnrated, true, false},
		{"high+", SevHigh, true, true},   // case-insensitive
		{" High ", SevHigh, true, false}, // surrounding space is not a new tier
		{"Severe", SevUnrated, true, true},
		{"", SevUnrated, false, false},
	}
	for _, c := range cases {
		if got := DisplaySeverity(c.recorded); got != c.want {
			t.Errorf("DisplaySeverity(%q) = %q, want %q", c.recorded, got, c.want)
		}
		if got := SeverityWasRecorded(c.recorded); got != c.recordedAtAll {
			t.Errorf("SeverityWasRecorded(%q) = %v, want %v", c.recorded, got, c.recordedAtAll)
		}
		if got := SeverityDiverges(c.recorded); got != c.diverges {
			t.Errorf("SeverityDiverges(%q) = %v, want %v", c.recorded, got, c.diverges)
		}
	}
	// A missing rating must not be guessed into a plausible tier.
	if DisplaySeverity("") != SevUnrated || SeverityWasRecorded("") {
		t.Error("an absent severity must read as Unrated and as not recorded, never as a guess")
	}
	// High+ must never reach Critical through any path.
	if DisplaySeverity("High+") == SevCritical {
		t.Error("High+ silently became Critical")
	}
}

// T008 (C-P13): group severity is the highest displayed severity among its members, and
// every distinct recorded rating stays available for technical details.
func TestGroupSeverityUsesHighestAndRetainsOriginals(t *testing.T) {
	cases := []struct {
		name      string
		recorded  []string
		want      string
		originals []string
	}{
		{"single high+", []string{"High+"}, SevHigh, []string{"High+"}},
		{"high+ with medium", []string{"Medium", "High+"}, SevHigh, []string{"High+", "Medium"}},
		{"critical wins", []string{"Medium", "Critical", "High"}, SevCritical, []string{"Critical", "High", "Medium"}},
		{"high+ and high both display High, both retained most-severe-first", []string{"High", "High+"}, SevHigh, []string{"High+", "High"}},
		{"unknown label", []string{"Spicy"}, SevUnrated, []string{"Spicy"}},
		{"unknown does not outrank a real rating", []string{"Spicy", "Low"}, SevLow, []string{"Low", "Spicy"}},
		{"no ratings at all", nil, SevUnrated, nil},
		{"only empties", []string{"", "  "}, SevUnrated, nil},
		{"duplicates collapse", []string{"High", "High", "High"}, SevHigh, []string{"High"}},
	}
	for _, c := range cases {
		got, originals := GroupSeverity(c.recorded)
		if got != c.want {
			t.Errorf("%s: GroupSeverity = %q, want %q", c.name, got, c.want)
		}
		if strings.Join(originals, ",") != strings.Join(c.originals, ",") {
			t.Errorf("%s: originals = %v, want %v", c.name, originals, c.originals)
		}
	}
	// Ordering is deterministic: the same input twice gives the same originals.
	a, oa := GroupSeverity([]string{"Medium", "High+", "Low", "High"})
	b, ob := GroupSeverity([]string{"Medium", "High+", "Low", "High"})
	if a != b || strings.Join(oa, ",") != strings.Join(ob, ",") {
		t.Error("GroupSeverity is not deterministic")
	}
}

// T008: the displayed categories are exactly the six the spec names, and a zeroed chart
// shows every one of them rather than omitting empty tiers.
func TestDisplaySeverityCategoriesAreExact(t *testing.T) {
	want := []string{"Critical", "High", "Medium", "Low", "Informational", "Unrated"}
	if strings.Join(DisplaySeverities, ",") != strings.Join(want, ",") {
		t.Errorf("DisplaySeverities = %v, want %v", DisplaySeverities, want)
	}
	counts := EmptySeverityCounts()
	if len(counts) != len(want) {
		t.Errorf("EmptySeverityCounts has %d categories, want %d", len(counts), len(want))
	}
	for _, s := range want {
		if n, ok := counts[s]; !ok || n != 0 {
			t.Errorf("EmptySeverityCounts missing a real zero for %q", s)
		}
	}
	// Ranks order the categories correctly and push an unknown category last.
	for i := 1; i < len(DisplaySeverities); i++ {
		if SeverityRankOf(DisplaySeverities[i-1]) >= SeverityRankOf(DisplaySeverities[i]) {
			t.Errorf("rank order broken between %q and %q", DisplaySeverities[i-1], DisplaySeverities[i])
		}
	}
	if SeverityRankOf("not-a-category") <= SeverityRankOf(SevUnrated) {
		t.Error("an unknown category must sort last, never ahead of a real one")
	}
}

// T008 (SC-002): the frozen corpus maps to 13 High, 19 Medium and 2 Low once High+
// folds into High, with no Critical, Informational or Unrated.
func TestFixture016GroupSeverityDistribution(t *testing.T) {
	base := loadFixture016Baseline(t)
	groups := fixture016Groups(t)
	doc := fixture016Doc(t)

	sevByID := map[string]string{}
	for _, f := range doc.Findings {
		id, _ := f["id"].(string)
		sev, _ := f["severity"].(string)
		sevByID[id] = sev
	}
	got := EmptySeverityCounts()
	for _, g := range groups.Groups {
		recorded := make([]string, 0, len(g.Members))
		for _, m := range g.Members {
			recorded = append(recorded, sevByID[m.FindingID])
		}
		display, _ := GroupSeverity(recorded)
		got[display]++
	}
	for _, sev := range DisplaySeverities {
		if got[sev] != base.GroupSeverity[sev] {
			t.Errorf("group severity %s = %d, baseline records %d", sev, got[sev], base.GroupSeverity[sev])
		}
	}
	total := 0
	for _, n := range got {
		total += n
	}
	if total != base.Counts.EstablishedGroups {
		t.Errorf("severity counts sum to %d, want one per group (%d)", total, base.Counts.EstablishedGroups)
	}
}
