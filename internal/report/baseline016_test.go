package report

import (
	"strings"
	"testing"

	"vhlocal/internal/consolidate"
)

// Feature 016 (T005): the frozen acceptance corpus must reproduce every recorded count
// from its own records. If a future fixture regeneration changes the corpus, this fails
// loudly instead of silently moving the acceptance targets in SC-002 and SC-010.
func TestFixture016ReproducesRecordedCounts(t *testing.T) {
	base := loadFixture016Baseline(t)
	doc := fixture016Doc(t)
	groups := fixture016Groups(t)

	// Classification counts come from the single Classify rule, not from a stored total.
	byClass := map[consolidate.Class]int{}
	emptyFix := 0
	for _, f := range doc.Findings {
		cls := consolidate.Classify(f)
		byClass[cls]++
		if cls == consolidate.ClassSupported {
			if fix, _ := f["fix"].(string); strings.TrimSpace(fix) == "" {
				emptyFix++
			}
		}
	}
	checks := []struct {
		name      string
		got, want int
	}{
		{"supported detections", byClass[consolidate.ClassSupported], base.Counts.SupportedDetections},
		{"rejected", byClass[consolidate.ClassRejected], base.Counts.Rejected},
		{"unresolved explicit", byClass[consolidate.ClassUnresolvedExplicit], base.Counts.UnresolvedExplicit},
		{"unresolved failed", byClass[consolidate.ClassUnresolvedFailed], base.Counts.UnresolvedFailed},
		{"established groups", len(groups.Groups), base.Counts.EstablishedGroups},
		{"raw supported on the group record", groups.RawSupported, base.Counts.SupportedDetections},
		{"grouped count", groups.Grouped, base.Counts.EstablishedGroups},
		{"supported findings with an empty recommended fix", emptyFix, base.Counts.FindingsWithEmptyFix},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s = %d, recorded baseline says %d; the fixture drifted from its baseline", c.name, c.got, c.want)
		}
	}
	if n := base.Counts.UnresolvedExplicit + base.Counts.UnresolvedFailed; n != base.Counts.NeedsReviewTotal {
		t.Errorf("baseline is internally inconsistent: %d + %d != needs_review_total %d",
			base.Counts.UnresolvedExplicit, base.Counts.UnresolvedFailed, base.Counts.NeedsReviewTotal)
	}

	// Every supported finding belongs to exactly one group, and no group is empty.
	seen := map[string]int{}
	for _, g := range groups.Groups {
		if len(g.Members) == 0 {
			t.Errorf("group %s has no members", g.ID)
		}
		for _, m := range g.Members {
			seen[m.FindingID]++
		}
	}
	if len(seen) != base.Counts.UniqueGroupMembers {
		t.Errorf("unique group members = %d, want %d", len(seen), base.Counts.UniqueGroupMembers)
	}
	total := 0
	for id, n := range seen {
		total += n
		if n != 1 {
			t.Errorf("finding %s appears in %d groups; membership must be exactly once", id, n)
		}
	}
	if total != base.Counts.GroupMembers {
		t.Errorf("group member rows = %d, want %d", total, base.Counts.GroupMembers)
	}

	// Coverage: the reader-facing figure is completed review, and exposure is separate.
	in := fixture016Input(t)
	if in.Coverage == nil {
		t.Fatal("fixture produced no coverage view")
	}
	if in.Coverage.Completed != base.Coverage.CompletedReview {
		t.Errorf("completed review = %d, want %d", in.Coverage.Completed, base.Coverage.CompletedReview)
	}
	if in.Coverage.Exposed != base.Coverage.SourceExposed {
		t.Errorf("source exposed = %d, want %d", in.Coverage.Exposed, base.Coverage.SourceExposed)
	}
	if in.Coverage.Total != base.Coverage.TotalEntryPoints {
		t.Errorf("total entry points = %d, want %d", in.Coverage.Total, base.Coverage.TotalEntryPoints)
	}
	if in.Coverage.Completed == in.Coverage.Exposed {
		t.Error("the fixture must keep exposure distinct from completed review, or it cannot exercise C-P8")
	}

	// The corpus must keep the same-location case the edge cases rely on: two or more
	// ESTABLISHED groups anchored at one file and line. In this corpus the clearest
	// instance is unsafe pickle deserialization at dispatch_operations.py:61, recorded
	// once under the `deserialization` family and once under the unfamilied `cwe-754`
	// fallback. They describe the same weakness at the same route and must stay separate,
	// so a merge inferred from weakness, title or route would be caught here.
	byAnchor := map[string][]string{}
	for _, g := range groups.Groups {
		if g.Status != consolidate.GroupEstablished {
			continue
		}
		key := g.Anchor.File + ":" + itoa016(g.Anchor.Line)
		byAnchor[key] = append(byAnchor[key], g.Family)
	}
	shared := 0
	for key, fams := range byAnchor {
		if len(fams) > 1 {
			shared++
			if len(fams) != len(uniqueStrings(fams)) {
				t.Errorf("anchor %s has two established groups of the same family (%v); grouping should have merged them", key, fams)
			}
		}
	}
	if shared == 0 {
		t.Error("the corpus must keep at least one source location carrying two separate established groups, or the no-merge edge case is untested")
	}
	unfamilied := 0
	for _, f := range doc.Findings {
		if consolidate.Classify(f) != consolidate.ClassSupported {
			continue
		}
		if fam, _ := f["cwe_family"].(string); strings.TrimSpace(fam) == "" {
			unfamilied++
		}
	}
	if unfamilied == 0 {
		t.Error("the corpus must keep at least one supported finding with no weakness family, or the investigate branch is untested")
	}
}

// Feature 016 (T005): the fixture must carry no operator path, host or prompt record.
func TestFixture016IsSanitized(t *testing.T) {
	dir := fixture016Dir(t)
	for _, name := range []string{
		"report_model.json", "findings.json", consolidate.GroupsFile, "scan_meta.json",
		"review_units.json", "coverage_ledger.json", "verification_metrics.json",
		"verification_sessions.json", "verification_reconciliation.json",
	} {
		raw := readFixtureFile(t, dir, name)
		for _, bad := range []string{"/home/", "/Users/", "192.168."} {
			if strings.Contains(raw, bad) {
				t.Errorf("%s still contains %q after sanitizing", name, bad)
			}
		}
	}
	if fileExistsIn(dir, "prompts.jsonl") {
		t.Error("prompts.jsonl must not be part of the acceptance corpus")
	}
}
