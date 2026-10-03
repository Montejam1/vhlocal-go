package report

import (
	"strings"
	"testing"
)

// T011 (FR-007, FR-008, C-P11): every supported finding is accounted for in exactly one
// primary issue, and the frozen corpus yields 34 issues over 49 detections.
func TestPrimaryIssueAccountingExactlyOnce(t *testing.T) {
	base := loadFixture016Baseline(t)
	in := fixture016Input(t)
	issues, counts := BuildPrimaryIssues(in)

	if len(issues) != base.Counts.EstablishedGroups {
		t.Errorf("primary issues = %d, want %d", len(issues), base.Counts.EstablishedGroups)
	}
	detections, seen := 0, map[string]int{}
	for _, p := range issues {
		if p.DetectionCount != len(p.Members) {
			t.Errorf("%s: detection_count %d disagrees with %d members", p.Ref, p.DetectionCount, len(p.Members))
		}
		detections += p.DetectionCount
		primaries := 0
		for _, m := range p.Members {
			seen[m.FindingID]++
			if m.Role == "primary" {
				primaries++
			}
		}
		if primaries != 1 {
			t.Errorf("%s has %d primary members, want exactly 1", p.Ref, primaries)
		}
		if p.Ref == "" || p.Title == "" {
			t.Errorf("issue with no reference or title: %+v", p.Ref)
		}
	}
	if detections != base.Counts.SupportedDetections {
		t.Errorf("detections across issues = %d, want %d", detections, base.Counts.SupportedDetections)
	}
	if len(seen) != base.Counts.SupportedDetections {
		t.Errorf("distinct findings in issues = %d, want %d", len(seen), base.Counts.SupportedDetections)
	}
	for id, n := range seen {
		if n != 1 {
			t.Errorf("finding %s appears in %d primary issues; must be exactly one", id, n)
		}
	}
	// Severity counts are over ISSUES, one each, and match the recorded distribution.
	total := 0
	for _, sev := range DisplaySeverities {
		total += counts[sev]
		if counts[sev] != base.GroupSeverity[sev] {
			t.Errorf("severity %s = %d, baseline records %d", sev, counts[sev], base.GroupSeverity[sev])
		}
	}
	if total != len(issues) {
		t.Errorf("severity counts sum to %d, want one per issue (%d)", total, len(issues))
	}
	// References are unique and stable across rebuilds.
	refs := map[string]bool{}
	for _, p := range issues {
		if refs[p.Ref] {
			t.Errorf("duplicate issue reference %s", p.Ref)
		}
		refs[p.Ref] = true
	}
	again, _ := BuildPrimaryIssues(fixture016Input(t))
	if len(again) != len(issues) {
		t.Fatalf("rebuild produced %d issues, want %d", len(again), len(issues))
	}
	for i := range issues {
		if again[i].Ref != issues[i].Ref || firstMemberID(again[i]) != firstMemberID(issues[i]) {
			t.Errorf("issue order is not stable at %d: %s/%s vs %s/%s",
				i, again[i].Ref, firstMemberID(again[i]), issues[i].Ref, firstMemberID(issues[i]))
		}
	}
}

// T011 (C-P12): no merge is inferred from a matching weakness, title or route. The
// corpus has two established groups at one location; they stay two issues.
func TestPrimaryIssuesDoNotMergeDistinctGroups(t *testing.T) {
	in := fixture016Input(t)
	issues, _ := BuildPrimaryIssues(in)

	byLocation := map[string][]string{}
	byEntryPoint := map[string][]string{}
	for _, p := range issues {
		for _, l := range p.Locations {
			if l.Available {
				byLocation[l.File+":"+l.Lines] = append(byLocation[l.File+":"+l.Lines], p.Ref)
			}
		}
		for _, ep := range p.EntryPoints {
			byEntryPoint[ep] = append(byEntryPoint[ep], p.Ref)
		}
	}
	sharedLoc, sharedEP := 0, 0
	for _, refs := range byLocation {
		if len(refs) > 1 {
			sharedLoc++
		}
	}
	for _, refs := range byEntryPoint {
		if len(refs) > 1 {
			sharedEP++
		}
	}
	if sharedLoc == 0 && sharedEP == 0 {
		t.Error("the corpus should still contain separate issues sharing a location or route; a merge may have been inferred")
	}
	// Every recorded group id appears at most once across the issues.
	groupSeen := map[string]int{}
	for _, p := range issues {
		if p.GroupID != "" {
			groupSeen[p.GroupID]++
		}
	}
	for id, n := range groupSeen {
		if n != 1 {
			t.Errorf("group %s backs %d issues, want 1", id, n)
		}
	}
}

// T011 (FR-013, C-P15): repeated citations of one location collapse to one affected
// location carrying the citation count, so detections never inflate the location count.
func TestAffectedLocationsCollapseRepeatedCitations(t *testing.T) {
	in := fixture016Input(t)
	issues, _ := BuildPrimaryIssues(in)

	collapsed := 0
	for _, p := range issues {
		citations := 0
		for _, l := range p.Locations {
			citations += l.CitationCount
			if l.CitationCount < 1 {
				t.Errorf("%s: location %s has citation_count %d", p.Ref, l.File, l.CitationCount)
			}
			if l.CitationCount > 1 {
				collapsed++
			}
			if l.Available && l.File == "" {
				t.Errorf("%s: an available location must name a file", p.Ref)
			}
			if !l.Available && l.Lines != "" {
				t.Errorf("%s: an unavailable location must not claim line numbers", p.Ref)
			}
		}
		if citations != p.DetectionCount {
			t.Errorf("%s: citations across locations = %d, want one per detection (%d)", p.Ref, citations, p.DetectionCount)
		}
		if len(p.Locations) > p.DetectionCount {
			t.Errorf("%s: %d locations from %d detections; locations were inflated", p.Ref, len(p.Locations), p.DetectionCount)
		}
	}
	if collapsed == 0 {
		t.Error("no location collapsed in a corpus with multi-detection groups; dedup may not be running")
	}
}

// T011 (FR-010, C-P21): at most five priority rows, each a different issue, most serious
// first, and never "fix not provided" as the action.
func TestPriorityActionsAreBoundedAndDistinct(t *testing.T) {
	in := fixture016Input(t)
	issues, _ := BuildPrimaryIssues(in)
	rows := BuildPriorityActions(issues, 5)

	if len(rows) != 5 {
		t.Fatalf("priority rows = %d, want 5 for this corpus", len(rows))
	}
	seen := map[string]bool{}
	last := -1
	for _, r := range rows {
		if seen[r.Ref] {
			t.Errorf("priority list repeats issue %s", r.Ref)
		}
		seen[r.Ref] = true
		if rank := SeverityRankOf(r.Severity); rank < last {
			t.Errorf("priority rows are not in severity order at %s", r.Ref)
		} else {
			last = rank
		}
		if r.Issue == "" || r.AffectedArea == "" || r.Action == "" {
			t.Errorf("priority row %s is missing a field: %+v", r.Ref, r)
		}
		if strings.Contains(strings.ToLower(r.Action), "fix not provided") {
			t.Errorf("priority row %s uses the forbidden placeholder action", r.Ref)
		}
	}
	// The bound is respected even when asked for more than exist.
	if n := len(BuildPriorityActions(issues[:2], 5)); n != 2 {
		t.Errorf("asked for 5 from 2 issues, got %d", n)
	}
}
