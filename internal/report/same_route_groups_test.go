package report

import (
	"strings"
	"testing"
)

// T056 (spec Edge Cases, C-P12): the fixture records two established groups that both
// describe unsafe pickle deserialization at one location in one route — one classified
// CWE-502, the other CWE-754. They stay two primary issues.
//
// This is deliberately the uncomfortable case. A human reading both would probably call
// them one defect, but the records establish two groups and nothing in the report may infer
// the merge from a matching title, weakness or route. What the report owes the reader
// instead is the fact that they sit at the same location, so the merge can be made by a
// person who can verify it.
func TestTwoEstablishedGroupsAtOneRouteStaySeparate(t *testing.T) {
	const (
		anchorFile = "backend/app/dispatch_operations.py"
		deserGroup = "RG-a9c1ac10a8918ea4"
		otherGroup = "RG-4b04247718975ff3"
	)
	in := fixture016Input(t)

	// Precondition: both groups are recorded, established, and at the same anchor.
	found := map[string]Group{}
	for _, g := range in.Groups {
		if g.ID == deserGroup || g.ID == otherGroup {
			found[g.ID] = g
		}
	}
	if len(found) != 2 {
		t.Fatalf("fixture precondition: expected both groups, found %d", len(found))
	}
	for id, g := range found {
		if !groupIsEstablished(g) {
			t.Fatalf("fixture precondition: group %s is not established (%q)", id, g.Status)
		}
		if !strings.HasPrefix(g.Anchor, anchorFile) {
			t.Fatalf("fixture precondition: group %s anchor is %q", id, g.Anchor)
		}
	}

	m := BuildModel(in)
	var deser, other *PrimaryIssue
	for i := range m.Presentation.Issues {
		switch m.Presentation.Issues[i].GroupID {
		case deserGroup:
			deser = &m.Presentation.Issues[i]
		case otherGroup:
			other = &m.Presentation.Issues[i]
		}
	}
	if deser == nil || other == nil {
		t.Fatalf("the two groups did not both become primary issues: deser=%v other=%v", deser != nil, other != nil)
	}
	if deser.Ref == other.Ref {
		t.Fatal("the two groups collapsed into one issue")
	}
	// Their detections are disjoint: neither issue claims the other's findings.
	ids := map[string]bool{}
	for _, mem := range deser.Members {
		ids[mem.FindingID] = true
	}
	for _, mem := range other.Members {
		if ids[mem.FindingID] {
			t.Errorf("detection %s is claimed by both issues", mem.FindingID)
		}
	}

	// The reader can see they are in the same file, so a person can judge the merge.
	sameFile := false
	for _, a := range deser.Locations {
		for _, b := range other.Locations {
			if a.File == b.File {
				sameFile = true
			}
		}
	}
	if !sameFile {
		t.Error("the two issues do not show a shared file, so a reader cannot see they may be one defect")
	}
	md := renderMarkdownModel(in, m)
	if n := strings.Count(md, `<a id="group-`+deserGroup+`"></a>`); n != 1 {
		t.Errorf("group %s anchor appears %d times, want 1", deserGroup, n)
	}
	if n := strings.Count(md, `<a id="group-`+otherGroup+`"></a>`); n != 1 {
		t.Errorf("group %s anchor appears %d times, want 1", otherGroup, n)
	}
}
