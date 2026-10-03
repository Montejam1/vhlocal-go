package report

import (
	"encoding/json"
	"strings"
	"testing"

	"vhlocal/internal/consolidate"
)

// T057 (C-B12, FR-020): the model carries groups; index rows carry group id and
// role, primaries first with occurrences beneath; the index states raw vs grouped
// counts; group anchors exist in Markdown and HTML; one leading action per group.
func TestGroupsInReportSurfaces(t *testing.T) {
	in := replayInput(t)
	var findings []consolidate.Finding
	b, _ := json.Marshal(in.Doc.Findings)
	if err := json.Unmarshal(b, &findings); err != nil {
		t.Fatal(err)
	}
	cg := consolidate.BuildGroups(findings, in.Repo)
	if cg.Grouped == 0 || cg.Grouped >= cg.RawSupported {
		t.Fatalf("fixture must reduce: raw=%d grouped=%d", cg.RawSupported, cg.Grouped)
	}
	in.Groups = GroupsFromConsolidate(cg)
	m := BuildModel(in)
	if m.Counts.RemediationGroups != cg.Grouped || m.Counts.Supported != cg.RawSupported {
		t.Errorf("counts = %+v", m.Counts)
	}
	// Every index row has a group and a role; a group's rows are contiguous with the
	// primary first.
	seenGroup := map[string]bool{}
	prev := ""
	for _, row := range m.Index {
		if row.GroupID == "" || (row.Role != "primary" && row.Role != "occurrence") {
			t.Fatalf("row %+v lacks group/role", row)
		}
		if row.GroupID != prev {
			if seenGroup[row.GroupID] {
				t.Errorf("group %s rows are not contiguous", row.GroupID)
			}
			if row.Role != "primary" {
				t.Errorf("group %s does not start with its primary: %+v", row.GroupID, row)
			}
			seenGroup[row.GroupID] = true
		}
		prev = row.GroupID
	}
	if len(seenGroup) != cg.Grouped {
		t.Errorf("index covers %d groups, want %d", len(seenGroup), cg.Grouped)
	}
	// Leading issues: one per group (no two leading rows share a group).
	lead := map[string]bool{}
	for _, l := range m.Summary.Leading {
		var gid string
		for _, row := range m.Index {
			if row.Anchor == l.Ref {
				gid = row.GroupID
			}
		}
		if lead[gid] {
			t.Errorf("two leading actions for group %s", gid)
		}
		lead[gid] = true
	}

	// Feature 016 (T036): the raw-vs-grouped sentence, the ↳ occurrence marks and the
	// "Supported findings (raw)" metric label are the legacy document's way of showing
	// grouping. The new document reports one section per group and states the same two
	// counts in Scan details; its grouping behaviour is asserted in US3. Every assertion
	// below is unchanged and read from the legacy path, which still renders pre-016 models.
	md := renderMarkdownLegacy(in, m)
	h := renderHTMLLegacy(in, m)
	rawGrouped := "supported finding(s) (raw) in " + itoa(cg.Grouped) + " remediation group(s)"
	if !strings.Contains(md, rawGrouped) {
		t.Errorf("markdown index lacks raw vs grouped statement %q", rawGrouped)
	}
	if !strings.Contains(h, rawGrouped) {
		t.Error("html index lacks raw vs grouped statement")
	}
	var multi Group
	for _, g := range m.Groups {
		if len(g.Members) > 1 {
			multi = g
			break
		}
	}
	if multi.ID == "" {
		t.Fatal("no multi-member group")
	}
	if !strings.Contains(md, `<a id="group-`+multi.ID+`"></a>`) {
		t.Errorf("markdown lacks the group anchor for %s", multi.ID)
	}
	if !strings.Contains(h, `id="group-`+multi.ID+`"`) {
		t.Errorf("html lacks the group anchor for %s", multi.ID)
	}
	if !strings.Contains(h, `data-role="occurrence"`) || !strings.Contains(md, "↳") {
		t.Error("occurrence rows must be marked beneath their primary")
	}
	// Outcome metrics state both counts.
	if !strings.Contains(md, "**Supported findings (raw)**: "+itoa(cg.RawSupported)) || !strings.Contains(md, "**Remediation groups (grouped)**: "+itoa(cg.Grouped)) {
		t.Error("outcome metrics must state raw and grouped counts")
	}
	// The model JSON is what the UIs read: groups with members and roles.
	mb, _ := json.Marshal(m)
	if !strings.Contains(string(mb), `"role":"primary"`) || !strings.Contains(string(mb), `"group_size"`) {
		t.Error("model JSON lacks member roles / group size")
	}
}

func itoa(n int) string {
	b, _ := json.Marshal(n)
	return string(b)
}
