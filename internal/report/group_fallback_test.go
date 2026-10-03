package report

import (
	"strings"
	"testing"
)

// T057 (FR-008, C-P12): a group the records do not establish, or one whose members are
// already reported elsewhere, falls back to separate supported findings — and the reason is
// recorded in Scan details rather than the group silently disappearing.
func TestSuggestedGroupFallsBackWithTheReasonRecorded(t *testing.T) {
	in := corpusInput([]map[string]any{
		corpusFinding("C1", "Unsafe pickle", "CWE-502", "deserialization", "High", "a.py:10", "POST /a", "supported"),
		corpusFinding("C2", "Unsafe pickle elsewhere", "CWE-502", "deserialization", "High", "a.py:40", "POST /a", "supported"),
	}, []Group{corpusGroup("RG-sugg", "deserialization", "suggested", "C1", "C2")})
	m := BuildModel(in)
	p := m.Presentation

	if len(p.Issues) != 2 {
		t.Fatalf("issues = %d, want 2 (a suggested group must not merge)", len(p.Issues))
	}
	// Each finding carries the reason it is reported on its own.
	for _, is := range p.Issues {
		if is.GroupID != "" {
			t.Errorf("%s claims group %s although that group is only suggested", is.Ref, is.GroupID)
		}
		if !strings.Contains(is.GroupingNote, "RG-sugg") {
			t.Errorf("%s does not record why it is reported separately: %q", is.Ref, is.GroupingNote)
		}
	}
	// And Scan details says what became of the recorded group.
	if len(p.GroupingNotes) == 0 {
		t.Fatal("no grouping note was recorded for the unused group")
	}
	md := renderMarkdownModel(in, m)
	scan := sectionOf(t, md, hdrScanDetail)
	if !strings.Contains(scan, "RG-sugg") {
		t.Errorf("Scan details does not record what became of RG-sugg:\n%s", scan)
	}
	if !strings.Contains(scan, "suggested") {
		t.Error("Scan details does not state the recorded status that disqualified the group")
	}
	// The reason belongs in the operator section, not in the vulnerability list.
	issues := sectionOf(t, md, hdrIssues)
	if strings.Contains(issues, "RG-sugg") {
		t.Error("the index table carries a grouping diagnostic")
	}
}

// T057: a group whose every member is already reported under another group contributes no
// second issue, and that too is recorded rather than silently dropped.
func TestConflictingGroupIsRecordedNotSilentlyDropped(t *testing.T) {
	in := corpusInput([]map[string]any{
		corpusFinding("C1", "Unsafe pickle", "CWE-502", "deserialization", "High", "a.py:10", "POST /a", "supported"),
		corpusFinding("C2", "Unsafe pickle again", "CWE-502", "deserialization", "High", "a.py:10", "POST /a", "supported"),
	}, []Group{
		corpusGroup("RG-first", "deserialization", "established", "C1", "C2"),
		corpusGroup("RG-second", "deserialization", "established", "C2"),
	})
	m := BuildModel(in)
	p := m.Presentation
	if len(p.Issues) != 1 {
		t.Fatalf("issues = %d, want 1", len(p.Issues))
	}
	// C2 is counted exactly once, under the first group that claimed it.
	count := 0
	for _, is := range p.Issues {
		for _, mem := range is.Members {
			if mem.FindingID == "C2" {
				count++
			}
		}
	}
	if count != 1 {
		t.Errorf("C2 appears in %d issues, want exactly 1", count)
	}
	md := renderMarkdownModel(in, m)
	scan := sectionOf(t, md, hdrScanDetail)
	if !strings.Contains(scan, "RG-second") {
		t.Errorf("Scan details does not record what became of the conflicting group:\n%s", scan)
	}
}

// T057: a group with no established status at all — a record written before grouping had a
// status field — is treated as not established rather than assumed good.
func TestGroupWithNoStatusIsNotTreatedAsEstablished(t *testing.T) {
	in := corpusInput([]map[string]any{
		corpusFinding("C1", "Unsafe pickle", "CWE-502", "deserialization", "High", "a.py:10", "POST /a", "supported"),
		corpusFinding("C2", "Unsafe pickle elsewhere", "CWE-502", "deserialization", "High", "a.py:40", "POST /a", "supported"),
	}, []Group{corpusGroup("RG-nostatus", "deserialization", "", "C1", "C2")})
	m := BuildModel(in)
	if n := len(m.Presentation.Issues); n != 2 {
		t.Errorf("issues = %d, want 2: a group with no recorded status must not merge", n)
	}
	md := renderMarkdownModel(in, m)
	if !strings.Contains(sectionOf(t, md, hdrScanDetail), "RG-nostatus") {
		t.Error("Scan details does not record the unused group with no status")
	}
}
