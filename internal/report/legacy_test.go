package report

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// T082 (FR-026, C-C7, C-C8): a report saved before this feature still opens. A model with no
// presentation projection renders as a legacy report, values this feature would have
// computed read as unavailable rather than being back-filled, and the saved evidence and
// classifications are unchanged.
func TestSavedReportWithoutProjectionRendersAsLegacy(t *testing.T) {
	in := fixture016Input(t)
	current := BuildModel(in)

	// A pre-016 model: the projection absent, exactly as an older report_model.json is.
	legacy := current
	legacy.Presentation = nil

	md := renderMarkdownModel(in, legacy)
	h := renderHTMLModel(in, legacy)

	// It renders through the legacy path, with the feature-015 sections.
	for _, want := range []string{"## Executive summary", "## Outcome metrics", "## Findings index", "## Findings"} {
		if !strings.Contains(md, want) {
			t.Errorf("a legacy model must still render %q", want)
		}
	}
	// And NOT as the redesigned document, which would imply figures it never computed.
	for _, bad := range []string{hdrIssues, hdrPriority, hdrDiagnostics} {
		if strings.Contains(md, bad) {
			t.Errorf("a legacy model rendered the redesigned section %q", bad)
		}
	}
	if strings.Contains(h, `id="technical-diagnostics"`) {
		t.Error("a legacy model rendered the redesigned html")
	}

	// Unavailable values are disclosed, not invented.
	if !strings.Contains(md, "not provided") && !strings.Contains(md, "not recorded") {
		t.Error("the legacy document does not disclose its unavailable values")
	}

	// Evidence and classifications are byte-for-byte what the model carried.
	for _, f := range legacy.Findings {
		if f.Classification != "" && !strings.Contains(md, f.Classification) {
			t.Errorf("classification %q of %s was dropped", f.Classification, f.ID)
		}
		for _, e := range f.Evidence {
			if !strings.Contains(md, e.Path) {
				t.Errorf("evidence %s of %s was dropped", e.Path, f.ID)
			}
		}
	}

	// The persisted file for such a report carries no empty projection key, so a reader
	// cannot mistake absence for an empty result.
	dir := t.TempDir()
	if _, err := WriteModel(legacy, dir); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, ModelFile))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), `"presentation"`) {
		t.Error("a legacy model was persisted with a presentation key")
	}
	var reloaded ReportModel
	if err := json.Unmarshal(raw, &reloaded); err != nil {
		t.Fatal(err)
	}
	if reloaded.Presentation != nil {
		t.Error("a legacy model reloaded with a fabricated projection")
	}
}

// T082 (FR-026, C-C8): a saved report with no remediation groups still produces one issue
// per supported finding. Absent grouping is not an error and is not invented.
func TestSavedReportWithoutGroupsStillReportsEveryFinding(t *testing.T) {
	in := fixture016Input(t)
	in.Groups = nil
	m := BuildModel(in)
	p := m.Presentation
	if p == nil {
		t.Fatal("no projection")
	}
	base := loadFixture016Baseline(t)
	if len(p.Issues) != base.Counts.SupportedDetections {
		t.Errorf("with no groups, issues = %d, want one per supported detection (%d)",
			len(p.Issues), base.Counts.SupportedDetections)
	}
	for _, is := range p.Issues {
		if is.GroupID != "" {
			t.Errorf("%s claims group %s although the record carries no groups", is.Ref, is.GroupID)
		}
		if is.GroupingNote != "" {
			t.Errorf("%s records a grouping note although no group was recorded: %q", is.Ref, is.GroupingNote)
		}
		if is.DetectionCount != 1 {
			t.Errorf("%s has %d detections without a group", is.Ref, is.DetectionCount)
		}
	}
	if len(p.GroupingNotes) != 0 {
		t.Errorf("grouping notes were invented for a record with no groups: %v", p.GroupingNotes)
	}
	// The document still renders, with the issues it does have.
	md := renderMarkdownModel(in, m)
	if strings.Count(sectionOf(t, md, hdrDetails), "\n### ") != len(p.Issues) {
		t.Error("the ungrouped document does not render one section per issue")
	}
}
