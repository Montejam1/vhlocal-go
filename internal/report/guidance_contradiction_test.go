package report

import (
	"strings"
	"testing"

	"vhlocal/internal/guidance"
)

// T045 (FR-014, C-R9): the spec's edge case "a recorded recommendation inappropriate for
// the observed weakness".
//
// FR-014 uses a recorded recommendation when it is APPLICABLE. A recorded fix that only
// encodes input does not address a deserialization defect, so it is not applicable: the
// family mechanism is used instead, the divergence is disclosed, and the recorded text is
// neither presented as the mechanism fix nor silently discarded.
func TestRecordedFixThatMissesTheMechanismIsDisclosedNotUsed(t *testing.T) {
	const recorded = "HTML-encode the user-supplied value before use."
	in := fixture016Input(t)

	// Find a supported deserialization finding in the frozen corpus and give it a recorded
	// fix that addresses a different mechanism.
	target := ""
	for _, f := range in.Doc.Findings {
		if !isSupported(f) {
			continue
		}
		if !strings.Contains(strings.ToLower(str(f["cwe"])+" "+str(f["cwe_family"])), "502") &&
			str(f["cwe_family"]) != "deserialization" {
			continue
		}
		f["fix"] = recorded
		target = str(f["id"])
		break
	}
	if target == "" {
		t.Fatal("fixture precondition: no supported deserialization finding")
	}

	m := BuildModel(in)
	var issue *PrimaryIssue
	for i := range m.Presentation.Issues {
		for _, mem := range m.Presentation.Issues[i].Members {
			if mem.FindingID == target {
				issue = &m.Presentation.Issues[i]
			}
		}
	}
	if issue == nil {
		t.Fatalf("finding %s is in no primary issue", target)
	}
	r := issue.HowToFixIt

	// Not used as the fix.
	if r.Provenance == guidance.ProvRecorded {
		t.Error("an inapplicable recorded recommendation was used as the recommendation")
	}
	for _, step := range r.Steps {
		if strings.Contains(step, recorded) {
			t.Errorf("the inapplicable text is presented as a remediation step: %q", step)
		}
	}
	// The mechanism fix is used instead.
	if !strings.Contains(strings.ToLower(strings.Join(r.Steps, " ")), "deserializ") {
		t.Errorf("the deserialization mechanism fix was not used: %v", r.Steps)
	}
	// The divergence is disclosed, and the recorded text is kept.
	if !strings.Contains(strings.ToLower(r.Label), "does not address") {
		t.Errorf("the divergence is not disclosed to the reader: %q", r.Label)
	}
	if !strings.Contains(r.RecordedNote, recorded) {
		t.Errorf("the recorded recommendation was discarded rather than kept: %q", r.RecordedNote)
	}

	// And it reaches the reader on both surfaces, labelled.
	for name, body := range map[string]string{
		"markdown":        renderMarkdownModel(in, m),
		"standalone html": renderHTMLModel(in, m),
	} {
		if !strings.Contains(body, recorded) {
			t.Errorf("%s drops the recorded recommendation entirely", name)
		}
		if !strings.Contains(body, "does not address") {
			t.Errorf("%s does not tell the reader why the recorded text was not used", name)
		}
	}
}
