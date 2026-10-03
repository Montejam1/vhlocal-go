package report

import (
	"strings"
	"testing"
)

// T069 (FR-018, C-C3): a dismissed candidate keeps the reason and the decision recorded at
// the time, stays available, and stays out of the default body and the severity charts. The
// report never re-decides a dismissal.
func TestDismissedCandidatesStayAvailableAndOutOfTotals(t *testing.T) {
	base := loadFixture016Baseline(t)
	in := fixture016Input(t)
	m := BuildModel(in)
	p := m.Presentation

	if len(p.Dismissed) != base.Counts.Rejected {
		t.Fatalf("dismissed = %d, records say %d", len(p.Dismissed), base.Counts.Rejected)
	}
	if p.Counts.Dismissed != base.Counts.Rejected {
		t.Errorf("dismissed count = %d, records say %d", p.Counts.Dismissed, base.Counts.Rejected)
	}
	refs := map[string]bool{}
	for _, d := range p.Dismissed {
		if d.Ref == "" || refs[d.Ref] {
			t.Errorf("dismissed reference %q is missing or repeated", d.Ref)
		}
		refs[d.Ref] = true
		if strings.TrimSpace(d.Reason) == "" {
			t.Errorf("%s: the recorded reason was dropped", d.Ref)
		}
		if strings.TrimSpace(d.Decision) == "" {
			t.Errorf("%s: the recorded decision was dropped", d.Ref)
		}
		if strings.TrimSpace(d.Title) == "" {
			t.Errorf("%s: no title", d.Ref)
		}
	}

	// Out of the issue list, the severity chart and the priority list.
	sum := 0
	for _, s := range DisplaySeverities {
		sum += p.Counts.Severity[s]
	}
	if sum != p.Counts.IssuesToFix {
		t.Errorf("severity chart sums to %d, the headline is %d: a dismissal entered the chart", sum, p.Counts.IssuesToFix)
	}
	dismissedTitles := map[string]bool{}
	for _, d := range p.Dismissed {
		dismissedTitles[d.Title] = true
	}
	for _, is := range p.Issues {
		if dismissedTitles[is.Title] && is.DetectionCount == 0 {
			t.Errorf("dismissed candidate %q appears as an issue", is.Title)
		}
	}
	for _, a := range p.Priority {
		if dismissedTitles[a.Issue] {
			t.Errorf("dismissed candidate %q reached the priority list", a.Issue)
		}
	}

	// Available, but after the vulnerability content and the operator section.
	md := renderMarkdownModel(in, m)
	section := sectionOf(t, md, hdrDismissed)
	for _, d := range p.Dismissed {
		if !strings.Contains(section, d.Title) {
			t.Errorf("%s (%q) is not available in the dismissed section", d.Ref, d.Title)
		}
		if !strings.Contains(section, d.Reason) {
			t.Errorf("%s: the recorded reason is not shown", d.Ref)
		}
	}
	if i, j := strings.Index(md, hdrDismissed), strings.Index(md, hdrIssues); i < j {
		t.Error("dismissed candidates appear before the issues to fix")
	}

	// In the HTML the section is on demand rather than part of the reading flow.
	h := renderHTMLModel(in, m)
	if !strings.Contains(h, `<details id="dismissed"`) {
		t.Error("the dismissed section is not an on-demand section in the html")
	}
	// Nothing re-decides the dismissal.
	for _, phrase := range []string{"may actually be", "could still be exploitable", "reconsider as a vulnerability"} {
		if strings.Contains(strings.ToLower(h), phrase) {
			t.Errorf("the report second-guesses a recorded dismissal: %q", phrase)
		}
	}
}
