package report

import (
	"regexp"
	"strings"
	"testing"
)

// T020 (FR-003, FR-007, C-P6, C-P7): the headline count is established defects, the
// severity split sums to it, review items and dismissed candidates are labelled
// separately, detections are labelled as detections, and the candidate total appears only
// where it is labelled as candidates examined.
func TestHeadlineCountsAreTheEstablishedDefects(t *testing.T) {
	base := loadFixture016Baseline(t)
	in := fixture016Input(t)
	m := BuildModel(in)
	c := m.Presentation.Counts

	if c.IssuesToFix != base.Counts.EstablishedGroups {
		t.Errorf("issues to fix = %d, the records establish %d", c.IssuesToFix, base.Counts.EstablishedGroups)
	}
	// Every display severity is present, including the zero rows, so a reader sees the
	// whole scale rather than inferring absence from a missing label.
	sum := 0
	for _, s := range DisplaySeverities {
		got, ok := c.Severity[s]
		if !ok {
			t.Errorf("severity split omits %s", s)
			continue
		}
		if want := base.GroupSeverity[s]; got != want {
			t.Errorf("severity %s = %d, records say %d", s, got, want)
		}
		sum += got
	}
	if sum != c.IssuesToFix {
		t.Errorf("severity split sums to %d but the headline is %d", sum, c.IssuesToFix)
	}
	if len(c.Severity) != len(DisplaySeverities) {
		t.Errorf("severity split has %d keys, want exactly the %d display severities: %v",
			len(c.Severity), len(DisplaySeverities), c.Severity)
	}
	if c.NeedsReview != base.Counts.NeedsReviewTotal {
		t.Errorf("needs review = %d, want %d", c.NeedsReview, base.Counts.NeedsReviewTotal)
	}
	if c.Dismissed != base.Counts.Rejected {
		t.Errorf("dismissed = %d, want %d", c.Dismissed, base.Counts.Rejected)
	}
	if c.Detections != base.Counts.SupportedDetections {
		t.Errorf("detections = %d, want %d", c.Detections, base.Counts.SupportedDetections)
	}
	if c.CandidatesExamined != base.Counts.CandidatesExamined {
		t.Errorf("candidates examined = %d, want %d", c.CandidatesExamined, base.Counts.CandidatesExamined)
	}
	// The three totals are independent quantities, so none may be the sum of others.
	if c.IssuesToFix == base.Counts.EstablishedGroups+base.Counts.NeedsReviewTotal {
		t.Error("needs review was folded into the headline count")
	}
	if c.IssuesToFix == c.Detections {
		t.Errorf("the headline count equals the detection count (%d); a defect cited twice is one issue", c.Detections)
	}
}

// T020 (FR-003, C-P6): the rendered surfaces label each total. A bare number of the wrong
// quantity next to the word "finding" or "vulnerability" is what this feature removes.
func TestRenderedCountsCarryTheirLabels(t *testing.T) {
	base := loadFixture016Baseline(t)
	in := fixture016Input(t)
	m := BuildModel(in)
	bodies := map[string]string{
		"markdown":        renderMarkdownModel(in, m),
		"standalone html": renderHTMLModel(in, m),
	}
	cand := itoa016(base.Counts.CandidatesExamined)
	det := itoa016(base.Counts.SupportedDetections)

	// A candidate total presented as findings or vulnerabilities, in either order.
	candAsFinding := regexp.MustCompile(`(?i)\b` + cand + `\s+(?:finding|vulnerabilit|issue|defect)`)
	findingAsCand := regexp.MustCompile(`(?i)(?:finding|vulnerabilit|issue|defect)[a-z]*\s*(?:\(s\))?\s*[:=]?\s*\b` + cand + `\b`)
	detAsIssue := regexp.MustCompile(`(?i)\b` + det + `\s+(?:vulnerabilit|issues to fix|defect)`)

	for name, body := range bodies {
		if loc := candAsFinding.FindString(body); loc != "" {
			t.Errorf("%s presents the candidate total as findings: %q", name, loc)
		}
		if loc := findingAsCand.FindString(body); loc != "" {
			t.Errorf("%s labels the candidate total as findings: %q", name, loc)
		}
		if loc := detAsIssue.FindString(body); loc != "" {
			t.Errorf("%s presents the detection total as vulnerabilities: %q", name, loc)
		}
		// Each total that is shown is shown with its own words.
		for _, want := range []string{"Issues to fix", "Needs review", "Dismissed", "candidates examined", "detections"} {
			if !strings.Contains(body, want) && !strings.Contains(strings.ToLower(body), strings.ToLower(want)) {
				t.Errorf("%s never labels %q", name, want)
			}
		}
		// The headline figure is present as the count of issues to fix.
		if !strings.Contains(body, itoa016(base.Counts.EstablishedGroups)) {
			t.Errorf("%s does not state the %d issues to fix", name, base.Counts.EstablishedGroups)
		}
	}
}
