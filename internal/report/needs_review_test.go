package report

import (
	"regexp"
	"strings"
	"testing"
)

// T067 (FR-017, C-C1): a review item carries the affected location when one was recorded, a
// plain explanation of what is unresolved, and a next step. The two kinds are labelled
// distinctly, and an assessment that did not finish says so in those words.
func TestReviewItemsExplainWhatIsUnresolved(t *testing.T) {
	base := loadFixture016Baseline(t)
	in := fixture016Input(t)
	m := BuildModel(in)
	items := m.Presentation.ReviewItems

	if len(items) != base.Counts.NeedsReviewTotal {
		t.Fatalf("review items = %d, records say %d", len(items), base.Counts.NeedsReviewTotal)
	}
	kinds := map[string]int{}
	refs := map[string]bool{}
	for _, it := range items {
		switch it.Kind {
		case ReviewInconclusive, ReviewIncomplete:
			kinds[it.Kind]++
		default:
			t.Errorf("%s: kind %q is neither inconclusive nor incomplete", it.Ref, it.Kind)
		}
		if it.Ref == "" || refs[it.Ref] {
			t.Errorf("review item reference %q is missing or repeated", it.Ref)
		}
		refs[it.Ref] = true
		if strings.TrimSpace(it.WhatIsUnresolved) == "" {
			t.Errorf("%s: does not say what is unresolved", it.Ref)
		}
		if strings.TrimSpace(it.NextStep) == "" {
			t.Errorf("%s: gives the reader no next step", it.Ref)
		}
		if it.Kind == ReviewIncomplete && !strings.Contains(it.WhatIsUnresolved, "Assessment not completed") {
			t.Errorf("%s: an unfinished assessment must read \"Assessment not completed\": %q", it.Ref, it.WhatIsUnresolved)
		}
		// Neither kind may read as a confirmation or as a dismissal. An honest negation —
		// "nothing has been established or refuted" — is the point, so the patterns match
		// affirmative verdicts rather than the words themselves.
		text := it.WhatIsUnresolved + " " + it.NextStep
		for _, re := range []*regexp.Regexp{
			regexp.MustCompile(`(?i)\b(?:is|was|has been) confirmed\b`),
			regexp.MustCompile(`(?i)\bconfirmed (?:vulnerability|as)\b`),
			regexp.MustCompile(`(?i)\bis vulnerable\b`),
			regexp.MustCompile(`(?i)\b(?:is|was) not a vulnerability\b`),
			regexp.MustCompile(`(?i)\b(?:is|was|has been) refuted\b`),
		} {
			if loc := re.FindString(text); loc != "" {
				t.Errorf("%s: an unsettled item reads as settled (%q)", it.Ref, loc)
			}
		}
	}
	if kinds[ReviewInconclusive] != base.Counts.UnresolvedExplicit {
		t.Errorf("inconclusive = %d, records say %d", kinds[ReviewInconclusive], base.Counts.UnresolvedExplicit)
	}
	if kinds[ReviewIncomplete] != base.Counts.UnresolvedFailed {
		t.Errorf("incomplete = %d, records say %d", kinds[ReviewIncomplete], base.Counts.UnresolvedFailed)
	}

	// The locations that were recorded reach the reader.
	withLocation := 0
	for _, it := range items {
		if it.Location != "" {
			withLocation++
		}
	}
	if withLocation == 0 {
		t.Error("no review item carries a location, although the records cite them")
	}

	md := renderMarkdownModel(in, m)
	section := sectionOf(t, md, hdrNeedsRev)
	for _, it := range items {
		if !strings.Contains(section, it.Title) {
			t.Errorf("%s (%q) is missing from the Needs review section", it.Ref, it.Title)
		}
	}
	if !strings.Contains(section, "Assessment not completed") {
		t.Error("the section never states that an assessment did not complete")
	}
	// The two kinds are visibly distinct.
	if !strings.Contains(section, "Inconclusive") {
		t.Error("the section does not label the inconclusive items")
	}
}

// T068 (FR-017, C-C2): a proposed severity is explicitly provisional, and it never enters
// the vulnerability totals, the severity chart or the priority list.
func TestProvisionalSeverityStaysOutOfTotals(t *testing.T) {
	base := loadFixture016Baseline(t)
	in := fixture016Input(t)
	m := BuildModel(in)
	p := m.Presentation

	// The severity chart sums to the issues, with no review item folded in.
	sum := 0
	for _, s := range DisplaySeverities {
		sum += p.Counts.Severity[s]
	}
	if sum != p.Counts.IssuesToFix {
		t.Errorf("severity chart sums to %d but the headline is %d", sum, p.Counts.IssuesToFix)
	}
	if p.Counts.IssuesToFix != base.Counts.EstablishedGroups {
		t.Errorf("issues to fix = %d, records say %d", p.Counts.IssuesToFix, base.Counts.EstablishedGroups)
	}

	// No review item appears in the priority list or among the issues.
	issueRefs := map[string]bool{}
	for _, is := range p.Issues {
		issueRefs[is.Ref] = true
		for _, mem := range is.Members {
			issueRefs[mem.FindingID] = true
		}
	}
	for _, it := range p.ReviewItems {
		if issueRefs[it.Ref] {
			t.Errorf("review item %s is also an issue", it.Ref)
		}
		for _, a := range p.Priority {
			if a.Ref == it.Ref || (it.Title != "" && a.Issue == it.Title) {
				t.Errorf("review item %s reached the priority list", it.Ref)
			}
		}
	}

	// Where a provisional severity is shown, it is labelled as proposed, not established.
	md := renderMarkdownModel(in, m)
	section := sectionOf(t, md, hdrNeedsRev)
	shown := 0
	for _, it := range p.ReviewItems {
		if it.ProvisionalSeverity == "" {
			continue
		}
		shown++
	}
	if shown > 0 {
		if !strings.Contains(section, "proposed, not established") {
			t.Error("a proposed severity is shown without being labelled provisional")
		}
		// And it is never rendered with the bare severity styling used for established
		// issues, which would read as a rating the scan stands behind.
		if regexp.MustCompile(`(?m)^- \*\*(?:Critical|High|Medium|Low)\*\*`).MatchString(section) {
			t.Error("a review item is presented with an established severity heading")
		}
	}

	h := renderHTMLModel(in, m)
	if shown > 0 && !strings.Contains(h, "proposed, not established") {
		t.Error("the html does not label a proposed severity as provisional")
	}
}
