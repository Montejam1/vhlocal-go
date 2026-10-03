package report

import (
	"regexp"
	"strings"
	"testing"
)

// T019 (FR-004, C-P8, C-P9): the three independent status facts appear together once in
// plain language; coverage reads the COMPLETED figure over its denominator; the exposure
// axis is never presented as reviewed; unknown coverage stays unknown.
func TestScopeNoteShowsThreeFactsOnce(t *testing.T) {
	base := loadFixture016Baseline(t)
	in := fixture016Input(t)
	m := BuildModel(in)
	md := renderMarkdownModel(in, m)
	h := renderHTMLModel(in, m)

	for name, body := range map[string]string{"markdown": md, "standalone html": h} {
		// The completed figure over its denominator, in plain words.
		if !strings.Contains(body, "40 of 100") {
			t.Errorf("%s does not state coverage as 40 of 100 completed", name)
		}
		// 90 is the exposure axis. Wherever it is shown as a coverage figure it must be
		// labelled as exposure; a bare "90" elsewhere (a line number, a hash) is not a
		// coverage claim, so the check targets the shapes that read as coverage.
		for _, re := range coverageShapes(base.Coverage.SourceExposed, base.Coverage.TotalEntryPoints) {
			for _, loc := range re.FindAllStringIndex(body, -1) {
				window := body[maxInt(0, loc[0]-200):minInt(len(body), loc[1]+120)]
				if !strings.Contains(strings.ToLower(window), "expos") {
					t.Errorf("%s presents the exposed count as coverage without labelling it: %q",
						name, strings.TrimSpace(body[loc[0]:loc[1]]))
				}
			}
		}
		// Execution and method in plain language, not raw axis values.
		if !strings.Contains(body, "Incomplete") {
			t.Errorf("%s does not state the execution status in plain language", name)
		}
		if !strings.Contains(body, "Source-code analysis") {
			t.Errorf("%s does not state the assessment method in plain language", name)
		}
		// Entry points get a plain explanation.
		if !strings.Contains(body, "accepts input") {
			t.Errorf("%s does not explain what an entry point is", name)
		}
	}

	// The scope facts are stated once in the opening, not repeated per issue.
	if n := strings.Count(md, "Review scope:"); n != 1 {
		t.Errorf("the scope line appears %d times in the markdown, want exactly once", n)
	}
	// The projection keeps the axes separate and matches the records.
	sc := m.Presentation.Scope
	if sc.CoverageComplete != base.Coverage.CompletedReview || sc.CoverageExposed != base.Coverage.SourceExposed {
		t.Errorf("scope note = %d completed / %d exposed, records say %d / %d",
			sc.CoverageComplete, sc.CoverageExposed, base.Coverage.CompletedReview, base.Coverage.SourceExposed)
	}
	if sc.GapSentence == "" {
		t.Error("a 60-entry-point gap is material and needs a sentence")
	}
}

// T019 (FR-004): with no recorded coverage denominator, coverage reads unknown and is
// never filled in from the discovered, assigned or attempted counts.
func TestScopeNoteKeepsUnknownCoverageUnknown(t *testing.T) {
	in := fixture016Input(t)
	in.Coverage = nil // a run whose review-unit record carries no coverage
	m := BuildModel(in)
	sc := m.Presentation.Scope
	if sc.CoverageKnown {
		t.Error("coverage must read as unknown when the record has no denominator")
	}
	if sc.CoverageTotal != 0 || sc.CoverageComplete != 0 {
		t.Errorf("unknown coverage must not invent numbers: %+v", sc)
	}
	// The reader-facing figure is what FR-004 governs. Scan details may still carry the
	// recorded operator diagnostics, including a review-unit tally the run itself wrote;
	// what must not happen is the opening presenting a coverage figure it does not have.
	body := renderMarkdownModel(in, m)
	idx := strings.Index(body, hdrIssues)
	if idx < 0 {
		t.Fatalf("report has no %q section", hdrIssues)
	}
	opening := body[:idx]
	if !strings.Contains(strings.ToLower(opening), "not recorded") && !strings.Contains(strings.ToLower(opening), "unknown") {
		t.Error("the opening must say coverage is unknown rather than omitting the fact")
	}
	if strings.Contains(opening, "of 100 entry points") || strings.Contains(opening, "40 of 100") {
		t.Error("the opening presented a coverage figure although the coverage record carries none")
	}
}

// coverageShapes are the renderings that read as a coverage figure for n out of total.
func coverageShapes(n, total int) []*regexp.Regexp {
	s, tot := itoa016(n), itoa016(total)
	return []*regexp.Regexp{
		regexp.MustCompile(`\b` + s + ` of ` + tot + `\b`),
		regexp.MustCompile(`\b` + s + `\s*/\s*` + tot + `\b`),
		regexp.MustCompile(`(?i)\b` + s + ` (?:entry points?|routes?|units?) (?:were |was )?(?:reviewed|assessed|covered)`),
		regexp.MustCompile(`(?i)\b(?:reviewed|assessed|covered)[:\s]+` + s + `\b`),
	}
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
