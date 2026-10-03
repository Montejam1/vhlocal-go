package report

import (
	"regexp"
	"strings"
	"testing"
)

// Markdown section headings of the redesigned document. Tests locate content by these
// rather than by line number, so a wording change inside a section does not break them.
const (
	hdrSummary    = "## Summary"
	hdrPriority   = "## Priority actions"
	hdrIssues     = "## Issues to fix"
	hdrDetails    = "## Issue details"
	hdrNeedsRev   = "## Needs review"
	hdrScanDetail = "## Scan details"
	hdrDismissed  = "## Dismissed candidates"
)

// sectionOf returns the markdown between one heading and the next "## " heading.
func sectionOf(t *testing.T, md, heading string) string {
	t.Helper()
	i := strings.Index(md, heading)
	if i < 0 {
		t.Fatalf("report has no %q section", heading)
	}
	rest := md[i+len(heading):]
	if j := strings.Index(rest, "\n## "); j >= 0 {
		rest = rest[:j]
	}
	return rest
}

// proseWords counts the reader-facing prose of a section, excluding what FR-002
// excludes: table rows, bold label runs, headings and blockquote markers.
var (
	reTableRow  = regexp.MustCompile(`(?m)^\s*\|.*$`)
	reBoldLabel = regexp.MustCompile(`\*\*[^*]+\*\*`)
	reHeading   = regexp.MustCompile(`(?m)^#+ .*$`)
	reAnchor    = regexp.MustCompile(`<a id="[^"]*"></a>`)
)

func proseWords(section string) int {
	s := reTableRow.ReplaceAllString(section, "")
	s = reHeading.ReplaceAllString(s, "")
	s = reAnchor.ReplaceAllString(s, "")
	s = reBoldLabel.ReplaceAllString(s, "")
	s = strings.ReplaceAll(s, "·", " ")
	return len(strings.Fields(s))
}

// T017 (FR-002, C-P3): the opening prose is at most 180 words, counting the risk summary
// and the scope sentence and excluding the title, labels, metric tiles and priority rows.
// The recorded baseline for this corpus is 557 words before the index.
func TestOpeningProseIsBounded(t *testing.T) {
	base := loadFixture016Baseline(t)
	in := fixture016Input(t)
	m := BuildModel(in)
	p := m.Presentation
	if p == nil {
		t.Fatal("no presentation projection")
	}

	// The projection's own count must be the sum of exactly the two prose fields.
	want := len(strings.Fields(p.Opening.RiskSummary)) + len(strings.Fields(p.Opening.ScopeSentence))
	if p.Opening.Words != want {
		t.Errorf("Opening.Words = %d but risk summary plus scope sentence is %d words", p.Opening.Words, want)
	}
	if p.Opening.Words > base.ExpectedAfter.ProseWordsBeforeFindingIndexMax {
		t.Errorf("opening prose is %d words, bound is %d (baseline before this feature: %d)",
			p.Opening.Words, base.ExpectedAfter.ProseWordsBeforeFindingIndexMax, base.Document.ProseWordsBeforeFindingIndex)
	}
	if p.Opening.RiskSummary == "" {
		t.Error("the opening must say something about what was found")
	}

	// Measured independently from the rendered document: everything before the index.
	md := renderMarkdownModel(in, m)
	idx := strings.Index(md, hdrIssues)
	if idx < 0 {
		t.Fatalf("report has no %q section", hdrIssues)
	}
	before := proseWords(md[:idx])
	if before > base.ExpectedAfter.ProseWordsBeforeFindingIndexMax {
		t.Errorf("rendered prose before the index is %d words, bound is %d (baseline: %d)",
			before, base.ExpectedAfter.ProseWordsBeforeFindingIndexMax, base.Document.ProseWordsBeforeFindingIndex)
	}
	if before >= base.Document.ProseWordsBeforeFindingIndex {
		t.Errorf("rendered opening is %d words against a %d-word baseline; it did not get shorter",
			before, base.Document.ProseWordsBeforeFindingIndex)
	}

	// At most five priority rows, and the opening does not restate their titles in prose.
	if len(p.Priority) > MaxLeading {
		t.Errorf("priority rows = %d, want at most %d", len(p.Priority), MaxLeading)
	}
	summary := sectionOf(t, md, hdrSummary)
	for _, row := range p.Priority {
		if row.Issue != "" && strings.Contains(summary, row.Issue) {
			t.Errorf("the opening repeats the priority row title %q in a second narrative list", row.Issue)
		}
	}
}

// T018 (FR-003, C-P4): the opening carries no candidate hash, raw internal status
// identifier, phase troubleshooting, retry advice, token count or turn count.
func TestOpeningExcludesDiagnostics(t *testing.T) {
	in := fixture016Input(t)
	m := BuildModel(in)
	md := renderMarkdownModel(in, m)
	idx := strings.Index(md, hdrIssues)
	if idx < 0 {
		t.Fatalf("report has no %q section", hdrIssues)
	}
	opening := md[:idx]

	forbidden := []struct{ name, pattern string }{
		{"a candidate identifier", `CAND-[0-9a-f]{8}`},
		{"a remediation group identifier", `RG-[0-9a-f]{8}`},
		{"a raw internal status", `\bstatic_reasoning\b|\bunresolved_failed\b|\bunresolved_explicit\b|\bevidence_captured\b`},
		{"a raw execution axis value", `execution (?:complete|partial|incomplete)\b`},
		{"a phase number", `\bphase 2b\b|\bPhase 2b\b|\bphases completed\b`},
		{"retry or recovery advice", `(?i)\bre-?run\b|\brecovery:|--verify-model`},
		{"a token count", `(?i)\b(?:prompt|completion)[_ ]tokens\b`},
		{"a turn count", `(?i)\bturn limit\b|\bmax_turns\b`},
		{"a verification failure class", `(?i)\b(?:tool_envelope|invalid_submission|invalid_tool_args|turn_exhaustion)\b`},
	}
	for _, f := range forbidden {
		re, err := regexp.Compile(f.pattern)
		if err != nil {
			t.Fatalf("bad pattern for %s: %v", f.name, err)
		}
		if loc := re.FindString(opening); loc != "" {
			t.Errorf("the opening contains %s: %q", f.name, loc)
		}
	}
	// The candidate total may appear only where it is labelled as candidates examined.
	if strings.Contains(opening, "64") && !strings.Contains(opening, "candidates examined") {
		t.Error("the opening shows 64 without labelling it as candidates examined")
	}
}
