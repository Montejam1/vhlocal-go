package report

import (
	"regexp"
	"strings"
	"testing"
)

// T044 (FR-016, C-R8): the suggested checks are relevant to the issue, and no check is
// described as having been executed or passed. The scan never ran anything.
func TestSuggestedChecksAreRelevantAndNotClaimedExecuted(t *testing.T) {
	in := fixture016Input(t)
	m := BuildModel(in)
	p := m.Presentation

	executed := []*regexp.Regexp{
		regexp.MustCompile(`(?i)\b(?:check|test)s? (?:passed|succeeded|were run|was run|ran)\b`),
		regexp.MustCompile(`(?i)\bverified by (?:running|execution)\b`),
		regexp.MustCompile(`(?i)\bwe (?:ran|executed|confirmed by running)\b`),
		regexp.MustCompile(`(?i)\b(?:all|every) checks? (?:pass|passed)\b`),
	}
	withChecks := 0
	for _, is := range p.Issues {
		if len(is.HowToCheckTheFix) == 0 {
			t.Errorf("%s: no suggested check, so the reader cannot tell whether a fix worked", is.Ref)
			continue
		}
		withChecks++
		for _, chk := range is.HowToCheckTheFix {
			for _, re := range executed {
				if loc := re.FindString(chk); loc != "" {
					t.Errorf("%s: a suggested check claims execution (%q): %q", is.Ref, loc, chk)
				}
			}
			// A check must be an instruction, not a verdict.
			if strings.HasPrefix(strings.ToLower(strings.TrimSpace(chk)), "no ") {
				t.Errorf("%s: a suggested check reads as a verdict: %q", is.Ref, chk)
			}
		}
	}
	if withChecks == 0 {
		t.Fatal("no issue carried suggested checks")
	}

	// Relevance: an issue whose weakness family is known uses that family's checks, so a
	// path-traversal issue is never handed a deserialization check.
	for _, is := range p.Issues {
		if is.Family == "" {
			continue
		}
		joined := strings.ToLower(strings.Join(is.HowToCheckTheFix, " "))
		switch is.Family {
		case "path-traversal":
			if strings.Contains(joined, "deserializ") || strings.Contains(joined, "pickle") {
				t.Errorf("%s (path traversal) carries a deserialization check: %s", is.Ref, joined)
			}
		case "deserialization":
			if strings.Contains(joined, "traversal sequence") {
				t.Errorf("%s (deserialization) carries a path-traversal check: %s", is.Ref, joined)
			}
		}
	}

	// The rendered document carries the checks as suggestions under their own heading.
	md := renderMarkdownModel(in, m)
	if !strings.Contains(md, "**How to check the fix**") {
		t.Error("the document has no 'How to check the fix' section")
	}
	for _, re := range executed {
		if loc := re.FindString(md); loc != "" {
			t.Errorf("the rendered document claims a check was executed: %q", loc)
		}
	}
}
