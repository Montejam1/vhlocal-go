package report

import (
	"regexp"
	"strings"
	"testing"
)

// T081 (FR-024, C-P34): the printed copy carries the summary, the prioritized index and all
// five main sections for every primary issue regardless of the browser's expansion state.
// Evidence excerpts, dismissed candidates and diagnostics are opt-in additions.
func TestPrintCarriesEverySectionRegardlessOfDisclosureState(t *testing.T) {
	in := fixture016Input(t)
	m := BuildModel(in)
	h := renderHTMLModel(in, m)

	printCSS := printBlock(t, h)

	// Disclosure state cannot hide content from print: collapsed sections are forced open
	// and their children are restored to their normal display.
	for _, want := range []string{"details{display:block}", "details>*{display:revert}"} {
		if !strings.Contains(printCSS, want) {
			t.Errorf("the print stylesheet lacks %q, so a collapsed section would print empty", want)
		}
	}
	// Belt and braces: the page also expands everything before printing.
	if !strings.Contains(h, "beforeprint") || !strings.Contains(h, "expandAll") {
		t.Error("the page does not expand its sections before printing")
	}

	// The summary, the index and every issue's five sections are in the markup, not
	// generated on expansion.
	for _, want := range []string{`id="summary"`, `id="priority"`, `id="issues"`, `id="details"`} {
		if !strings.Contains(h, want) {
			t.Errorf("the printed body would lack %s", want)
		}
	}
	for _, is := range m.Presentation.Issues {
		block := issueHTMLBlock(h, strings.ToLower(is.Ref))
		if block == "" {
			t.Errorf("%s has no detail block in the markup", is.Ref)
			continue
		}
		for _, sec := range []string{"What we found", "Why it matters", "Where it is", "How to fix it", "How to check the fix"} {
			if !strings.Contains(block, sec) {
				t.Errorf("%s would print without its %q section", is.Ref, sec)
			}
		}
	}

	// Opt-in additions: diagnostics are excluded from the default print body, and there is
	// a scope that includes them.
	if !strings.Contains(printCSS, "#technical-diagnostics{display:none}") {
		t.Error("the default print body includes the scanner diagnostics")
	}
	if !strings.Contains(h, `value="diagnostics"`) {
		t.Error("there is no print scope that adds the diagnostics")
	}
	// A summary-only scope drops the detail, the review list and the dismissed list.
	for _, want := range []string{"body[data-scope=summary] #details", "body[data-scope=summary] #needs-review", "body[data-scope=summary] #dismissed"} {
		if !strings.Contains(printCSS, want) {
			t.Errorf("the summary print scope does not exclude %q", want)
		}
	}
	// Layout: nothing is clipped, no dark page background, and an issue heading is not
	// orphaned from its body.
	for _, want := range []string{"--bg:#fff", "--fg:#000", "break-inside:avoid", "white-space:pre-wrap"} {
		if !strings.Contains(printCSS, want) {
			t.Errorf("the print stylesheet lacks %q", want)
		}
	}
	if !regexp.MustCompile(`break-(?:after|inside):avoid`).MatchString(printCSS) {
		t.Error("the print stylesheet does not keep an issue heading with its body")
	}
}

// printBlock returns the content of the page's print media query.
func printBlock(t *testing.T, h string) string {
	t.Helper()
	i := strings.Index(h, "@media print{")
	if i < 0 {
		t.Fatal("the page has no print stylesheet")
	}
	rest := h[i:]
	// The block ends at the closing brace that matches the media query's.
	depth := 0
	for j, r := range rest {
		switch r {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return rest[:j+1]
			}
		}
	}
	t.Fatal("the print stylesheet is unterminated")
	return ""
}

// issueHTMLBlock returns the markup of one issue's details element.
func issueHTMLBlock(h, ref string) string {
	i := strings.Index(h, `id="`+ref+`"`)
	if i < 0 {
		return ""
	}
	rest := h[i:]
	if j := strings.Index(rest, "</details>"); j >= 0 {
		return rest[:j]
	}
	return rest
}
