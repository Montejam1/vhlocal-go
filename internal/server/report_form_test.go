package server

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	vhlocal "vhlocal"
)

// T033 (FR-010, SC-002 shipped-asset half): the EMBEDDED viewers consume
// report_model.json first (with the pre-015 fallback note), render the model-driven
// findings index with search/filter/keyboard/anchors and collapsed details, and
// the React source carries the same behaviors. These are SOURCE-STRING checks on
// the shipped assets — not browser verification (operator-run, recorded separately).
//
// Feature 016 (T096): every assertion below is RETAINED unchanged. The strings it checks
// belong to the feature-015 renderers, which still render a report saved before feature 016
// (FR-026, C-C7), so none of them became wrong — the redesign added a second path rather
// than replacing this one. The redesigned surface has its own contract in
// shipped_report_test.go: the projection is read rather than recomputed (T078), exactly one
// of the two paths renders for a given report (T079), and the index stays searchable,
// filterable, keyboard navigable and readable at 375 CSS pixels (T093). The artifact-link,
// deep-link and read-confinement assertions in this file are unchanged and still apply to
// both paths.
func TestShippedReportContract(t *testing.T) {
	web, err := fs.Sub(vhlocal.WebFS, "vhlocal/web")
	if err != nil {
		t.Fatal(err)
	}
	b, err := fs.ReadFile(web, "index.html")
	if err != nil {
		t.Fatal(err)
	}
	src := string(b)
	for name, want := range map[string]string{
		"model fetched first":   "has('report_model.json')",
		"summary from model":    "function reportSummaryHTML(model)",
		"pre-015 fallback note": "counts from findings.json (pre-015 scan)",
		"model-driven index":    "function reportIndexHTML(model, id)",
		"index search":          `id="rq"`,
		"index severity filter": `id="rsev"`,
		"index status filter":   `id="rstatus"`,
		"keyboard rows":         `tabindex="0" role="button" data-anchor=`,
		"keydown handler":       "onkeydown=\"reportRowKey(event",
		"collapsed details":     `<details class="rfind" id="finding-`,
		"evidence as code":      `<figure class="evidence"><figcaption><code>`,
		"fix not provided":      "not provided",
		"evidence none":         "none (not verified)",
		"appendix explicit":     "Unresolved (explicit decision)",
		"appendix failed":       "Unresolved (session failed)",
		"selection remembered":  "vhlocal.report.finding.",
		"link rule":             "function mdHref(",
		"legacy table kept":     "function findingsSectionHTML(fj)",
	} {
		if !strings.Contains(src, want) {
			t.Errorf("shipped index.html lacks %s: %q", name, want)
		}
	}
	for _, name := range []string{"index.classic.html", "index.legacy.html"} {
		cb, err := fs.ReadFile(web, name)
		if err != nil {
			t.Fatal(err)
		}
		for _, want := range []string{"report_model.json", "function reportModelSummaryHTML(", "pre-015 scan", "function mdHref("} {
			if !strings.Contains(string(cb), want) {
				t.Errorf("%s lacks %q", name, want)
			}
		}
	}
	// React sources (built into /app by the operator).
	if rb, err := os.ReadFile(filepath.Join("..", "..", "web-react", "src", "components", "FindingsIndex.tsx")); err == nil {
		for _, want := range []string{`useSearchParams`, `tabIndex={0}`, `role="button"`, `Filtered view — showing`, `none (not verified)`, `"not provided"`, `<figure`, `unresolved_explicit`, `unresolved_failed`} {
			if !strings.Contains(string(rb), want) {
				t.Errorf("web-react FindingsIndex.tsx lacks %q", want)
			}
		}
	}
	if rb, err := os.ReadFile(filepath.Join("..", "..", "web-react", "src", "pages", "Reports.tsx")); err == nil {
		for _, want := range []string{"<FindingsIndex", "<IssuesIndex", "ExecutiveSummary", "PresentationSummary", "pre-015 scan", `base={`} {
			if !strings.Contains(string(rb), want) {
				t.Errorf("web-react Reports.tsx lacks %q", want)
			}
		}
	}
}
