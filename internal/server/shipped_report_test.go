package server

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	vhlocal "vhlocal"
)

// shippedWeb reads one shipped viewer from the embedded assets.
func shippedWeb(t *testing.T, name string) string {
	t.Helper()
	web, err := fs.Sub(vhlocal.WebFS, "vhlocal/web")
	if err != nil {
		t.Fatal(err)
	}
	b, err := fs.ReadFile(web, name)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// T078 (FR-021, C-P27): the three shipped viewers read the presentation projection and do
// not recompute grouping, severity, counts or guidance.
//
// These are SOURCE-STRING checks on the shipped assets, not browser verification: the
// browser pass is operator-run and recorded separately.
func TestShippedViewersReadThePresentationProjection(t *testing.T) {
	pages := map[string][]struct{ what, want string }{
		"index.html": {
			{"a presentation guard", "model.presentation"},
			{"a presentation summary renderer", "function reportPresentationSummaryHTML("},
			{"a presentation index renderer", "function reportPresentationIndexHTML("},
			{"the bounded opening from the projection", "p.opening"},
			{"the scope note from the projection", "p.scope"},
			{"the issue list from the projection", "p.issues"},
			{"the counts from the projection", "p.counts"},
			{"the counts bound to the projection", "c = p.counts"},
			{"the mapped severity read from those counts", "c.severity"},
			{"the resolved guidance from the projection", "how_to_fix_it"},
			{"the five reader sections", "How to check the fix"},
			{"issues to fix as the headline", "Issues to fix"},
			{"needs review labelled separately", "Needs review"},
		},
		"index.classic.html": {
			{"a presentation guard", "model.presentation"},
			{"a presentation summary renderer", "function reportPresentationSummaryHTML("},
			{"the counts from the projection", "p.counts"},
			{"issues to fix as the headline", "issues to fix"},
		},
		"index.legacy.html": {
			{"a presentation guard", "model.presentation"},
			{"a presentation summary renderer", "function reportPresentationSummaryHTML("},
			{"the counts from the projection", "p.counts"},
			{"issues to fix as the headline", "issues to fix"},
		},
	}
	for name, wants := range pages {
		src := shippedWeb(t, name)
		for _, w := range wants {
			if !strings.Contains(src, w.want) {
				t.Errorf("%s lacks %s: %q", name, w.what, w.want)
			}
		}
	}

	// Nothing is recomputed from the raw records inside the presentation path: no grouping
	// pass, no severity tallying, no count arithmetic over findings.
	src := shippedWeb(t, "index.html")
	body := presentationFns(t, src)
	for _, bad := range []struct{ what, pattern string }{
		{"a grouping pass", `group_id\s*\]\s*=|groupBy|reduce\(`},
		{"a severity tally", `severity\w*\[[^\]]+\]\s*\+\+|\+\+\s*bySev`},
		{"count arithmetic over findings", `findings\.(?:length|filter|reduce)`},
		{"guidance written in the viewer", `(?i)validate/encode untrusted input`},
	} {
		if regexp.MustCompile(bad.pattern).MatchString(body) {
			t.Errorf("index.html's presentation renderers contain %s (/%s/)", bad.what, bad.pattern)
		}
	}
}

// T079 (FR-021, C-P28): no surface prepends a second legacy summary or appends a second full
// candidate dump. The projection path and the legacy path are mutually exclusive.
func TestShippedViewersRenderOneSummaryAndOneCandidateList(t *testing.T) {
	for _, name := range []string{"index.html", "index.classic.html", "index.legacy.html"} {
		src := shippedWeb(t, name)
		// The choice is a single guard, so both paths cannot run for one report.
		if !strings.Contains(src, "usePresentation") {
			t.Errorf("%s does not choose between the projection and the legacy path with one guard", name)
		}
		if !regexp.MustCompile(`usePresentation\s*\?`).MatchString(src) {
			t.Errorf("%s does not render the summary from exactly one of the two paths", name)
		}
	}
	// In the default viewer, the legacy summary and the legacy index are each reachable only
	// through the fallback side of that guard.
	src := shippedWeb(t, "index.html")
	for _, fn := range []string{"reportSummaryHTML(model)", "reportIndexHTML(model, id)"} {
		for _, call := range callSites(src, fn) {
			if !strings.Contains(call, "usePresentation ?") && !strings.Contains(call, ": "+fn) {
				t.Errorf("index.html calls the legacy %s outside the fallback: %q", fn, call)
			}
		}
	}
	// The candidate appendices are rendered once, by one renderer.
	if n := strings.Count(src, "Unresolved (session failed)"); n > 1 {
		t.Errorf("index.html renders the failed-session candidate list %d times", n)
	}
	if n := strings.Count(src, "function reportIndexHTML("); n != 1 {
		t.Errorf("index.html defines the legacy index renderer %d times", n)
	}
	if n := strings.Count(src, "function reportPresentationIndexHTML("); n != 1 {
		t.Errorf("index.html defines the projection index renderer %d times", n)
	}
}

// presentationFns returns the source of the viewer's presentation renderers, so the
// "nothing is recomputed" checks do not accidentally read the legacy functions.
func presentationFns(t *testing.T, src string) string {
	t.Helper()
	var out strings.Builder
	for _, fn := range []string{"function reportPresentationSummaryHTML(", "function reportPresentationIndexHTML("} {
		i := strings.Index(src, fn)
		if i < 0 {
			t.Fatalf("viewer lacks %s", fn)
		}
		rest := src[i:]
		// Up to the start of the next top-level function declaration.
		if j := strings.Index(rest[len(fn):], "\nfunction "); j >= 0 {
			rest = rest[:len(fn)+j]
		}
		out.WriteString(rest)
	}
	return out.String()
}

// callSites returns each line on which a function is called.
func callSites(src, fn string) []string {
	var out []string
	for _, line := range strings.Split(src, "\n") {
		if strings.Contains(line, fn) && !strings.Contains(line, "function "+fn) {
			out = append(out, strings.TrimSpace(line))
		}
	}
	return out
}

// T093 (FR-022, FR-023, C-P30, C-P31, C-P33): the interactive index is searchable and
// filterable, keyboard navigable with a visible focus ring, labels severity as text rather
// than by colour alone, names the displayed subset while keeping the full total reachable,
// and stays readable at 375 CSS pixels.
func TestShippedIndexIsFilterableAndAccessible(t *testing.T) {
	src := shippedWeb(t, "index.html")
	for _, w := range []struct{ what, want string }{
		{"a search box", `id="rq"`},
		{"a severity filter", `id="rsev"`},
		{"a section filter", `id="rstatus"`},
		{"keyboard-activatable rows", `tabindex="0" role="button"`},
		{"a keydown handler", `onkeydown="reportRowKey(event`},
		{"a visible focus ring", `tr.ridx:focus-visible{outline:2px solid var(--accent)`},
		{"severity as text, not colour alone", `<span class="sevchip ${_sevClass(is.severity)}">${esc(is.severity)}</span>`},
		{"the displayed subset named", "Filtered view — showing"},
		{"the displayed subset counted against the rendered rows", "showing ${shown} of ${n} rows"},
		{"the full report total kept reachable", "issues to fix in the full report"},
		{"long recorded paths broken instead of widening the page", "#reportIndex td,#reportIndex dd,#reportIndex li,#reportIndex p{overflow-wrap:anywhere}"},
		{"a narrow-screen layout", "@media (max-width:420px){"},
	} {
		if !strings.Contains(src, w.want) {
			t.Errorf("index.html lacks %s: %q", w.what, w.want)
		}
	}

	// The React surface carries the same behaviours for the projection-driven index.
	rb, err := readRepoFile("web-react/src/components/IssuesIndex.tsx")
	if err != nil {
		t.Skipf("React source not available: %v", err)
	}
	for _, w := range []struct{ what, want string }{
		{"a search box", `aria-label="Search issues"`},
		{"a severity filter", `aria-label="Severity filter"`},
		{"a section filter", `aria-label="Section filter"`},
		{"keyboard-activatable rows", `tabIndex={0}`},
		{"a keydown handler", `onKeyDown=`},
		{"a visible focus ring", "focus:outline"},
		{"severity as text", "<Badge variant={/^(critical|high)$/i.test(is.severity) ? \"err\" : \"warn\"}>{is.severity}</Badge>"},
		{"the displayed subset named", "Filtered view — showing"},
		{"the full total kept reachable", "issues to fix in the full report"},
		{"a zero-match statement", "No issue matches this filter"},
		{"a narrow-screen layout", "max-sm:grid-cols-1"},
		{"long values broken", "break-all"},
		{"the five reader sections", "How to check the fix"},
		{"pre-016 deep links preserved", "id={`finding-${m.finding_id}`}"},
	} {
		if !strings.Contains(rb, w.want) {
			t.Errorf("IssuesIndex.tsx lacks %s: %q", w.what, w.want)
		}
	}
	// It must not recompute what the projection already established.
	for _, bad := range []string{"remediation_groups", "severity_supported", "total_candidates"} {
		if strings.Contains(rb, bad) {
			t.Errorf("IssuesIndex.tsx reads the legacy model field %q instead of the projection", bad)
		}
	}
}

// readRepoFile reads a path relative to the repository root.
func readRepoFile(rel string) (string, error) {
	b, err := os.ReadFile(filepath.Join("..", "..", filepath.FromSlash(rel)))
	return string(b), err
}
