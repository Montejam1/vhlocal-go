package report

import (
	"fmt"
	"regexp"
	"strings"
	"testing"
)

// scaleCorpus builds a records-shaped corpus of n supported findings, each its own primary
// issue, cycling through the display severities and weakness families so filtering has
// something real to reach. Nothing is written to disk.
func scaleCorpus(t *testing.T, n int) Input {
	t.Helper()
	severities := []string{"Critical", "High+", "High", "Medium", "Low", "Informational", ""}
	families := []struct{ family, cwe string }{
		{"deserialization", "CWE-502"}, {"path-traversal", "CWE-22"}, {"access-control", "CWE-862"},
		{"race-condition", "CWE-362"}, {"sql-injection", "CWE-89"}, {"xss", "CWE-79"},
		{"", "CWE-754"}, // a weakness in no family: the investigate branch at scale
	}
	findings := make([]map[string]any, 0, n)
	for i := 0; i < n; i++ {
		f := families[i%len(families)]
		findings = append(findings, corpusFinding(
			fmt.Sprintf("CAND-scale%04d", i),
			fmt.Sprintf("Issue %d in handler %d", i, i%17),
			f.cwe, f.family, severities[i%len(severities)],
			fmt.Sprintf("app/pkg%d/module%d.py:%d", i%9, i%23, 10+i),
			fmt.Sprintf("POST /api/v1/resource%d", i%31),
			"supported",
			Evidence{Path: fmt.Sprintf("app/pkg%d/module%d.py", i%9, i%23), Start: 10 + i, End: 12 + i, Quote: fmt.Sprintf("row = load(request.data)  # %d", i)},
		))
	}
	return corpusInput(findings, nil)
}

// T086 (SC-007, C-P30): at 100 primary issues the search and severity filters reach every
// eligible issue, filtering never changes the full-report total, and a zero-match view says
// so while keeping the full total reachable.
func TestScaleCorpusFiltersReachEveryIssue(t *testing.T) {
	const n = 120
	in := scaleCorpus(t, n)
	m := BuildModel(in)
	p := m.Presentation
	if len(p.Issues) < 100 {
		t.Fatalf("corpus produced %d primary issues, want at least 100", len(p.Issues))
	}
	if p.Counts.IssuesToFix != len(p.Issues) {
		t.Errorf("headline %d does not match %d issues", p.Counts.IssuesToFix, len(p.Issues))
	}

	h := renderHTMLModel(in, m)
	rows := regexp.MustCompile(`<tr class="idx"[^>]*data-sev="([^"]*)"[^>]*data-text="([^"]*)"`).FindAllStringSubmatch(h, -1)
	if len(rows) != len(p.Issues) {
		t.Fatalf("the index renders %d filterable rows for %d issues", len(rows), len(p.Issues))
	}

	// Severity filter: every row is reachable by one of the offered options, and the options
	// cover every severity present.
	offered := map[string]bool{}
	for _, opt := range regexp.MustCompile(`<option>([a-z+]+)</option>`).FindAllStringSubmatch(h, -1) {
		offered[opt[1]] = true
	}
	bySev := map[string]int{}
	for _, r := range rows {
		bySev[r[1]]++
		if !offered[r[1]] {
			t.Errorf("severity %q has rows but no filter option", r[1])
		}
	}
	total := 0
	for _, s := range DisplaySeverities {
		got := bySev[strings.ToLower(s)]
		if got != p.Counts.Severity[s] {
			t.Errorf("severity %s: %d rows but the chart says %d", s, got, p.Counts.Severity[s])
		}
		total += got
	}
	if total != len(p.Issues) {
		t.Errorf("filterable rows by severity sum to %d, want %d", total, len(p.Issues))
	}

	// Search: every issue is reachable by a substring of its own searchable text, and the
	// text is lower-cased so a case-insensitive search works.
	for i, r := range rows {
		is := p.Issues[i]
		if !strings.Contains(r[2], strings.ToLower(is.Title)) {
			t.Errorf("%s is not reachable by searching its title", is.Ref)
		}
		if r[2] != strings.ToLower(r[2]) {
			t.Errorf("%s searchable text is not normalised for case", is.Ref)
		}
	}

	// Filtering is presentation only: the full total stays in the document, and the filter
	// banner names the displayed subset against it.
	if !strings.Contains(h, "Filtered view — showing") || !strings.Contains(h, "' of '+n+'") {
		t.Error("the filter banner does not name the displayed subset against the full total")
	}
	if !strings.Contains(h, fmt.Sprintf(`<div class="tn">%d</div><div class="tl">Issues to fix</div>`, p.Counts.IssuesToFix)) {
		t.Error("the full total is not stated outside the filtered table")
	}
	// A zero-match view is handled by the same banner, which reports "showing 0 of N".
	if !strings.Contains(h, "shown+' of '+n") && !strings.Contains(h, "showing '+shown+' of '+n") {
		t.Error("a zero-match filtered view would not state the empty result against the full total")
	}
}

// T086 (spec Edge Cases, C-P30): very long names, paths, source lines and evidence render
// without page-level overflow or lost content.
func TestScaleCorpusHandlesVeryLongValues(t *testing.T) {
	long := strings.Repeat("extremely-long-segment-", 40)                // ~920 chars
	longLine := strings.Repeat("a = compute(b, c, d, e, f, g, h); ", 60) // a very long source line
	in := corpusInput([]map[string]any{
		corpusFinding("CAND-long", "A title that "+long, "CWE-502", "deserialization", "High",
			"app/"+long+"/module.py:1", "POST /api/"+long, "supported",
			Evidence{Path: "app/" + long + "/module.py", Start: 1, End: 2, Quote: longLine}),
	}, nil)
	m := BuildModel(in)
	md := renderMarkdownModel(in, m)
	h := renderHTMLModel(in, m)

	// Nothing is truncated away: the long values are present in full.
	for name, body := range map[string]string{"markdown": md, "standalone html": h} {
		if !strings.Contains(body, long) {
			t.Errorf("%s lost the long path or title", name)
		}
	}
	if !strings.Contains(h, "a = compute(b, c, d, e, f, g, h);") {
		t.Error("the long source line was dropped from the html")
	}
	// The markdown table row stays a single row: no embedded newline breaks it.
	index := sectionOf(t, md, hdrIssues)
	dataRows := 0
	for _, line := range strings.Split(strings.TrimSpace(index), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "| 1 |") {
			dataRows++
		}
	}
	if dataRows != 1 {
		t.Errorf("the long values produced %d rows for one issue", dataRows)
	}
	// The page constrains overflow rather than letting the body scroll sideways: long
	// content lives in wrapping or scrollable containers.
	for _, want := range []string{"white-space:pre-wrap", "overflow:auto"} {
		if !strings.Contains(h, want) {
			t.Errorf("the stylesheet lacks %q, so a long line would overflow the page", want)
		}
	}
	if !regexp.MustCompile(`word-break|overflow-wrap|word-wrap`).MatchString(h) {
		t.Error("the stylesheet has no rule to break an unbreakable long token")
	}
}
