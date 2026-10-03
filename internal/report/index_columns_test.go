package report

import (
	"regexp"
	"strings"
	"testing"
)

// T059 (FR-010, C-P22): every index row carries severity, a human-readable title, the
// affected component or location count, and the recommended action; no long internal
// identifier dominates a title or a default column.
func TestIndexRowsCarryTheFourReaderColumns(t *testing.T) {
	in := fixture016Input(t)
	m := BuildModel(in)
	md := renderMarkdownModel(in, m)
	index := sectionOf(t, md, hdrIssues)

	rows := regexp.MustCompile(`(?m)^\| \d+ \|.*\|$`).FindAllString(index, -1)
	if len(rows) != len(m.Presentation.Issues) {
		t.Fatalf("index has %d rows for %d issues", len(rows), len(m.Presentation.Issues))
	}
	displayed := map[string]bool{}
	for _, s := range DisplaySeverities {
		displayed[s] = true
	}
	for i, row := range rows {
		is := m.Presentation.Issues[i]
		cells := strings.Split(strings.Trim(row, "|"), "|")
		if len(cells) != 5 {
			t.Fatalf("row %d has %d cells, want 5: %s", i+1, len(cells), row)
		}
		sev, title, affected, action := strings.TrimSpace(cells[1]), strings.TrimSpace(cells[2]), strings.TrimSpace(cells[3]), strings.TrimSpace(cells[4])
		if !displayed[sev] {
			t.Errorf("row %d severity %q is not a displayed category", i+1, sev)
		}
		if !strings.Contains(title, is.Title) {
			t.Errorf("row %d title %q does not carry the issue title", i+1, title)
		}
		if affected == "" {
			t.Errorf("row %d names no affected component or location", i+1)
		}
		if action == "" {
			t.Errorf("row %d gives no recommended action", i+1)
		}
		if strings.Contains(action, "not provided") {
			t.Errorf("row %d action is a non-answer: %q", i+1, action)
		}
		// The affected cell is a location or a location count, never a detection count
		// masquerading as one.
		if len(is.Locations) > 1 && !strings.Contains(affected, "locations") {
			t.Errorf("row %d has %d locations but the cell reads %q", i+1, len(is.Locations), affected)
		}
	}

	// No long internal identifier in any default column.
	for _, re := range []*regexp.Regexp{
		regexp.MustCompile(`CAND-[0-9a-f]{8}`),
		regexp.MustCompile(`RG-[0-9a-f]{8}`),
		regexp.MustCompile(`\b[0-9a-f]{24,}\b`),
	} {
		if loc := re.FindString(index); loc != "" {
			t.Errorf("the index carries the internal identifier %q", loc)
		}
	}

	// The HTML index has the same four reader columns in the same order.
	h := renderHTMLModel(in, m)
	if !strings.Contains(h, `<th>Severity</th><th>Issue</th><th>Affected</th><th>Recommended action</th>`) {
		t.Error("the html index does not carry the four reader columns in order")
	}
}
