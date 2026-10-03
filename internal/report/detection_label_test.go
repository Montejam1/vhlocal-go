package report

import (
	"regexp"
	"strings"
	"testing"
)

// T058 (FR-007, C-P6): detection counts are secondary, labelled and traceable, and never
// presented as a count of vulnerabilities.
func TestDetectionCountsAreSecondaryAndLabelled(t *testing.T) {
	base := loadFixture016Baseline(t)
	in := fixture016Input(t)
	m := BuildModel(in)
	p := m.Presentation
	md := renderMarkdownModel(in, m)

	// Secondary: the headline figure is issues, and the detection total appears only in the
	// operator section, after the vulnerability content.
	det := itoa016(base.Counts.SupportedDetections)
	idx := strings.Index(md, hdrIssues)
	opening := md[:idx]
	if regexp.MustCompile(`\b` + det + `\b`).MatchString(opening) {
		t.Errorf("the detection total %s appears in the opening", det)
	}
	scanAt := strings.Index(md, hdrScanDetail)
	accounting := strings.Index(md, "**Supported detections**")
	if accounting < 0 {
		t.Fatal("the detection total is not stated anywhere")
	}
	if accounting < scanAt {
		t.Error("the detection total is stated before Scan details")
	}

	// Labelled: wherever it appears it is called detections, never vulnerabilities.
	forVuln := regexp.MustCompile(`(?i)\b` + det + `\s+(?:vulnerabilit\w*|issues?|defects?|findings?)\b`)
	for name, body := range map[string]string{"markdown": md, "standalone html": renderHTMLModel(in, m)} {
		if loc := forVuln.FindString(body); loc != "" {
			t.Errorf("%s presents the detection total as vulnerabilities: %q", name, loc)
		}
	}

	// Traceable: every detection is named in the issue it belongs to, with its recorded id.
	total := 0
	for _, is := range p.Issues {
		total += is.DetectionCount
		block := ""
		if i := strings.Index(md, `<a id="`+strings.ToLower(is.Ref)+`"></a>`); i >= 0 {
			block = md[i:]
			if j := strings.Index(block[1:], `<a id="issue-`); j >= 0 {
				block = block[:j]
			}
		}
		for _, mem := range is.Members {
			if !strings.Contains(block, mem.FindingID) {
				t.Errorf("%s does not name its detection %s", is.Ref, mem.FindingID)
			}
		}
	}
	if total != base.Counts.SupportedDetections {
		t.Errorf("detections across issues = %d, records say %d", total, base.Counts.SupportedDetections)
	}

	// An issue backed by several detections says so where the reader meets it.
	multi := 0
	for _, is := range p.Issues {
		if is.DetectionCount > 1 {
			multi++
		}
	}
	if multi == 0 {
		t.Fatal("fixture precondition: no issue has more than one detection")
	}
	if !strings.Contains(md, "detections") {
		t.Error("the document never uses the word detections")
	}
}
