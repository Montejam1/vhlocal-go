package report

import (
	"regexp"
	"strings"
	"testing"
)

// T035 (FR-010, C-P22): every index row links to a target that exists, long internal
// identifiers stay out of the title and the default columns, and every deep link a reader
// may already have bookmarked still resolves — the per-detection `#finding-<id>` anchors
// and the `#group-<id>` anchors of the recorded remediation groups.
func TestIndexLinksAndLegacyDeepLinksResolve(t *testing.T) {
	in := fixture016Input(t)
	m := BuildModel(in)
	p := m.Presentation
	md := renderMarkdownModel(in, m)
	h := renderHTMLModel(in, m)

	// Every index row's target exists on both surfaces.
	for _, is := range p.Issues {
		ref := strings.ToLower(is.Ref)
		if !strings.Contains(md, "(#"+ref+")") {
			t.Errorf("issue %s has no index link in markdown", is.Ref)
		}
		if !strings.Contains(md, `<a id="`+ref+`"></a>`) {
			t.Errorf("issue %s has no anchor in markdown", is.Ref)
		}
		if !strings.Contains(h, `href="#`+ref+`"`) || !strings.Contains(h, `id="`+ref+`"`) {
			t.Errorf("issue %s link or anchor missing in html", is.Ref)
		}
	}

	// Pre-016 deep links keep working: one anchor per supported detection.
	detections := 0
	for _, is := range p.Issues {
		for _, mem := range is.Members {
			detections++
			if !strings.Contains(md, `<a id="finding-`+mem.FindingID+`"></a>`) {
				t.Errorf("markdown lost the deep link #finding-%s", mem.FindingID)
			}
			if !strings.Contains(h, `id="finding-`+mem.FindingID+`"`) {
				t.Errorf("html lost the deep link #finding-%s", mem.FindingID)
			}
		}
	}
	if detections == 0 {
		t.Fatal("fixture has no supported detections")
	}

	// Group deep links keep working for every established group that backs an issue.
	groups := 0
	for _, is := range p.Issues {
		if is.GroupID == "" {
			continue
		}
		groups++
		if !strings.Contains(md, `<a id="group-`+is.GroupID+`"></a>`) {
			t.Errorf("markdown lost the deep link #group-%s", is.GroupID)
		}
		if !strings.Contains(h, `id="group-`+is.GroupID+`"`) {
			t.Errorf("html lost the deep link #group-%s", is.GroupID)
		}
	}
	if groups == 0 {
		t.Fatal("fixture has no established groups")
	}

	// Long internal identifiers do not dominate the reader-facing columns: no candidate or
	// group id appears in the index table itself (they stay in the detail sections).
	index := sectionOf(t, md, hdrIssues)
	for _, re := range []*regexp.Regexp{regexp.MustCompile(`CAND-[0-9a-f]{8}`), regexp.MustCompile(`RG-[0-9a-f]{8}`)} {
		if loc := re.FindString(index); loc != "" {
			t.Errorf("the index table carries the internal identifier %q", loc)
		}
	}
	for _, is := range p.Issues {
		if strings.Contains(is.Title, "CAND-") {
			t.Errorf("issue title carries an internal identifier: %q", is.Title)
		}
	}
}

// T035 (FR-025-equivalent, C-C12): the new standalone HTML stays inert and offline —
// model-authored text is escaped and nothing is fetched from the network.
func TestPresentationHTMLIsInertAndOffline(t *testing.T) {
	in := fixture016Input(t)
	// A model-authored title carrying markup must render as text, not as an element.
	in.Doc.Findings = append(in.Doc.Findings, map[string]any{
		"id": "CAND-xss016", "title": "<script>alert(1)</script> in <title>", "severity": "Low",
		"location": "x.py:1", "verification_status": "supported", "from_confirmed": true,
	})
	h := renderHTMLModel(in, BuildModel(in))
	for _, bad := range []string{`src="http`, `href="http://`, `href="https://`, `//cdn`, `googleapis`, `http-equiv="refresh`, "<script>alert(1)</script>"} {
		if strings.Contains(h, bad) {
			t.Errorf("standalone html contains %q", bad)
		}
	}
	if !strings.Contains(h, "&lt;script&gt;alert(1)&lt;/script&gt;") {
		t.Error("model-authored markup must be escaped")
	}
	// The controls a reader needs are present and self-contained.
	for _, want := range []string{`id="q"`, `id="sevFilter"`, `id="scope"`, "function applyFilter", "beforeprint", "Save as PDF", `id="printhdr"`, "break-inside:avoid"} {
		if !strings.Contains(h, want) {
			t.Errorf("standalone html lacks %q", want)
		}
	}
}
