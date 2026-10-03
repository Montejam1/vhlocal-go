package report

import (
	"strings"
	"testing"
)

// The five reader sections of an issue, in the order FR-011 fixes them, plus the optional
// technical detail that follows.
var issueSections = []string{
	"**What we found**", "**Why it matters**", "**Where it is**",
	"**How to fix it**", "**How to check the fix**",
}

const sectionTechnical = "**Technical evidence**"

// issueBlocks splits the rendered "Issue details" section into one block per issue.
func issueBlocks(t *testing.T, md string) []string {
	t.Helper()
	body := sectionOf(t, md, hdrDetails)
	parts := strings.Split(body, "\n### ")
	if len(parts) < 2 {
		t.Fatalf("no issue detail sections rendered")
	}
	return parts[1:]
}

// T041 (FR-011, C-P16): every primary issue carries the five sections in order, with
// technical evidence following as optional detail, under a header naming the title, the
// severity and a stable reference.
func TestIssueSectionsAreOrderedAndComplete(t *testing.T) {
	in := fixture016Input(t)
	m := BuildModel(in)
	md := renderMarkdownModel(in, m)
	blocks := issueBlocks(t, md)
	if len(blocks) != len(m.Presentation.Issues) {
		t.Fatalf("rendered %d detail sections for %d issues", len(blocks), len(m.Presentation.Issues))
	}

	for i, block := range blocks {
		is := m.Presentation.Issues[i]
		header := block[:strings.Index(block, "\n")]
		for _, want := range []string{is.Severity, is.Title, is.Ref} {
			if !strings.Contains(header, want) {
				t.Errorf("issue %s header lacks %q: %q", is.Ref, want, header)
			}
		}
		last := -1
		for _, sec := range issueSections {
			at := strings.Index(block, sec)
			if at < 0 {
				t.Errorf("issue %s has no %s section", is.Ref, sec)
				continue
			}
			if at < last {
				t.Errorf("issue %s renders %s out of order", is.Ref, sec)
			}
			last = at
		}
		// Technical evidence follows the five sections when present.
		if at := strings.Index(block, sectionTechnical); at >= 0 && at < last {
			t.Errorf("issue %s renders technical evidence before the reader sections", is.Ref)
		}
		// Each section says something.
		for _, sec := range issueSections {
			if body := strings.TrimSpace(sectionBody(block, sec)); body == "" {
				t.Errorf("issue %s has an empty %s section", is.Ref, sec)
			}
		}
	}
}

// T042 (FR-011, C-P17): no paragraph is repeated under more than one heading. A reader who
// meets the same sentence twice learns nothing the second time and trusts the document less.
func TestIssueSectionsDoNotRepeatParagraphs(t *testing.T) {
	in := fixture016Input(t)
	m := BuildModel(in)
	md := renderMarkdownModel(in, m)
	for i, block := range issueBlocks(t, md) {
		is := m.Presentation.Issues[i]
		seen := map[string]string{}
		for _, sec := range append(append([]string{}, issueSections...), sectionTechnical) {
			body := sectionBody(block, sec)
			for _, para := range strings.Split(body, "\n") {
				p := normalizeParagraph(para)
				if len(p) < 40 { // a short label or list marker is not a paragraph
					continue
				}
				if other, dup := seen[p]; dup && other != sec {
					t.Errorf("issue %s repeats a paragraph under %s and %s: %q", is.Ref, other, sec, truncate(p, 70))
				}
				seen[p] = sec
			}
		}
	}
}

// sectionBody returns the text between one bold section label and the next one.
func sectionBody(block, label string) string {
	i := strings.Index(block, label)
	if i < 0 {
		return ""
	}
	rest := block[i+len(label):]
	best := len(rest)
	for _, other := range append(append([]string{}, issueSections...), sectionTechnical) {
		if other == label {
			continue
		}
		if j := strings.Index(rest, other); j >= 0 && j < best {
			best = j
		}
	}
	return rest[:best]
}

func normalizeParagraph(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimLeft(s, "-*0123456789. \t")
	s = strings.ReplaceAll(s, "`", "")
	return strings.Join(strings.Fields(strings.ToLower(s)), " ")
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
