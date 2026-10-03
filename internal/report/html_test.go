package report

import (
	"regexp"
	"strings"
	"testing"

	"vhlocal/internal/consolidate"
)

// T025 (C-A7, C-A11, FR-010): the single-file HTML has search + severity/status
// filters over EVERY row class, keyboard-focusable index rows, print header with
// export scope and active-filter disclosure, page-break rules, beforeprint expand,
// no external requests, and escaped model content.
func TestHTMLFiltersPrintAndEscaping(t *testing.T) {
	in := replayInput(t)
	in.Doc.Findings = append(in.Doc.Findings, map[string]any{
		"id": "CAND-xss", "title": "<script>alert(1)</script> in <title>", "severity": "Low", "severity_rank": 5,
		"location": "x.py:1", "verification_status": "supported", "from_confirmed": true,
	})
	// Feature 016 (T036): the status filter and the per-detection row classes belong to
	// the legacy document. That document still renders for pre-016 models (FR-026, C-C7),
	// so the filter, print, escaping and no-external-request assertions below are kept and
	// read from it. The new document's equivalents are asserted in anchors_test.go.
	h := renderHTMLLegacy(in, BuildModel(in))
	for _, want := range []string{
		`id="q"`, `id="sevFilter"`, `id="statusFilter"`, `id="scope"`, `function applyFilter`,
		`querySelectorAll('.idx,.finding,.cand')`, `tabindex="0"`, `data-status="supported"`, `data-status="rejected"`,
		`data-status="unresolved_explicit"`, `data-status="unresolved_failed"`, `data-sev="high"`,
		`id="printhdr"`, `Export scope: `, `break-inside:avoid`, `beforeprint`, `Filtered view — showing`, `Save as PDF`,
		`sessionStorage`, `id="finding-CAND-xss"`,
	} {
		if !strings.Contains(h, want) {
			t.Errorf("HTML lacks %q", want)
		}
	}
	for _, bad := range []string{`src="http`, `href="http://`, `//cdn`, `googleapis`, `http-equiv="refresh`, "<script>alert(1)</script>"} {
		if strings.Contains(h, bad) {
			t.Errorf("HTML contains %q", bad)
		}
	}
	if !strings.Contains(h, "&lt;script&gt;alert(1)&lt;/script&gt;") {
		t.Error("model-authored markup must be escaped")
	}
	// Every index row and appendix row is filterable (data-status on each class).
	idx := regexp.MustCompile(`<tr class="idx"[^>]*data-status=`).FindAllString(h, -1)
	if len(idx) != 44 {
		t.Errorf("index rows with data-status = %d, want 44", len(idx))
	}
	cand := regexp.MustCompile(`<li class="cand"[^>]*data-status=`).FindAllString(h, -1)
	if len(cand) != 7+8+113 {
		t.Errorf("appendix rows with data-status = %d, want 128", len(cand))
	}
}

// Relative links only in the persisted report (portable exports); in-app viewers
// rewrite them (asserted on the shipped assets in internal/server).
func TestReportLinksAreRelative(t *testing.T) {
	in := replayInput(t)
	in.Nav = []NavLink{{Label: "Threat model", Path: "threat_model.md"}}
	md := RenderMarkdown(in)
	for _, m := range regexp.MustCompile(`\]\(([^)]+)\)`).FindAllStringSubmatch(md, -1) {
		target := m[1]
		if strings.HasPrefix(target, "/") || strings.HasPrefix(target, "file:") {
			t.Errorf("absolute link in Markdown export: %s", target)
		}
	}
	h := RenderHTML(in)
	for _, m := range regexp.MustCompile(`href="([^"]+)"`).FindAllStringSubmatch(h, -1) {
		target := m[1]
		if strings.HasPrefix(target, "/") || strings.HasPrefix(target, "file:") {
			t.Errorf("absolute link in HTML export: %s", target)
		}
	}
	_ = consolidate.ClassSupported
}
