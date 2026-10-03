package report

import (
	"regexp"
	"strings"
	"testing"
)

// T085 (FR-023, C-P32): the generated standalone report is self-contained for its primary
// content and usable with network access disabled — no external script, stylesheet, font or
// image reference, no CDN host, no absolute http or https resource URL.
func TestStandaloneReportIsSelfContained(t *testing.T) {
	in := fixture016Input(t)
	// A recorded field that happens to contain a URL must not become a live reference.
	in.Nav = []NavLink{{Label: "Threat model", Path: "threat_model.md"}, {Label: "SBOM", Path: "sbom.cdx.json"}}
	h := renderHTMLModel(in, BuildModel(in))

	// No resource is loaded from anywhere but this file.
	external := []struct{ what, pattern string }{
		{"an external script", `<script[^>]+src=`},
		{"an external stylesheet", `<link[^>]+rel=["']?stylesheet`},
		{"any link element at all", `<link\s`},
		{"an image reference", `<img\s`},
		{"a remote font", `@font-face|fonts\.(?:googleapis|gstatic)`},
		{"a CSS import", `@import`},
		{"a CDN host", `(?i)cdnjs|jsdelivr|unpkg|cdn\.|googleapis|gstatic|bootstrapcdn`},
		{"an absolute http resource", `(?:src|href)\s*=\s*["']?https?://`},
		{"a url() pointing off-file", `url\(\s*["']?(?:https?:)?//`},
		{"a meta refresh", `(?i)http-equiv=["']?refresh`},
		{"a form posting somewhere", `<form\s`},
		{"an iframe", `(?i)<iframe`},
		{"a websocket or fetch to a host", `(?i)(?:new WebSocket\(|fetch\(\s*["']https?://)`},
	}
	for _, e := range external {
		re := regexp.MustCompile(e.pattern)
		if loc := re.FindString(h); loc != "" {
			t.Errorf("the standalone report contains %s: %q", e.what, loc)
		}
	}

	// Every href is a same-document anchor or a relative path beside the report.
	for _, m := range regexp.MustCompile(`href="([^"]*)"`).FindAllStringSubmatch(h, -1) {
		target := m[1]
		switch {
		case strings.HasPrefix(target, "#"):
		case strings.HasPrefix(target, "/"), strings.HasPrefix(target, "file:"),
			strings.Contains(target, "://"), strings.HasPrefix(target, "//"):
			t.Errorf("non-portable link in the standalone report: %q", target)
		}
	}

	// The styling and the behaviour are inline, so the file renders alone.
	if !strings.Contains(h, "<style>") {
		t.Error("the report has no inline stylesheet")
	}
	if !strings.Contains(h, "<script>") {
		t.Error("the report has no inline script")
	}
	// Its primary content is present as markup, not fetched or generated on demand.
	m := BuildModel(in)
	for _, is := range m.Presentation.Issues {
		if !strings.Contains(h, `id="`+strings.ToLower(is.Ref)+`"`) {
			t.Errorf("%s is not present in the file itself", is.Ref)
		}
	}
	// Storage access is optional: a browser with storage blocked must still render.
	if strings.Contains(h, "sessionStorage") && !strings.Contains(h, "try{") {
		t.Error("storage access is not guarded, so a blocked-storage browser would break")
	}
}
