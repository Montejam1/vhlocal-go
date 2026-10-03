package server

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	vhlocal "vhlocal"
)

// T026 (C-A9): the shipped in-app viewers rewrite the report's relative links to
// the owning report's confined file endpoint and validate link schemes; the
// React Markdown component carries the same rule in source.
func TestShippedViewersRewriteReportLinks(t *testing.T) {
	web, err := fs.Sub(vhlocal.WebFS, "vhlocal/web")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"index.html", "index.classic.html", "index.legacy.html"} {
		b, err := fs.ReadFile(web, name)
		if err != nil {
			t.Fatal(err)
		}
		src := string(b)
		for _, want := range []string{
			"function mdRender(src, base)", // base-aware renderer
			"function mdHref(",             // the single link rule: relative → file endpoint, scheme allow-list
			`/file?path=`,                  // confined report file endpoint
			"ALLOWED_SCHEMES",              // http, https, mailto only (plus relative and #anchors)
		} {
			if !strings.Contains(src, want) {
				t.Errorf("%s lacks %q", name, want)
			}
		}
		// Every mdRender call that renders a report file passes the report base.
		if strings.Contains(src, "mdRender(txt)}") || strings.Contains(src, "mdRender(t)}") {
			t.Errorf("%s renders a report file without its base (links would break in-app)", name)
		}
	}
	// React: react-markdown urlTransform with the same rule.
	md, err := os.ReadFile(filepath.Join("..", "..", "web-react", "src", "components", "Markdown.tsx"))
	if err == nil {
		for _, want := range []string{"urlTransform", "base?: string", "?path=", "mailto:", "ALLOWED_SCHEMES"} {
			if !strings.Contains(string(md), want) {
				t.Errorf("web-react Markdown.tsx lacks %q", want)
			}
		}
	}
}
