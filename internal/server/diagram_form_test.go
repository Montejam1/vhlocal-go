package server

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	vhlocal "vhlocal"
)

// T037 (C-A15, C-A16): the SHIPPED main UI renders each diagram on its own —
// parse-first with suppressed errors, strict security level, a per-diagram error
// with line/code, Retry and View-source controls, a node/flow table fallback, a
// theme-change re-render hook and SVG export; classic/legacy show the table
// fallback and point to the main UI. React sources carry the same states. These
// are source-string checks on shipped assets, not browser verification.
func TestShippedDiagramContract(t *testing.T) {
	web, err := fs.Sub(vhlocal.WebFS, "vhlocal/web")
	if err != nil {
		t.Fatal(err)
	}
	b, err := fs.ReadFile(web, "index.html")
	if err != nil {
		t.Fatal(err)
	}
	src := string(b)
	for name, want := range map[string]string{
		"per-diagram render":   "window.renderDiagram = async function(pre, force)",
		"parse first":          "m.parse(src, {suppressErrors: true})",
		"strict security":      "securityLevel:'strict'",
		"error with line":      "Diagram did not render",
		"retry control":        "retryDiagram(",
		"view source control":  "toggleDiagramSource(",
		"table fallback":       "function _diagramTableHTML(src)",
		"theme re-render":      "window.rerenderDiagrams = function()",
		"svg export":           "exportDiagramSVG(",
		"independent siblings": "nodes.forEach(n => renderDiagram(n, false))",
		"state per element":    "data-dgm-state",
		"repair disclosed":     "repaired (bounded formatting rules)",
		"no loose mode":        "securityLevel:'loose'",
	} {
		has := strings.Contains(src, want)
		if name == "no loose mode" {
			if has {
				t.Errorf("shipped index.html still uses %q", want)
			}
			continue
		}
		if !has {
			t.Errorf("shipped index.html lacks %s: %q", name, want)
		}
	}
	for _, name := range []string{"index.classic.html", "index.legacy.html"} {
		cb, err := fs.ReadFile(web, name)
		if err != nil {
			t.Fatal(err)
		}
		for _, want := range []string{"function diagramTableHTML(", "diagram rendering is available in the main UI", "diagramTableHTML(buf.join('\\n'))"} {
			if !strings.Contains(string(cb), want) {
				t.Errorf("%s lacks %q", name, want)
			}
		}
	}
	if rb, err := os.ReadFile(filepath.Join("..", "..", "web-react", "src", "components", "Mermaid.tsx")); err == nil {
		for _, want := range []string{`securityLevel: "strict"`, "mermaid.parse(src, { suppressErrors: true })", `setState({ kind: "rendering" })`, "Retry", "View source", "DiagramTable", "Export SVG", `attributeFilter: ["data-theme"]`, `data-testid="diagram-error"`} {
			if !strings.Contains(string(rb), want) {
				t.Errorf("web-react Mermaid.tsx lacks %q", want)
			}
		}
		if strings.Contains(string(rb), `securityLevel: "loose"`) {
			t.Error("web-react Mermaid.tsx still uses loose security")
		}
	}
	// The prompt asks for exactly what the parser accepts (T044).
	if pb, err := os.ReadFile(filepath.Join("..", "..", "skill", "phases", "phase1t_threat_model.md")); err == nil {
		for _, want := range []string{"threat_model_diagram.json", "An edge label MUST be closed", "never `subgraph \"User space\"`"} {
			if !strings.Contains(string(pb), want) {
				t.Errorf("phase1t prompt lacks %q", want)
			}
		}
	}
}
