package reports

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// CA-6 / FR-018: each material state is classified explicitly; requested-but-missing
// reads as missing while not-requested reads as not_requested.
func TestMaterialStates(t *testing.T) {
	cases := []struct {
		name      string
		write     func(dir string)
		artifact  string
		requested bool
		want      string
	}{
		{"sbom available", func(d string) { os.WriteFile(filepath.Join(d, "sbom.cdx.json"), []byte(`{"components":[]}`), 0o644) }, "sbom.cdx.json", true, MatAvailable},
		{"sbom malformed", func(d string) { os.WriteFile(filepath.Join(d, "sbom.cdx.json"), []byte(`{bad`), 0o644) }, "sbom.cdx.json", true, MatMalformed},
		{"sbom empty→genfail", func(d string) { os.WriteFile(filepath.Join(d, "sbom.cdx.json"), []byte(``), 0o644) }, "sbom.cdx.json", true, MatGenerationFailed},
		{"sbom missing+requested", func(d string) {}, "sbom.cdx.json", true, MatMissing},
		{"sbom missing+not requested", func(d string) {}, "sbom.cdx.json", false, MatNotRequested},
		{"threat available", func(d string) { os.WriteFile(filepath.Join(d, "threat_model.md"), []byte("# TM\n"), 0o644) }, "threat_model.md", true, MatAvailable},
		{"threat empty→genfail", func(d string) { os.WriteFile(filepath.Join(d, "threat_model.md"), []byte("  \n"), 0o644) }, "threat_model.md", true, MatGenerationFailed},
		{"threat not requested", func(d string) {}, "threat_model.md", false, MatNotRequested},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			c.write(dir)
			m := MaterialFor(dir, c.artifact, c.requested)
			if m.State != c.want {
				t.Errorf("state = %q want %q", m.State, c.want)
			}
			if c.want == MatAvailable && m.Path == "" {
				t.Errorf("available material must carry a path")
			}
		})
	}
}

// Feature 015 (C-A14, T035): the threat model's narrative availability and its
// diagram validity are separate facts; a pre-015 run reads diagram "unknown".
func TestThreatModelDiagramSubState(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "threat_model.md"), []byte("# TM\n\n```mermaid\nflowchart TD\n    B -.->|HTTP request (untrusted) .-> E\n```\n"), 0o644)
	m := MaterialFor(dir, "threat_model.md", true)
	if m.State != MatAvailable || m.Diagram == nil || m.Diagram.State != DiagramUnknown {
		t.Fatalf("without the artifact: %+v", m)
	}
	os.WriteFile(filepath.Join(dir, "threat_model_diagram.json"), []byte(`{"version":1,"renderer_version":"11.17.2","source":"threat_model.md","diagrams":[{"index":0,"state":"invalid","repairs":[],"errors":[{"line":2,"code":"E_EDGE_LABEL_UNTERMINATED","message":"edge label opened with | but never closed"}]}]}`), 0o644)
	m = MaterialFor(dir, "threat_model.md", true)
	if m.State != MatAvailable {
		t.Errorf("narrative must stay available: %+v", m)
	}
	if m.Diagram == nil || m.Diagram.State != "invalid" || len(m.Diagram.Errors) != 1 || !strings.Contains(m.Diagram.Errors[0], "line 2: E_EDGE_LABEL_UNTERMINATED") {
		t.Errorf("diagram sub-state = %+v", m.Diagram)
	}
}
