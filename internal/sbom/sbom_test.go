package sbom

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func moduleRoot(t *testing.T) string {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}

func TestCollectFixtureFlask(t *testing.T) {
	repo := filepath.Join(moduleRoot(t), "testdata", "vulnapp")
	comps := Collect(repo)
	if len(comps) != 1 || comps[0].Name != "flask" || comps[0].Ecosystem != "pypi" {
		t.Fatalf("expected [flask/pypi], got %+v", comps)
	}
}

func TestBuildCycloneDXShape(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "requirements.txt"), []byte("flask==2.0\nrequests>=2.28\n# comment\n"), 0o644)
	os.WriteFile(filepath.Join(dir, "package.json"), []byte(`{"dependencies":{"react":"^18.2.0"}}`), 0o644)

	doc := Build(dir, "")
	if doc.BOMFormat != "CycloneDX" || doc.SpecVersion != "1.5" || doc.Version != 1 {
		t.Fatalf("bad header: %+v", doc)
	}
	if len(doc.Components) != 3 {
		t.Fatalf("want 3 components, got %d", len(doc.Components))
	}
	// deterministic order: golang<npm<pypi by ecosystem; here npm(react) then pypi(flask,requests)
	if doc.Components[0].Purl != "pkg:npm/react@18.2.0" {
		t.Errorf("first purl = %q", doc.Components[0].Purl)
	}
	// property key parity
	if doc.Components[0].Properties[0].Name != "vhlocal:ecosystem" {
		t.Errorf("property name = %q", doc.Components[0].Properties[0].Name)
	}
	// pypi version parsed
	var flask *cdxComp
	for i := range doc.Components {
		if doc.Components[i].Name == "flask" {
			flask = &doc.Components[i]
		}
	}
	if flask == nil || flask.Version != "2.0" || flask.Purl != "pkg:pypi/flask@2.0" {
		t.Fatalf("flask component wrong: %+v", flask)
	}
}

func TestWriteAndSummarize(t *testing.T) {
	repo := filepath.Join(moduleRoot(t), "testdata", "vulnapp")
	results := t.TempDir()
	path, err := Write(repo, results, "")
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil || filepath.Base(path) != "sbom.cdx.json" {
		t.Fatalf("write: %v path=%s", err, path)
	}
	var doc map[string]any
	if json.Unmarshal(b, &doc) != nil {
		t.Fatal("output is not valid JSON")
	}
	sum := Summarize(repo)
	if sum.Total != 1 || sum.ByEcosystem["pypi"] != 1 {
		t.Fatalf("summary = %+v", sum)
	}
}
