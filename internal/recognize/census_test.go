package recognize

import (
	"os"
	"path/filepath"
	"testing"
)

func write(t *testing.T, root, rel, content string) {
	t.Helper()
	p := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func entryFor(es []CensusEntry, rel string) *CensusEntry {
	for i := range es {
		if es[i].Path == rel {
			return &es[i]
		}
	}
	return nil
}

// T005 (FR-007/008): census classifies production/test/generated and excludes
// dependencies; excluded deps are not production source.
func TestCensusClassification(t *testing.T) {
	root := t.TempDir()
	write(t, root, "app/main.go", "package main\n")
	write(t, root, "app/main_test.go", "package main\n")
	write(t, root, "app/api.pb.go", "package main\n")
	write(t, root, "web/index.ts", "export const x = 1\n")
	write(t, root, "node_modules/dep/index.js", "module.exports = {}\n") // dependency dir → excluded entirely
	write(t, root, "README.md", "# not source\n")                        // unsupported ext → not censused

	es, err := Census(root)
	if err != nil {
		t.Fatal(err)
	}
	if e := entryFor(es, "app/main.go"); e == nil || e.Classification != ClassProduction || e.Language != LangGo {
		t.Fatalf("main.go: %+v", e)
	}
	if e := entryFor(es, "app/main_test.go"); e == nil || e.Classification != ClassTest {
		t.Fatalf("test file not classified as test: %+v", e)
	}
	if e := entryFor(es, "app/api.pb.go"); e == nil || e.Classification != ClassGenerated {
		t.Fatalf("generated file not classified: %+v", e)
	}
	if e := entryFor(es, "web/index.ts"); e == nil || e.Language != LangTypeScript {
		t.Fatalf("ts file not censused: %+v", e)
	}
	// node_modules is excluded wholesale.
	for _, e := range es {
		if e.Path == "node_modules/dep/index.js" {
			t.Fatal("dependency dir must be excluded from census")
		}
	}
	// Non-source excluded.
	if entryFor(es, "README.md") != nil {
		t.Fatal("non-source file must not be censused")
	}
	// Production count excludes tests/generated (FR-008).
	prod := 0
	for _, e := range es {
		if e.Classification == ClassProduction {
			prod++
		}
	}
	if prod != 2 { // app/main.go + web/index.ts
		t.Fatalf("production count = %d, want 2", prod)
	}
}
