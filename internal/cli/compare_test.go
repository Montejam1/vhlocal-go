package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"vhlocal/internal/engine"
	"vhlocal/internal/verification"
)

func TestVerifierComparisonDryRunNeverContactsEndpoint(t *testing.T) {
	repo := t.TempDir()
	os.WriteFile(filepath.Join(repo, "a.py"), []byte("pass\n"), 0600)
	revision, e := engine.SourceFingerprint(repo)
	if e != nil {
		t.Fatal(e)
	}
	root := t.TempDir()
	frozen := filepath.Join(root, "manifest.json")
	b, _ := json.Marshal(verification.Manifest{Repo: repo, Revision: revision})
	os.WriteFile(frozen, b, 0600)
	out := filepath.Join(root, "comparison")
	if code := compareCmd([]string{"--manifest", frozen, "--repo", repo, "--revision", revision, "--out", out, "--dry-run", "--variant", "model=planned,backend=ollama,host=http://127.0.0.1:1"}); code != ExitOK {
		t.Fatal(code)
	}
	b, e = os.ReadFile(filepath.Join(out, "comparison.json"))
	if e != nil {
		t.Fatal(e)
	}
	var result engine.ComparisonResult
	json.Unmarshal(b, &result)
	if !result.NotRun || len(result.Variants) != 1 || !result.Variants[0].NotRun || result.Variants[0].Endpoint != "http://127.0.0.1:1" {
		t.Fatalf("planned variant not disclosed: %+v", result)
	}
}
