package engine

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// Feature 013 (FR-025, SC-011): validation evidence records the build identity of
// the RUNNING engine (engine_version in scan_meta), so a green source test is not
// mistaken for a fixed running application. Combined with the shipped-form contract
// test (which reads the EMBEDDED vhlocal.WebFS, not loose source), this
// distinguishes running-engine vs embedded-asset identity.
func TestScanMetaRecordsBuildIdentity(t *testing.T) {
	repo := filepath.Join(repoRoot(t), "testdata", "vulnapp")
	results := t.TempDir()
	spec := brokenSpec(repo, results)
	spec.EngineVersion = "1.2.3-test"
	if _, err := Execute(context.Background(), spec, Providers{Hunt: &pathWriter{model: "m"}}, staticSkill{}, nil); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(results, ScanMetaFile))
	if err != nil {
		t.Fatal(err)
	}
	var meta map[string]any
	if err := json.Unmarshal(b, &meta); err != nil {
		t.Fatal(err)
	}
	if meta["engine_version"] != "1.2.3-test" {
		t.Errorf("scan_meta must record the running build identity (engine_version), got %v", meta["engine_version"])
	}
}
