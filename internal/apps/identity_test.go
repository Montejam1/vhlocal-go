package apps

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestIdentityDoesNotMergeBasenamesOrLegacyResults(t *testing.T) {
	root, _ := setup(t)
	repos := []string{filepath.Join(t.TempDir(), "shop"), filepath.Join(t.TempDir(), "shop")}
	for i, repo := range repos {
		dir := filepath.Join(root, []string{"one", "two"}[i])
		os.MkdirAll(dir, 0700)
		b, _ := json.Marshal(map[string]any{"repo": repo, "app_slug": SlugFor(repo), "schema": "partial", "status": "running"})
		os.WriteFile(filepath.Join(dir, "scan_meta.json"), b, 0600)
	}
	for _, name := range []string{"shop_VULNHUNT_RESULTS_m_2026-09-28-000000", "shop_VULNHUNT_RESULTS_m_2026-09-29-000000"} {
		os.MkdirAll(filepath.Join(root, name), 0700)
		os.WriteFile(filepath.Join(root, name, "findings.json"), []byte(`{"findings":[]}`), 0600)
	}
	list := ListSummaries(root)
	if len(list) != 4 {
		t.Fatalf("distinct histories merged/hidden: %+v", list)
	}
	seen := map[string]bool{}
	ambiguous := 0
	for _, a := range list {
		if seen[a.Slug] {
			t.Fatal("duplicate slug")
		}
		seen[a.Slug] = true
		d, ok := BuildDetail(a.Slug, root)
		if !ok || len(d.ScanHistory) != 1 {
			t.Fatalf("history: %+v", d)
		}
		if a.AmbiguousMapping {
			ambiguous++
			if len(d.Ambiguous) != 1 {
				t.Fatal("legacy mapping not disclosed")
			}
		}
	}
	if ambiguous != 2 || !seen[SlugFor(repos[0])] || !seen[SlugFor(repos[1])] {
		t.Fatalf("identities: %+v", list)
	}
}
