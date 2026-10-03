package verification

import (
	"os"
	"path/filepath"
	"testing"

	"vhlocal/internal/consolidate"
)

// Feature 015 (R5, T059): the manifest REPORTS likely equivalence (same established
// anchor) on every candidate — nothing is skipped or merged because of it.
func TestManifestReportsLikelyGroupWithoutSkipping(t *testing.T) {
	repo, root := t.TempDir(), t.TempDir()
	src := "class First:\n    def query(self, x):\n        conn.execute(x)\n        conn.execute(x)\n\nclass Second:\n    def query(self, x):\n        conn.execute(x)\n"
	if err := os.WriteFile(filepath.Join(repo, "app.py"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	a, b, c := candFinding("app.py:3"), candFinding("app.py:4"), candFinding("app.py:8")
	a.ID, b.ID, c.ID = "A", "B", "C"
	m, err := BuildManifest(root, repo, "rev", []consolidate.Finding{a, b, c})
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Candidates) != 3 {
		t.Fatalf("likely groups must not drop candidates: %d", len(m.Candidates))
	}
	lg := map[string]string{}
	for _, cand := range m.Candidates {
		if cand.LikelyGroup == "" {
			t.Errorf("candidate %s has no likely_group", cand.ID)
		}
		lg[cand.Finding.ID] = cand.LikelyGroup
	}
	// A and B sit on adjacent execute() sinks in one function (one statement block);
	// C is another function.
	if lg["A"] != lg["B"] || lg["A"] == lg["C"] {
		t.Errorf("likely groups = %v", lg)
	}
}
