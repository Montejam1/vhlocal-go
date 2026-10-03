package apps

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"vhlocal/internal/server/testsupport"
)

// T055 (FR-028, SC-011): the preview selects ONLY entries that match the Go test
// temp-dir shape AND have zero history AND whose path is gone, each with a reason;
// a legitimate zero-scan app and a real /tmp repo are preserved; apply without the
// token changes nothing; apply writes the backup BEFORE removing exactly the
// previewed ids and touches no reports or ledgers.
func TestCleanupPreviewAndApply(t *testing.T) {
	reportsDir, ledgerDir := setup(t)
	// A real repo under /tmp that still exists (must be preserved even though the
	// path is under /tmp).
	realTmp := filepath.Join(t.TempDir(), "Test"+"Live123", "001")
	if err := os.MkdirAll(realTmp, 0o755); err != nil {
		t.Fatal(err)
	}
	// Synthetic leaks: gone paths matching the shape.
	leak1, leak2 := "/tmp/TestExecuteWritesRecords1234567/001", "/tmp/TestHunt_Parallel99/002"
	// Shape match but WITH history → preserved.
	withHist := "/tmp/TestWithHistory42/001"
	// Legitimate zero-scan app (named by the operator, path gone) → preserved.
	legit := "/repos/legit-but-unscanned"

	for _, r := range []string{leak1, leak2, withHist, legit, realTmp} {
		if _, err := Register(r); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := SetName(SlugFor(legit), "Legit", legit); err != nil {
		t.Fatal(err)
	}
	testsupport.SeedReport(t, reportsDir, testsupport.ReportSeed{
		Name: "hist", Repo: withHist, Created: time.Unix(1000, 0), Readme: true,
	})
	testsupport.SeedLedger(t, ledgerDir, SlugFor(legit), legit, 1)
	if len(loadAll()) != 5 {
		t.Fatalf("registry should hold 5 entries, got %d", len(loadAll()))
	}
	regBefore, _ := os.ReadFile(storePath())
	reportsBefore := treeHash(t, reportsDir)
	ledgerBefore := treeHash(t, ledgerDir)

	pv := PreviewSynthetic(reportsDir)
	got := map[string]bool{}
	for _, c := range pv.Candidates {
		got[c.Repo] = true
		if !strings.Contains(c.Reason, "no scan history") || !strings.Contains(c.Reason, "no longer exists") {
			t.Errorf("candidate %s lacks a full reason: %q", c.Repo, c.Reason)
		}
	}
	if len(pv.Candidates) != 2 || !got[leak1] || !got[leak2] {
		t.Fatalf("preview must select exactly the two leaks, got %+v", pv.Candidates)
	}
	if pv.PreservedCount != 3 {
		t.Errorf("preserved_count = %d, want 3", pv.PreservedCount)
	}
	if pv.PreviewToken == "" {
		t.Fatal("preview must carry a token")
	}
	// Preview changed nothing.
	if b, _ := os.ReadFile(storePath()); string(b) != string(regBefore) {
		t.Error("preview must not modify the registry")
	}

	// Apply without / with a wrong token: nothing changes, no backup.
	for _, bad := range []string{"", "nope"} {
		if _, err := Apply(reportsDir, bad); err == nil {
			t.Errorf("apply with token %q must fail", bad)
		}
	}
	if b, _ := os.ReadFile(storePath()); string(b) != string(regBefore) {
		t.Fatal("a refused apply must not modify the registry")
	}
	if backups, _ := filepath.Glob(storePath() + ".bak-*"); len(backups) != 0 {
		t.Fatalf("a refused apply must not write a backup: %v", backups)
	}

	res, err := Apply(reportsDir, pv.PreviewToken)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Removed) != 2 {
		t.Errorf("removed = %v, want the two leaks", res.Removed)
	}
	bb, err := os.ReadFile(res.BackupPath)
	if err != nil || string(bb) != string(regBefore) {
		t.Errorf("backup must be the pre-apply registry bytes (%s): %v", res.BackupPath, err)
	}
	after := loadAll()
	if len(after) != 3 {
		t.Errorf("registry should hold 3 entries after apply, got %d", len(after))
	}
	for _, keep := range []string{withHist, legit, realTmp} {
		if _, ok := after[SlugFor(keep)]; !ok {
			t.Errorf("preserved entry %s was removed", keep)
		}
	}
	if e := after[SlugFor(legit)]; e.Name != "Legit" {
		t.Errorf("operator name lost: %+v", e)
	}
	if treeHash(t, reportsDir) != reportsBefore || treeHash(t, ledgerDir) != ledgerBefore {
		t.Error("cleanup must not touch reports or ledgers")
	}
	// Idempotent: a second preview is empty and apply refuses.
	if pv2 := PreviewSynthetic(reportsDir); len(pv2.Candidates) != 0 || pv2.PreviewToken != "" {
		t.Errorf("second preview should be empty: %+v", pv2)
	}
	if _, err := Apply(reportsDir, pv.PreviewToken); err == nil {
		t.Error("stale token must be refused once the preview is empty")
	}
}

func treeHash(t *testing.T, dir string) string {
	t.Helper()
	m := map[string]string{}
	_ = filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		b, _ := os.ReadFile(p)
		rel, _ := filepath.Rel(dir, p)
		m[rel] = string(b)
		return nil
	})
	b, _ := json.Marshal(m)
	return string(b)
}
