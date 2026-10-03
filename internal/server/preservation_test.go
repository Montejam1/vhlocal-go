package server

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"vhlocal/internal/apps"
	"vhlocal/internal/server/testsupport"
)

// hashTree returns a stable map of relative path -> content hash under dir.
func hashTree(t *testing.T, dir string) map[string]string {
	t.Helper()
	out := map[string]string{}
	_ = filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		b, _ := os.ReadFile(p)
		rel, _ := filepath.Rel(dir, p)
		out[rel] = fmt.Sprintf("%x", sha256.Sum256(b))
		return nil
	})
	return out
}

// CB-21 (Polish, SC-009): the feature's read/aggregation and registry operations
// never lose or overwrite existing reports, ledgers, or application names.
func TestPreservationOfExistingData(t *testing.T) {
	base := t.TempDir()
	ledgerDir := filepath.Join(base, "ledger")
	t.Setenv("VHLOCAL_LEDGER_DIR", ledgerDir)
	reportsDir := filepath.Join(base, "reports")
	if err := os.MkdirAll(reportsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	repoA, repoB := "/repos/alpha", "/repos/bravo"

	testsupport.SeedReport(t, reportsDir, testsupport.ReportSeed{
		Name: "alpha", Repo: repoA, Created: time.Unix(1000, 0), Readme: true,
		Findings: []map[string]any{{"severity": "High", "classification": "statically_supported"}}, CoverageStatus: "complete",
	})
	testsupport.SeedReport(t, reportsDir, testsupport.ReportSeed{
		Name: "bravo", Repo: repoB, Created: time.Unix(2000, 0), Readme: true,
		Findings: []map[string]any{{"severity": "Low", "classification": "hypothesis"}}, CoverageStatus: "degraded",
	})
	testsupport.SeedLedger(t, ledgerDir, apps.SlugFor(repoA), repoA, 2)
	if _, err := apps.Register(repoA); err != nil {
		t.Fatal(err)
	}
	if _, err := apps.SetName(apps.SlugFor(repoB), "Bravo App", repoB); err != nil {
		t.Fatal(err)
	}

	beforeReports := hashTree(t, reportsDir)
	beforeLedger := hashTree(t, ledgerDir)

	// Exercise the feature's read + registry paths.
	_ = apps.ListSummaries(reportsDir)
	if _, ok := apps.BuildDetail(apps.SlugFor(repoA), reportsDir); !ok {
		t.Fatal("detail for alpha not found")
	}
	if _, err := apps.SetName(apps.SlugFor(repoA), "Alpha App", repoA); err != nil {
		t.Fatal(err)
	}

	// Report files must be byte-identical (never overwritten by aggregation).
	if after := hashTree(t, reportsDir); !equalMaps(after, beforeReports) {
		t.Errorf("report files changed:\nbefore=%v\nafter=%v", beforeReports, after)
	}
	// The ledger file must be untouched by registry/name operations.
	if after := hashTree(t, ledgerDir); after[apps.SlugFor(repoA)+".json"] != beforeLedger[apps.SlugFor(repoA)+".json"] {
		t.Errorf("ledger file changed")
	}
	// Bravo's name survives a rename of Alpha.
	if d, ok := apps.BuildDetail(apps.SlugFor(repoB), reportsDir); !ok || d.Name != "Bravo App" {
		t.Errorf("bravo name not preserved: %+v", d)
	}
}

func equalMaps(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}
