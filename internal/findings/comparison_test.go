package findings

import (
	"path/filepath"
	"testing"

	"vhlocal/internal/server/testsupport"
)

// T016 (FR-023): with a comparable baseline and complete coverage, findings are
// classified new/recurring/fixed by stable identity.
func TestCompareCompleteCoverage(t *testing.T) {
	dir := t.TempDir()
	basePath := testsupport.SeedReport(t, dir, testsupport.ReportSeed{
		Name: "app", Model: "m1", Stamp: "2026-09-01-000000", Repo: "/r/app",
		Findings: []map[string]any{
			{"id": "F1", "stable_identity": "s1", "severity": "High", "severity_rank": 1},
			{"id": "F2", "stable_identity": "s2", "severity": "Low", "severity_rank": 4},
		},
	})
	curPath := testsupport.SeedReport(t, dir, testsupport.ReportSeed{
		Name: "app", Model: "m1", Stamp: "2026-09-02-000000", Repo: "/r/app",
		CoverageStatus: "complete",
		Findings: []map[string]any{
			{"id": "F2", "stable_identity": "s2", "severity": "Low", "severity_rank": 4},
			{"id": "F3", "stable_identity": "s3", "severity": "High", "severity_rank": 1},
		},
	})
	c := Compare(dir, filepath.Base(curPath), filepath.Base(basePath))
	if !c.Comparable {
		t.Fatalf("expected comparable: %+v", c)
	}
	if !has(c.New, "source-v1:s3") || len(c.New) != 1 {
		t.Fatalf("new = %v, want [s3]", c.New)
	}
	if !has(c.Recurring, "source-v1:s2") || len(c.Recurring) != 1 {
		t.Fatalf("recurring = %v, want [s2]", c.Recurring)
	}
	if !has(c.Fixed, "source-v1:s1") || len(c.Fixed) != 1 {
		t.Fatalf("fixed = %v, want [s1]", c.Fixed)
	}
	if len(c.UnknownFixed) != 0 {
		t.Fatalf("nothing should be unknown-incomparable under complete coverage: %v", c.UnknownFixed)
	}
}

// T016 (FR-024): under partial coverage, an absent baseline finding is NOT fixed —
// it is unknown/incomparable.
func TestComparePartialCoverageNotFixed(t *testing.T) {
	dir := t.TempDir()
	basePath := testsupport.SeedReport(t, dir, testsupport.ReportSeed{
		Name: "app", Model: "m1", Stamp: "2026-09-01-000000", Repo: "/r/app",
		Findings: []map[string]any{{"id": "F1", "stable_identity": "s1", "severity": "High", "severity_rank": 1}},
	})
	curPath := testsupport.SeedReport(t, dir, testsupport.ReportSeed{
		Name: "app", Model: "m1", Stamp: "2026-09-02-000000", Repo: "/r/app",
		CoverageStatus: "partial",
		Findings:       []map[string]any{{"id": "F9", "stable_identity": "s9", "severity": "Low", "severity_rank": 4}},
	})
	c := Compare(dir, filepath.Base(curPath), filepath.Base(basePath))
	if len(c.Fixed) != 0 {
		t.Fatalf("partial coverage must not mark anything fixed: %v", c.Fixed)
	}
	if !has(c.UnknownFixed, "source-v1:s1") {
		t.Fatalf("s1 should be unknown-incomparable: %v", c.UnknownFixed)
	}
}

// FR-023: no baseline → not comparable, with an explicit reason.
func TestCompareNoBaseline(t *testing.T) {
	dir := t.TempDir()
	cur := testsupport.SeedReport(t, dir, testsupport.ReportSeed{
		Name: "app", Model: "m1", Stamp: "2026-09-02-000000", Repo: "/r/app",
		Findings: []map[string]any{{"id": "F1", "stable_identity": "s1", "severity": "High", "severity_rank": 1}},
	})
	c := Compare(dir, filepath.Base(cur), "none")
	if c.Comparable || c.Reason != "no-baseline" {
		t.Fatalf("expected no-baseline: %+v", c)
	}
}

func has(ss []string, v string) bool {
	for _, s := range ss {
		if s == v {
			return true
		}
	}
	return false
}
