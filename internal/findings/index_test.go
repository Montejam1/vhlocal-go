package findings

import (
	"testing"

	"vhlocal/internal/server/testsupport"
)

// helper: a disposition lookup that reports every finding as needs-review.
func needsReview(string) string { return "needs-review" }

// T006 (FR-001): the queue includes findings from scans that ran with the ledger
// disabled — findings come from findings.json, and no ledger is ever seeded here.
func TestIndexIncludesLedgerDisabledScans(t *testing.T) {
	dir := t.TempDir()
	testsupport.SeedReport(t, dir, testsupport.ReportSeed{
		Name: "app", Model: "m1", Stamp: "2026-09-01-000000", Repo: "/r/app",
		Findings: []map[string]any{
			{"id": "F1", "stable_identity": "s1", "severity": "High", "severity_rank": 1,
				"location": "a.go:10", "verification_status": "supported", "test_status": "passed"},
			{"id": "F2", "stable_identity": "s2", "severity": "Low", "severity_rank": 4,
				"location": "b.go:20", "assessment": "unresolved"},
		},
	})
	rows := Index(dir, needsReview)
	if len(rows) != 2 {
		t.Fatalf("indexed %d rows, want 2 (ledger-disabled scan must be included)", len(rows))
	}
	// Evidence assessment + reproduction state are mapped honestly.
	var f1 Row
	for _, r := range rows {
		if r.StableID == "source-v1:s1" {
			f1 = r
		}
	}
	if f1.Evidence != "supported" || f1.Reproduction != "reproduced" {
		t.Fatalf("F1 evidence=%q repro=%q", f1.Evidence, f1.Reproduction)
	}
}

// T006 (FR-007): filtered-empty is distinguishable from no-findings.
func TestSearchFilteredEmptyVsNoFindings(t *testing.T) {
	dir := t.TempDir()
	testsupport.SeedReport(t, dir, testsupport.ReportSeed{
		Name: "app", Model: "m1", Stamp: "2026-09-01-000000", Repo: "/r/app",
		Findings: []map[string]any{{"id": "F1", "stable_identity": "s1", "severity": "High", "severity_rank": 1, "location": "a.go:1"}},
	})
	// A filter that matches nothing → FilteredEmpty, not NoFindings.
	res := Search(dir, Query{Severity: "Critical"}, needsReview)
	if res.Total != 0 || !res.FilteredEmpty || res.NoFindings {
		t.Fatalf("expected filtered-empty: total=%d filteredEmpty=%v noFindings=%v", res.Total, res.FilteredEmpty, res.NoFindings)
	}
	// An empty reports dir → NoFindings, not FilteredEmpty.
	empty := Search(t.TempDir(), Query{}, needsReview)
	if !empty.NoFindings || empty.FilteredEmpty {
		t.Fatalf("expected no-findings on empty dir: %+v", empty)
	}
	// A matching filter returns the row.
	hit := Search(dir, Query{Severity: "High"}, needsReview)
	if hit.Total != 1 {
		t.Fatalf("expected 1 High row, got %d", hit.Total)
	}
}

// T008 (API-F2 / FR-010): Detail round-trips an occurrence and reports not-found.
func TestDetailRoundTripAndMissing(t *testing.T) {
	dir := t.TempDir()
	testsupport.SeedReport(t, dir, testsupport.ReportSeed{
		Name: "app", Model: "m1", Stamp: "2026-09-01-000000", Repo: "/r/app",
		Findings: []map[string]any{{"id": "F1", "stable_identity": "s1", "severity": "High", "severity_rank": 1, "location": "a.go:1"}},
	})
	rows := Index(dir, needsReview)
	occ := rows[0].Occurrence
	row, raw, ok := Detail(dir, occ, needsReview)
	if !ok || row.Occurrence != occ || raw["id"] != "F1" {
		t.Fatalf("detail round-trip failed: ok=%v row=%+v", ok, row)
	}
	if _, _, ok := Detail(dir, "nope~missing", needsReview); ok {
		t.Fatal("missing occurrence must return ok=false")
	}
}
