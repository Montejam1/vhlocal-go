package attention

import (
	"testing"
	"time"

	"vhlocal/internal/findings"
	"vhlocal/internal/server/testsupport"
)

func allNeedsReview(string) string { return "needs-review" }

// q returns a queue by key.
func q(rep Report, key string) Queue {
	for _, x := range rep.Queues {
		if x.Key == key {
			return x
		}
	}
	return Queue{}
}

// T030 (FR-035/036): the supported-awaiting-review count equals its filtered
// destination, and a finding recurring across scans is counted once (dedup).
func TestSupportedAwaitingReviewCountMatchesAndDedupes(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("VHLOCAL_REVIEWS_DIR", t.TempDir())
	// Same finding (stable id s1) appears in two scans of the same app → one item.
	for _, stamp := range []string{"2026-09-01-000000", "2026-09-02-000000"} {
		testsupport.SeedReport(t, dir, testsupport.ReportSeed{
			Name: "app", Model: "m1", Stamp: stamp, Repo: "/r/app",
			Findings: []map[string]any{
				{"id": "F1", "stable_identity": "s1", "severity": "High", "severity_rank": 2, "verification_status": "supported"},
				{"id": "F2", "stable_identity": "s2", "severity": "Low", "severity_rank": 4, "verification_status": "supported"},
			},
		})
	}
	rep := Compute(dir, 7, allNeedsReview, time.Now().Unix())
	sup := q(rep, "supported_awaiting_review")
	if !sup.Available || sup.Count != 1 {
		t.Fatalf("supported Crit/High awaiting review = %d (available=%v), want 1 (s1, deduped; s2 is Low)", sup.Count, sup.Available)
	}
	// The count equals the same filter applied to the findings queue (distinct ids).
	res := findings.Search(dir, findings.Query{Evidence: "supported", Review: "needs-review", SeverityIn: []string{"Critical", "High"}}, allNeedsReview)
	if distinct(res.Rows) != sup.Count {
		t.Fatalf("queue count %d != filtered destination %d", sup.Count, distinct(res.Rows))
	}
}

// T030 (FR-035): the new-supported queue reports an explicit no-baseline note when
// no scan carries comparison data.
func TestNewSupportedNoBaselineNote(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("VHLOCAL_REVIEWS_DIR", t.TempDir())
	testsupport.SeedReport(t, dir, testsupport.ReportSeed{
		Name: "app", Model: "m1", Stamp: "2026-09-01-000000", Repo: "/r/app",
		Findings: []map[string]any{{"id": "F1", "stable_identity": "s1", "severity": "High", "severity_rank": 2, "verification_status": "supported"}},
	})
	rep := Compute(dir, 7, allNeedsReview, time.Now().Unix())
	nq := q(rep, "new_supported")
	if nq.Count != 0 || nq.Note == "" {
		t.Fatalf("expected 0 with a no-baseline note, got count=%d note=%q", nq.Count, nq.Note)
	}
}

// T030 (FR-035): incomplete/degraded scans are counted.
func TestIncompleteScansCounted(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("VHLOCAL_REVIEWS_DIR", t.TempDir())
	testsupport.SeedReport(t, dir, testsupport.ReportSeed{
		Name: "ok", Model: "m1", Stamp: "2026-09-01-000000", Repo: "/r/ok",
		ExecutionStatus: "complete", Findings: []map[string]any{},
	})
	testsupport.SeedReport(t, dir, testsupport.ReportSeed{
		Name: "bad", Model: "m1", Stamp: "2026-09-02-000000", Repo: "/r/bad",
		ExecutionStatus: "partial", Findings: []map[string]any{},
	})
	rep := Compute(dir, 7, allNeedsReview, time.Now().Unix())
	if inc := q(rep, "incomplete_scans"); inc.Count != 1 {
		t.Fatalf("incomplete scans = %d, want 1", inc.Count)
	}
}

// T030 (FR-038): stale apps counted against an editable threshold; time staleness
// is separate from coverage.
func TestStaleAppsThreshold(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("VHLOCAL_REVIEWS_DIR", t.TempDir())
	now := int64(1_000_000_000)
	old := time.Unix(now-30*86400, 0) // 30 days old
	fresh := time.Unix(now-1*86400, 0)
	testsupport.SeedReport(t, dir, testsupport.ReportSeed{Name: "old", Model: "m1", Stamp: "2026-08-01-000000", Repo: "/r/old", Created: old, Findings: []map[string]any{}})
	testsupport.SeedReport(t, dir, testsupport.ReportSeed{Name: "new", Model: "m1", Stamp: "2026-09-01-000000", Repo: "/r/new", Created: fresh, Findings: []map[string]any{}})
	rep := Compute(dir, 7, allNeedsReview, now)
	if st := q(rep, "stale_apps"); st.Count != 1 {
		t.Fatalf("stale apps (>7d) = %d, want 1", st.Count)
	}
	// A larger threshold un-stales it.
	rep2 := Compute(dir, 60, allNeedsReview, now)
	if st := q(rep2, "stale_apps"); st.Count != 0 {
		t.Fatalf("stale apps (>60d) = %d, want 0", st.Count)
	}
}

// The section always returns all six queues (independent computation).
func TestSixQueuesAlwaysPresent(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("VHLOCAL_REVIEWS_DIR", t.TempDir())
	rep := Compute(dir, 7, allNeedsReview, time.Now().Unix())
	if len(rep.Queues) != 6 {
		t.Fatalf("want 6 queues, got %d", len(rep.Queues))
	}
	if rep.StaleDays != 7 {
		t.Fatalf("stale_days = %d, want 7 default", rep.StaleDays)
	}
}
