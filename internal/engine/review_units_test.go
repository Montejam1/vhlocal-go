package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"vhlocal/internal/inventory"
)

// coverageFixture enumerates testdata/coverage100 and resolves each route's handler
// span, returning the repo path, the routes, and "file:start-end" span strings keyed
// by route id. JS/TS files are present but outside the current inventory (feature
// 012's JS/TS stage is later), so the 100 come from Python + Go.
func coverageFixture(t *testing.T) (string, []inventory.Route, map[string]string) {
	t.Helper()
	repo := filepath.Join(repoRoot(t), "testdata", "coverage100")
	routes, err := inventory.EnumerateRoutes(repo)
	if err != nil {
		t.Fatal(err)
	}
	if len(routes) != 100 {
		t.Fatalf("fixture must enumerate exactly 100 entry points (Python+Go), got %d", len(routes))
	}
	spans := newHandlerSpans(repo)
	out := map[string]string{}
	for _, r := range routes {
		sc := spans.scopeFor(r)
		if !sc.Found {
			t.Fatalf("handler span unresolved for %s", RouteID(r))
		}
		out[RouteID(r)] = fmt.Sprintf("%s:%d-%d", r.File, sc.Start, sc.End)
	}
	return repo, routes, out
}

func coverageSpec(repo, results string) ScanSpec {
	sc := brokenSpec(repo, results)
	sc.Phases = []string{"1", "2"} // hunt only; no verification needed to test coverage
	sc.MaxPartitions = 12          // 10 subsystems must all be assigned (no over-cap uncovered)
	return sc
}

func ledgerOf(t *testing.T, results string) inventory.CoverageLedger {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(results, "coverage_ledger.json"))
	if err != nil {
		t.Fatal(err)
	}
	var cl inventory.CoverageLedger
	if err := json.Unmarshal(b, &cl); err != nil {
		t.Fatal(err)
	}
	return cl
}

func reviewUnitsOf(t *testing.T, results string) *ReviewUnits {
	t.Helper()
	ru, ok := loadReviewUnits(results)
	if !ok {
		t.Fatal("review_units.json missing")
	}
	return ru
}

// SC-004 (FR-010..013, T030): a provider that READS every assigned handler span and
// writes valid deliverables — with findings located in exactly 8 handlers — yields
// 100/100 evidenced dispositions: 8 reviewed_with_findings + 92 reviewed_no_issue,
// across Python and Go, sibling handlers, and duplicate route names.
func TestCoverage100AllReviewedWithEvidence(t *testing.T) {
	repo, routes, spans := coverageFixture(t)
	all := make([]string, 0, len(spans))
	for _, s := range spans {
		all = append(all, s)
	}
	rw := newDispositionWriter(all, spans, plannedClasses, dispValid) // feature 015: credit needs dispositions
	// Plant an authorization finding (CWE-862) inside the first handler of 8 files
	// (Python and Go), and a verification plan that supports each through the real
	// evidence contract — findings only become findings once VERIFIED (2b), so the
	// run includes phase 2b (candidate-bound, fail-closed pipeline).
	plans := map[string]verifyPlan{}
	planted := 0
	hs := newHandlerSpans(repo)
	for _, r := range routes {
		if planted >= 8 || r.Path == "/health" {
			continue
		}
		if _, done := rw.findings[r.File]; done {
			continue
		}
		sc := hs.scopeFor(r)
		loc := fmt.Sprintf("%s:%d", r.File, sc.Start+1) // inside the span
		entry := r.Method + " " + r.Path
		rw.findings[r.File] = plantedFinding{Location: loc, CWE: "CWE-862", EntryPoint: entry, Title: "Missing authorization on " + entry}
		plans[loc] = verifyPlan{File: r.File, Start: sc.Start, End: sc.End, EntryPoint: entry}
		planted++
	}
	results := t.TempDir()
	spec := coverageSpec(repo, results)
	spec.Phases = []string{"1", "2", "2b"}
	if _, err := Execute(context.Background(), spec, Providers{Hunt: newVerifyingWriter(rw, plans)}, staticSkill{}, nil); err != nil {
		t.Fatal(err)
	}
	ru := reviewUnitsOf(t, results)
	if len(ru.Assignments) != 100 {
		t.Errorf("assignments = %d, want 100", len(ru.Assignments))
	}
	for _, a := range ru.Assignments {
		if a.UnitID == "" {
			t.Errorf("route %s unassigned: %s", a.RouteID, a.Reason)
		}
	}
	c := ru.Counts
	if c.ReviewedWithFindings != 8 || c.ReviewedNoIssue != 92 {
		t.Errorf("dispositions: with_findings=%d no_issue=%d partial=%d failed=%d skipped=%d unsupported=%d not_reviewed=%d (want 8/92)",
			c.ReviewedWithFindings, c.ReviewedNoIssue, c.Partial, c.Failed, c.Skipped, c.Unsupported, c.NotReviewed)
	}
	cl := ledgerOf(t, results)
	if cl.Reviewed != 100 || cl.NotReviewed != 0 || !cl.Complete {
		t.Errorf("ledger reviewed=%d not_reviewed=%d complete=%v counts=%v (want 100/0/true)", cl.Reviewed, cl.NotReviewed, cl.Complete, cl.Counts)
	}
	if cl.Counts["reviewed_no_issue"] != 92 || cl.Counts["finding_emitted"] != 8 {
		t.Errorf("ledger counts = %v, want finding_emitted=8 reviewed_no_issue=92", cl.Counts)
	}
	if len(ru.Gaps) != 0 {
		t.Errorf("no gaps expected, got %d: %+v", len(ru.Gaps), ru.Gaps[:min(3, len(ru.Gaps))])
	}
}

// SC-005 (FR-014, T031): a provider that reads ONLY the 8 paired handlers stays
// 8/100 with 92 explained gaps. A prose "reviewed everything" claim, a read outside
// any handler span, and a sibling's finding never mark other routes reviewed.
func TestCoveragePaired8StaysHonest(t *testing.T) {
	repo, routes, spans := coverageFixture(t)
	var paired struct {
		Routes []struct{ File, Path string } `json:"routes"`
	}
	b, _ := os.ReadFile(filepath.Join(repo, "paired8.json"))
	if err := json.Unmarshal(b, &paired); err != nil {
		t.Fatal(err)
	}
	var read []string
	want := map[string]bool{}
	eight := map[string]string{}
	for _, p := range paired.Routes {
		for _, r := range routes {
			if r.File == p.File && r.Path == p.Path {
				read = append(read, spans[RouteID(r)])
				want[RouteID(r)] = true
				eight[RouteID(r)] = spans[RouteID(r)]
			}
		}
	}
	if len(read) != 8 {
		t.Fatalf("paired8 resolved %d routes, want 8", len(read))
	}
	// Plus reads that must NOT count: file header lines (outside any handler span).
	read = append(read, "svc05/routes.py:1-3", "gosvc/svc10/routes.go:1-6")
	// Feature 015: credit needs a validated disposition per handler, not a read.
	rw := newDispositionWriter(read, eight, plannedClasses, dispValid)
	rw.proseClaim = true // "reviewed everything" prose without reads
	results := t.TempDir()
	if _, err := Execute(context.Background(), coverageSpec(repo, results), Providers{Hunt: rw}, staticSkill{}, nil); err != nil {
		t.Fatal(err)
	}
	ru := reviewUnitsOf(t, results)
	if ru.Counts.ReviewedNoIssue != 8 || ru.Counts.ReviewedWithFindings != 0 {
		t.Errorf("want exactly 8 reviewed_no_issue, got no_issue=%d with_findings=%d", ru.Counts.ReviewedNoIssue, ru.Counts.ReviewedWithFindings)
	}
	for _, d := range ru.Dispositions {
		if d.Disposition == RevNoIssue && !want[d.RouteID] {
			t.Errorf("route %s marked reviewed without being read (prose/out-of-span/sibling must not count)", d.RouteID)
		}
	}
	if len(ru.Gaps) != 92 {
		t.Errorf("gaps = %d, want 92 explained gaps", len(ru.Gaps))
	}
	for _, g := range ru.Gaps {
		if g.Reason == "" {
			t.Errorf("gap %s has no reason", g.RouteID)
		}
	}
	cl := ledgerOf(t, results)
	if cl.Reviewed != 8 || cl.NotReviewed != 92 || cl.Complete {
		t.Errorf("ledger reviewed=%d not_reviewed=%d complete=%v (want 8/92/false)", cl.Reviewed, cl.NotReviewed, cl.Complete)
	}
}

// FR-015 (T032): with enforcement ON, gaps get ONE bounded follow-up unit per
// partition whose reads then close them; with enforcement OFF no follow-up runs but
// the gaps are still computed and disclosed.
func TestCoverageEnforcementFollowUp(t *testing.T) {
	repo, _, spans := coverageFixture(t)
	all := make([]string, 0, len(spans))
	for _, s := range spans {
		all = append(all, s)
	}
	t.Run("enforcement on schedules bounded follow-up", func(t *testing.T) {
		rw := newDispositionWriter(all, spans, plannedClasses, dispValid)
		rw.followUpOnly = true // main units read nothing; follow-up units read everything and record dispositions
		results := t.TempDir()
		if _, err := Execute(context.Background(), coverageSpec(repo, results), Providers{Hunt: rw}, staticSkill{}, nil); err != nil {
			t.Fatal(err)
		}
		ru := reviewUnitsOf(t, results)
		if !ru.FollowUpRan {
			t.Fatal("follow-up should have run with enforcement on")
		}
		followups := 0
		for _, u := range ru.Units {
			if u.Class == "FOLLOWUP" {
				followups++
			}
		}
		if followups == 0 || followups > 10 {
			t.Errorf("expected one bounded follow-up per partition (<=10), got %d", followups)
		}
		if ru.Counts.ReviewedNoIssue != 100 {
			t.Errorf("follow-up reads should close the gaps: reviewed_no_issue=%d gaps=%d", ru.Counts.ReviewedNoIssue, len(ru.Gaps))
		}
	})
	t.Run("enforcement off still discloses gaps", func(t *testing.T) {
		rw := newDispositionWriter(all, spans, plannedClasses, dispValid)
		rw.followUpOnly = true
		off := false
		spec := coverageSpec(repo, t.TempDir())
		spec.EnforceCoverage = &off
		if _, err := Execute(context.Background(), spec, Providers{Hunt: rw}, staticSkill{}, nil); err != nil {
			t.Fatal(err)
		}
		ru := reviewUnitsOf(t, spec.ResultsDir)
		if ru.FollowUpRan {
			t.Error("enforcement off must not schedule follow-up units")
		}
		if len(ru.Gaps) != 100 {
			t.Errorf("gaps must still be disclosed with enforcement off: got %d, want 100", len(ru.Gaps))
		}
		for _, g := range ru.Gaps {
			if g.Reason != GapNotAttempted {
				t.Errorf("gap reason = %q, want %q", g.Reason, GapNotAttempted)
				break
			}
		}
	})
}

// FR-013/016 (T033): verification is a separate axis from review; regenerating an
// older scan WITHOUT review_units.json yields no reviewed_no_issue (nothing is
// invented); evidence recorded at a different revision is stale and ignored.
func TestCoverageAxesAndRegenerationHonesty(t *testing.T) {
	repo, _, spans := coverageFixture(t)
	all := make([]string, 0, len(spans))
	for _, s := range spans {
		all = append(all, s)
	}
	results := t.TempDir()
	if _, err := Execute(context.Background(), coverageSpec(repo, results), Providers{Hunt: newDispositionWriter(all, spans, plannedClasses, dispValid)}, staticSkill{}, nil); err != nil {
		t.Fatal(err)
	}
	if ledgerOf(t, results).Counts["reviewed_no_issue"] != 100 {
		t.Fatal("precondition: live run should be fully reviewed")
	}
	// Stale revision: rewrite review_units.json with another revision → regenerate →
	// no reviewed_no_issue may survive.
	ru := reviewUnitsOf(t, results)
	ru.Revision = "deadbeef-other-revision"
	if err := writeReviewUnits(results, ru); err != nil {
		t.Fatal(err)
	}
	if err := Regenerate(results); err != nil {
		t.Fatal(err)
	}
	if n := ledgerOf(t, results).Counts["reviewed_no_issue"]; n != 0 {
		t.Errorf("stale-revision evidence must not count: reviewed_no_issue=%d", n)
	}
	// Older scan: no review_units.json at all → regeneration invents nothing.
	os.Remove(filepath.Join(results, ReviewUnitsFile))
	if err := Regenerate(results); err != nil {
		t.Fatal(err)
	}
	if n := ledgerOf(t, results).Counts["reviewed_no_issue"]; n != 0 {
		t.Errorf("regeneration without records must not invent review: reviewed_no_issue=%d", n)
	}
}
