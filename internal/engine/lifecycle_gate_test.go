package engine

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"
)

// T048 (C-B8): with an incomplete v2 ledger a prior finding absent from the new scan
// is `unknown_incomparable`, never `fixed`/`not_observed`; a complete ledger keeps
// the existing reconciliation.
func TestLifecycleFixedRequiresCompleteCoverage(t *testing.T) {
	repo, handlers, spans := fixtureHandlersAndSpans(t)
	off := false
	// Prior run: a supported finding exists (planted + verified) with full coverage.
	rw := newDispositionWriter(spans, handlers, plannedClasses, dispValid)
	_, routes, _ := coverageFixture(t)
	hs := newHandlerSpans(repo)
	plans := map[string]verifyPlan{}
	for _, r := range routes {
		if r.File == "svc02/routes.py" && r.Path == "/svc02/items" {
			sc := hs.scopeFor(r)
			loc := fmt.Sprintf("%s:%d", filepath.ToSlash(r.File), sc.Start+1)
			entry := r.Method + " " + r.Path
			rw.findings[r.File] = plantedFinding{Location: loc, CWE: "CWE-862", EntryPoint: entry, Title: "Missing authorization on " + entry}
			plans[loc] = verifyPlan{File: r.File, Start: sc.Start, End: sc.End, EntryPoint: entry}
		}
	}
	base := t.TempDir()
	prior := filepath.Join(base, "prior")
	spec := coverageSpec(repo, prior)
	spec.Phases = []string{"1", "2", "2b"}
	spec.EnforceCoverage = &off
	if _, err := Execute(context.Background(), spec, Providers{Hunt: newVerifyingWriter(rw, plans)}, staticSkill{}, nil); err != nil {
		t.Fatal(err)
	}
	doc := loadFindings(t, prior)
	if n := len(doc["findings"].([]any)); n == 0 {
		t.Fatal("precondition: the prior run has a finding")
	}

	// Current run: complete execution, NO findings, but coverage INCOMPLETE (no
	// dispositions) → the missing finding is unknown_incomparable, not fixed.
	cur := filepath.Join(base, "current")
	spec2 := coverageSpec(repo, cur)
	spec2.Phases = []string{"1", "2", "2b"}
	spec2.EnforceCoverage = &off
	if _, err := Execute(context.Background(), spec2, Providers{Hunt: newDispositionWriter(spans, handlers, plannedClasses, dispNone)}, staticSkill{}, nil); err != nil {
		t.Fatal(err)
	}
	lc := loadFindings(t, cur)["lifecycle"].(map[string]any)
	if lc["comparison_status"] != "unknown_incomparable" {
		t.Errorf("incomplete coverage must not claim fixed: %v", lc["comparison_status"])
	}
	if fixed, _ := lc["fixed"].(float64); fixed != 0 {
		t.Errorf("fixed = %v, want 0", lc["fixed"])
	}

	// Current run with COMPLETE v2 coverage and no findings → reconciliation runs.
	cur2 := filepath.Join(base, "current2")
	spec3 := coverageSpec(repo, cur2)
	spec3.Phases = []string{"1", "2", "2b"}
	spec3.EnforceCoverage = &off
	if _, err := Execute(context.Background(), spec3, Providers{Hunt: newDispositionWriter(spans, handlers, plannedClasses, dispValid)}, staticSkill{}, nil); err != nil {
		t.Fatal(err)
	}
	lc2 := loadFindings(t, cur2)["lifecycle"].(map[string]any)
	if lc2["comparison_status"] == "unknown_incomparable" || lc2["comparison_status"] == "suppressed_unreliable_run" {
		t.Errorf("complete coverage must reconcile: %v", lc2["comparison_status"])
	}
}
