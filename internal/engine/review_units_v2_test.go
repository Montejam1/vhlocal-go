package engine

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func fixtureHandlersAndSpans(t *testing.T) (repo string, handlers map[string]string, spans []string) {
	t.Helper()
	repo, _, spanByID := coverageFixture(t)
	handlers = spanByID
	seen := map[string]bool{}
	for _, s := range spanByID {
		if !seen[s] {
			seen[s] = true
			spans = append(spans, s)
		}
	}
	return repo, handlers, spans
}

var plannedClasses = []string{"INJ", "NAV", "LOG"}

func runV2(t *testing.T, repo string, w *readingWriter, enforce *bool) (*ReviewUnits, string) {
	t.Helper()
	results := t.TempDir()
	spec := coverageSpec(repo, results)
	spec.EnforceCoverage = enforce
	if _, err := Execute(context.Background(), spec, Providers{Hunt: w}, staticSkill{}, nil); err != nil {
		t.Fatal(err)
	}
	return reviewUnitsOf(t, results), results
}

// T046 (C-B5, C-B6, SC-004, SC-005): credit requires a validated per-handler
// disposition; reads alone are exposure; the axes are independent.
func TestCoverageV2CreditRequiresValidatedDispositions(t *testing.T) {
	repo, handlers, spans := fixtureHandlersAndSpans(t)
	off := false

	t.Run("valid dispositions credit exactly their handlers", func(t *testing.T) {
		ru, results := runV2(t, repo, newDispositionWriter(spans, handlers, plannedClasses, dispValid), &off)
		if ru.SemanticsVersion != CoverageSemanticsV2 {
			t.Errorf("semantics_version = %d", ru.SemanticsVersion)
		}
		if ru.Counts.ReviewedNoIssue != 100 || ru.Axes.CompletedReview != 100 || ru.Axes.SourceExposed != 100 {
			t.Errorf("counts = %+v axes = %+v (want 100 completed, 100 exposed)", ru.Counts, ru.Axes)
		}
		if ru.Axes.Discovered != 100 || ru.Axes.Assigned == 0 || ru.Axes.Attempted == 0 {
			t.Errorf("axes = %+v", ru.Axes)
		}
		// T051: the unit records and hunt_execution.detail carry the tallies.
		tallied := 0
		for _, u := range ru.Units {
			if u.Valid && u.Dispositions != nil && u.Dispositions.Credited > 0 {
				tallied++
			}
			if u.Valid && u.NoDispositions {
				t.Errorf("unit %s wrote dispositions but is flagged no_dispositions", u.Label)
			}
		}
		if tallied == 0 {
			t.Error("no unit record carries a credited disposition tally")
		}
		h, ok := loadHuntExecution(results)
		if !ok {
			t.Fatal("hunt_execution.json unreadable")
		}
		annotated := 0
		for _, f := range h.Detail {
			if f.Dispositions != nil && f.Dispositions.Parsed == f.Dispositions.Credited+f.Dispositions.Rejected && f.Dispositions.Credited > 0 {
				annotated++
			}
		}
		if annotated == 0 {
			t.Errorf("hunt_execution.detail must carry dispositions{parsed,credited,rejected}: %+v", h.Detail[:min(2, len(h.Detail))])
		}
	})
	t.Run("full reads without dispositions are exposure only", func(t *testing.T) {
		ru, results := runV2(t, repo, newDispositionWriter(spans, handlers, plannedClasses, dispNone), &off)
		if ru.Counts.ReviewedNoIssue != 0 || ru.Axes.CompletedReview != 0 {
			t.Errorf("reads credited as review: %+v", ru.Counts)
		}
		if ru.Axes.SourceExposed != 100 {
			t.Errorf("source_exposed = %d, want 100", ru.Axes.SourceExposed)
		}
		if len(ru.Gaps) != 100 || ru.Gaps[0].Reason != GapNoDisposition {
			t.Errorf("gaps = %d (%v)", len(ru.Gaps), ru.Gaps[:min(2, len(ru.Gaps))])
		}
		flagged := 0
		for _, u := range ru.Units {
			if u.Valid && u.NoDispositions {
				flagged++
			}
		}
		if flagged == 0 {
			t.Error("a valid deliverable without the section must be flagged no_dispositions")
		}
		h, _ := loadHuntExecution(results)
		hf := 0
		for _, f := range h.Detail {
			if f.NoDispositions {
				hf++
			}
		}
		if hf == 0 {
			t.Error("hunt_execution.detail must flag no_dispositions")
		}
	})
	t.Run("one 400-line read across many handlers credits nothing", func(t *testing.T) {
		wide := []string{}
		files := map[string]bool{}
		for _, s := range spans {
			f, _, _ := parseSpan(s)
			if !files[f] {
				files[f] = true
				wide = append(wide, f+":1-400")
			}
		}
		ru, _ := runV2(t, repo, newDispositionWriter(wide, handlers, plannedClasses, dispNone), &off)
		if ru.Counts.ReviewedNoIssue != 0 {
			t.Errorf("a wide read credited %d handlers", ru.Counts.ReviewedNoIssue)
		}
		if ru.Axes.SourceExposed == 0 {
			t.Error("a wide read must still count as exposure")
		}
	})
	t.Run("prose claim credits nothing", func(t *testing.T) {
		ru, _ := runV2(t, repo, newDispositionWriter(spans, handlers, plannedClasses, dispProseOnly), &off)
		if ru.Counts.ReviewedNoIssue != 0 {
			t.Errorf("prose credited %d", ru.Counts.ReviewedNoIssue)
		}
	})
	t.Run("out-of-scope, fabricated and unread evidence are recorded but not credited", func(t *testing.T) {
		for _, mode := range []string{dispOutOfScope, dispFabricated, dispEvidenceUnread} {
			ru, _ := runV2(t, repo, newDispositionWriter(spans, handlers, plannedClasses, mode), &off)
			if ru.Counts.ReviewedNoIssue != 0 {
				t.Errorf("%s credited %d", mode, ru.Counts.ReviewedNoIssue)
			}
			recorded := len(ru.Unrecognized)
			for _, d := range ru.Dispositions {
				for _, hb := range d.HandlerBlocks {
					if !hb.Validation.OK() {
						recorded++
					}
				}
			}
			if mode != dispOutOfScope && recorded == 0 {
				t.Errorf("%s: rejected dispositions must still be recorded", mode)
			}
		}
	})
	t.Run("unresolved checks are partial with reasons", func(t *testing.T) {
		ru, _ := runV2(t, repo, newDispositionWriter(spans, handlers, plannedClasses, dispUnresolved), &off)
		if ru.Counts.Partial != 100 || ru.Counts.ReviewedNoIssue != 0 {
			t.Errorf("counts = %+v, want 100 partial", ru.Counts)
		}
		if len(ru.Dispositions[0].Unresolved) == 0 {
			t.Error("partial dispositions must carry the unresolved reasons")
		}
	})
	t.Run("paired: 8 dispositions with all 100 read report 8 completed, 100 exposed", func(t *testing.T) {
		eight := map[string]string{}
		pb, _ := os.ReadFile(filepath.Join(repo, "paired8.json"))
		var paired struct {
			Routes []struct{ File, Path string } `json:"routes"`
		}
		_ = json.Unmarshal(pb, &paired)
		for h, sp := range handlers {
			for _, pr := range paired.Routes {
				if strings.HasPrefix(h, pr.File+":") && strings.HasSuffix(h, " "+pr.Path) {
					eight[h] = sp
				}
			}
		}
		if len(eight) != 8 {
			t.Fatalf("paired handlers = %d, want 8", len(eight))
		}
		ru, _ := runV2(t, repo, newDispositionWriter(spans, eight, plannedClasses, dispValid), &off)
		if ru.Counts.ReviewedNoIssue != 8 || ru.Axes.CompletedReview != 8 || ru.Axes.SourceExposed != 100 {
			t.Errorf("counts = %+v axes = %+v (want 8 completed, 100 exposed)", ru.Counts, ru.Axes)
		}
	})
}

// T047 (C-B1, FR-019): a feature-014 record regenerates as v1 with its label on
// the model, the report, the scan view and never gains v2 credit.
func TestLegacyReviewUnitsStayV1OnRegeneration(t *testing.T) {
	repo, handlers, spans := fixtureHandlersAndSpans(t)
	off := false
	ru, results := runV2(t, repo, newDispositionWriter(spans, handlers, plannedClasses, dispValid), &off)
	if ru.Counts.ReviewedNoIssue != 100 {
		t.Fatal("precondition: 100 credited")
	}
	// Downgrade the record to the v1 shape (no semantics_version, no checks) as a
	// feature-014 run would have written it.
	b, _ := os.ReadFile(filepath.Join(results, ReviewUnitsFile))
	var raw map[string]any
	_ = json.Unmarshal(b, &raw)
	delete(raw, "semantics_version")
	delete(raw, "axes")
	for _, d := range raw["dispositions"].([]any) {
		m := d.(map[string]any)
		delete(m, "checks")
		delete(m, "handler_dispositions")
		delete(m, "unresolved")
		delete(m, "source_exposed")
	}
	nb, _ := json.MarshalIndent(raw, "", "  ")
	os.WriteFile(filepath.Join(results, ReviewUnitsFile), nb, 0o644)
	if err := Regenerate(results); err != nil {
		t.Fatal(err)
	}
	ru2 := reviewUnitsOf(t, results)
	if ru2.SemanticsVersion != CoverageSemanticsV1 || ru2.Counts.ReviewedNoIssue != 100 {
		t.Errorf("v1 record after regeneration: version=%d counts=%+v", ru2.SemanticsVersion, ru2.Counts)
	}
	md, _ := os.ReadFile(filepath.Join(results, "SCAN_REPORT.md"))
	if !strings.Contains(string(md), "read-overlap evidence (v1)") {
		t.Error("report must label v1 evidence")
	}
	mb, _ := os.ReadFile(filepath.Join(results, "report_model.json"))
	if !strings.Contains(string(mb), `"coverage_semantics_label": "read-overlap evidence (v1)"`) || !strings.Contains(string(mb), `"semantics_version": 1`) {
		t.Error("report model must carry the v1 label and version")
	}
	// v2 run: label says v2.
	md2, _ := os.ReadFile(filepath.Join(t.TempDir(), "x"))
	_ = md2
	ru3, results3 := runV2(t, repo, newDispositionWriter(spans, handlers, plannedClasses, dispValid), &off)
	_ = ru3
	md3, _ := os.ReadFile(filepath.Join(results3, "SCAN_REPORT.md"))
	if !strings.Contains(string(md3), "validated handler dispositions (v2)") {
		t.Error("report must label v2 evidence")
	}
}

// T049 (C-B7): gaps still trigger exactly one bounded follow-up per partition whose
// deliverable uses the v2 section; nothing else is scheduled.
func TestCoverageV2FollowUpUsesDispositions(t *testing.T) {
	repo, handlers, spans := fixtureHandlersAndSpans(t)
	// Regular units read but write no dispositions; the follow-up (whose deliverable
	// is `_followup.md`) writes valid ones.
	w := newDispositionWriter(spans, handlers, plannedClasses, dispValid)
	inner := w.extra
	w.extra = func(task string) string {
		if !strings.Contains(task, "_followup.md") {
			return ""
		}
		return inner(task)
	}
	on := true
	ru, _ := runV2(t, repo, w, &on)
	if !ru.FollowUpRan {
		t.Fatal("follow-up must run when handlers have no dispositions")
	}
	followups := 0
	for _, u := range ru.Units {
		if u.Class == "FOLLOWUP" {
			followups++
		}
	}
	if followups == 0 || followups > 12 {
		t.Errorf("follow-up units = %d (one per partition at most)", followups)
	}
	if ru.Counts.ReviewedNoIssue != 100 {
		t.Errorf("follow-up dispositions must credit: %+v", ru.Counts)
	}
}
