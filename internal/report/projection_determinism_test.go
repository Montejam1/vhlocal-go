package report

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// T015 (FR-026, C-C10): the projection is deterministic. Two builds from identical
// records produce byte-identical JSON, so regeneration reproduces the same report and a
// diff in a saved report always means the records changed.
func TestProjectionIsDeterministic(t *testing.T) {
	a := BuildModel(fixture016Input(t))
	b := BuildModel(fixture016Input(t))
	if a.Presentation == nil || b.Presentation == nil {
		t.Fatal("BuildModel produced no presentation projection")
	}
	ja, err := json.Marshal(a.Presentation)
	if err != nil {
		t.Fatal(err)
	}
	jb, err := json.Marshal(b.Presentation)
	if err != nil {
		t.Fatal(err)
	}
	if string(ja) != string(jb) {
		t.Error("two builds from identical records produced different projections")
	}

	// Writing twice into separate temporary directories is byte-identical too. Writes go
	// only to t.TempDir(); nothing touches an operator store (FR-028, C-C13).
	first := writeModelTo(t, a)
	second := writeModelTo(t, b)
	if first != second {
		t.Error("report_model.json differs across identical builds")
	}
}

// T013/T015: the persisted model carries the projection and its version, so every
// surface can read it and a legacy report is distinguishable from a current one.
func TestPersistedModelCarriesProjection(t *testing.T) {
	m := BuildModel(fixture016Input(t))
	dir := t.TempDir()
	if _, err := WriteModel(m, dir); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, ModelFile))
	if err != nil {
		t.Fatal(err)
	}
	var loaded ReportModel
	if err := json.Unmarshal(raw, &loaded); err != nil {
		t.Fatal(err)
	}
	if loaded.Presentation == nil {
		t.Fatal("the persisted model has no presentation projection")
	}
	p := loaded.Presentation
	if p.Version != PresentationVersion {
		t.Errorf("presentation version = %d, want %d", p.Version, PresentationVersion)
	}
	base := loadFixture016Baseline(t)
	if p.Counts.IssuesToFix != base.Counts.EstablishedGroups {
		t.Errorf("issues_to_fix = %d, want %d", p.Counts.IssuesToFix, base.Counts.EstablishedGroups)
	}
	if p.Counts.Detections != base.Counts.SupportedDetections {
		t.Errorf("detections = %d, want %d", p.Counts.Detections, base.Counts.SupportedDetections)
	}
	if p.Counts.NeedsReview != base.Counts.NeedsReviewTotal {
		t.Errorf("needs_review = %d, want %d", p.Counts.NeedsReview, base.Counts.NeedsReviewTotal)
	}
	if p.Counts.NeedsInconclusive != base.Counts.UnresolvedExplicit || p.Counts.NeedsIncomplete != base.Counts.UnresolvedFailed {
		t.Errorf("needs review split = %d inconclusive / %d incomplete, want %d / %d",
			p.Counts.NeedsInconclusive, p.Counts.NeedsIncomplete, base.Counts.UnresolvedExplicit, base.Counts.UnresolvedFailed)
	}
	if p.Counts.Dismissed != base.Counts.Rejected {
		t.Errorf("dismissed = %d, want %d", p.Counts.Dismissed, base.Counts.Rejected)
	}
	if p.Counts.CandidatesExamined != base.Counts.CandidatesExamined {
		t.Errorf("candidates_examined = %d, want %d", p.Counts.CandidatesExamined, base.Counts.CandidatesExamined)
	}
	// Needs review is never folded into the headline count.
	if p.Counts.IssuesToFix == p.Counts.IssuesToFix+p.Counts.NeedsReview && p.Counts.NeedsReview != 0 {
		t.Error("needs review was added into issues_to_fix")
	}
	// The scope note keeps the completed figure and the exposure axis apart.
	if p.Scope.CoverageComplete != base.Coverage.CompletedReview {
		t.Errorf("coverage completed = %d, want %d", p.Scope.CoverageComplete, base.Coverage.CompletedReview)
	}
	if p.Scope.CoverageExposed != base.Coverage.SourceExposed {
		t.Errorf("coverage exposed = %d, want %d", p.Scope.CoverageExposed, base.Coverage.SourceExposed)
	}
	if p.Scope.CoverageTotal != base.Coverage.TotalEntryPoints {
		t.Errorf("coverage total = %d, want %d", p.Scope.CoverageTotal, base.Coverage.TotalEntryPoints)
	}
	if !p.Scope.CoverageKnown {
		t.Error("coverage is recorded for this corpus and must read as known")
	}
	if p.Scope.Execution != "Incomplete" {
		t.Errorf("execution reads %q; the recorded status for this corpus is partial", p.Scope.Execution)
	}
	if p.Scope.Method != "Source-code analysis" {
		t.Errorf("method reads %q, want plain language", p.Scope.Method)
	}
	if p.Scope.EntryPointGloss == "" {
		t.Error("entry points need a plain explanation")
	}
	if p.Scope.GapSentence == "" {
		t.Error("a 40-of-100 coverage gap is material and needs a sentence")
	}
	// Identity names the application and the recorded revision.
	if p.Identity.Application == "" {
		t.Error("identity must name the application")
	}
	if p.Identity.ScanDate == "" || p.Identity.Timezone == "" {
		t.Errorf("identity must carry a scan date with its timezone: %+v", p.Identity)
	}
	// A legacy model, one without the projection, is still loadable and distinguishable.
	legacy := m
	legacy.Presentation = nil
	legacyDir := t.TempDir()
	if _, err := WriteModel(legacy, legacyDir); err != nil {
		t.Fatal(err)
	}
	lb, _ := os.ReadFile(filepath.Join(legacyDir, ModelFile))
	if strings.Contains(string(lb), `"presentation"`) {
		t.Error("a model without a projection must not emit an empty presentation key")
	}
	var reloaded ReportModel
	if json.Unmarshal(lb, &reloaded) != nil || reloaded.Presentation != nil {
		t.Error("a legacy model must load with a nil projection rather than a fabricated one")
	}
}

func writeModelTo(t *testing.T, m ReportModel) string {
	t.Helper()
	dir := t.TempDir()
	if _, err := WriteModel(m, dir); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(dir, ModelFile))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
