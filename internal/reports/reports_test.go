package reports

import (
	"os"
	"path/filepath"
	"testing"
)

// T094 (FR-026, C-C8): the lister honours the presentation version. A report carrying the
// projection exposes its reader-facing counts verbatim; one saved before feature 016 leaves
// them unavailable rather than reporting zero, because the two mean different things.
func TestPresentationVersionIsHonouredAndNeverInvented(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "scan_meta.json"), []byte(`{"repo":"/repos/shop","model":"m","started_at":1,"finished_at":2}`), 0o644)
	os.WriteFile(filepath.Join(dir, "SCAN_REPORT.md"), []byte("# report\n"), 0o644)

	// Pre-016: a model with no projection.
	os.WriteFile(filepath.Join(dir, "report_model.json"), []byte(`{"version":1}`), 0o644)
	r, ok := Load(dir)
	if !ok {
		t.Fatal("Load failed")
	}
	if r.PresentationVersion != 0 {
		t.Errorf("presentation_version = %d for a pre-016 report, want 0", r.PresentationVersion)
	}
	if r.IssuesToFix != nil || r.NeedsReview != nil || r.Dismissed != nil {
		t.Errorf("a pre-016 report must leave the reader-facing counts unavailable: %v %v %v",
			r.IssuesToFix, r.NeedsReview, r.Dismissed)
	}

	// With the projection: the counts come through exactly as recorded.
	os.WriteFile(filepath.Join(dir, "report_model.json"), []byte(
		`{"version":1,"presentation":{"version":1,"counts":{"issues_to_fix":34,"needs_review":7,"dismissed":8}}}`), 0o644)
	r, ok = Load(dir)
	if !ok {
		t.Fatal("Load failed")
	}
	if r.PresentationVersion != 1 {
		t.Errorf("presentation_version = %d, want 1", r.PresentationVersion)
	}
	if r.IssuesToFix == nil || *r.IssuesToFix != 34 {
		t.Errorf("issues_to_fix = %v, want 34", r.IssuesToFix)
	}
	if r.NeedsReview == nil || *r.NeedsReview != 7 {
		t.Errorf("needs_review = %v, want 7", r.NeedsReview)
	}
	if r.Dismissed == nil || *r.Dismissed != 8 {
		t.Errorf("dismissed = %v, want 8", r.Dismissed)
	}
	// A projection with version 0 is not a projection: it is not honoured.
	os.WriteFile(filepath.Join(dir, "report_model.json"), []byte(
		`{"version":1,"presentation":{"counts":{"issues_to_fix":3}}}`), 0o644)
	r, _ = Load(dir)
	if r.PresentationVersion != 0 || r.IssuesToFix != nil {
		t.Errorf("an unversioned projection must not be honoured: v=%d issues=%v", r.PresentationVersion, r.IssuesToFix)
	}
}
