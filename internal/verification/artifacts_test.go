package verification

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"vhlocal/internal/consolidate"
)

func supportedFinding(id, loc string) consolidate.Finding {
	f := consolidate.NewFinding(id)
	f.CWE, f.Location, f.VerificationStatus = "CWE-89", loc, "supported"
	return f
}

func writeManifest(t *testing.T, root string, entries []ArtifactEntry) {
	t.Helper()
	b, _ := json.MarshalIndent(entries, "", "  ")
	if err := os.WriteFile(filepath.Join(root, ArtifactManifestFile), b, 0o644); err != nil {
		t.Fatal(err)
	}
}

// C-4b (feature 006, FR-013): an authored artifact must bind entry ↔ supported
// candidate ↔ on-disk file; unregistered/orphaned artifacts and unaccounted
// candidates are flagged.
func TestValidateArtifactsBinding(t *testing.T) {
	root := t.TempDir()
	os.MkdirAll(filepath.Join(root, "poc"), 0o755)
	f := supportedFinding("CAND-abc", "app/db.py:42")

	// A valid PoC that names the candidate ID and the source location.
	poc := "# PoC for CAND-abc at app/db.py:42\nprint('exploit')\n"
	os.WriteFile(filepath.Join(root, "poc", "cand-abc.py"), []byte(poc), 0o644)
	writeManifest(t, root, []ArtifactEntry{
		{CandidateID: "CAND-abc", Kind: "poc", Path: "poc/cand-abc.py", Status: "authored"},
	})
	if errs := ValidateArtifacts(root, []consolidate.Finding{f}); len(errs) != 0 {
		t.Errorf("a well-formed PoC should validate cleanly, got %v", errs)
	}

	// An artifact referencing an unverified candidate is flagged.
	writeManifest(t, root, []ArtifactEntry{
		{CandidateID: "CAND-ghost", Kind: "poc", Path: "poc/cand-abc.py", Status: "authored"},
	})
	errs := ValidateArtifacts(root, []consolidate.Finding{f})
	if !containsSub(errs, "unknown or unverified") {
		t.Errorf("an artifact for an unknown candidate must be flagged, got %v", errs)
	}
	// ...and the supported candidate now has no disposition.
	if !containsSub(errs, "no reproduction disposition for CAND-abc") {
		t.Errorf("an unaccounted supported candidate must be flagged, got %v", errs)
	}

	// An orphaned file under poc/ that no entry registers is flagged.
	os.WriteFile(filepath.Join(root, "poc", "stray.py"), []byte("x=1\n"), 0o644)
	writeManifest(t, root, []ArtifactEntry{
		{CandidateID: "CAND-abc", Kind: "poc", Path: "poc/cand-abc.py", Status: "authored"},
	})
	errs = ValidateArtifacts(root, []consolidate.Finding{f})
	if !containsSub(errs, "unregistered artifact: poc/stray.py") {
		t.Errorf("an orphaned artifact file must be flagged, got %v", errs)
	}
}

// C-4b: a deferred disposition (with a reason) accounts for the candidate; an
// authored test needs an assertion; a PoC missing the candidate ID/location fails.
func TestValidateArtifactsDeferredAndContent(t *testing.T) {
	root := t.TempDir()
	f := supportedFinding("CAND-xyz", "app/db.py:42")

	// deferred with a reason → accounted, clean.
	writeManifest(t, root, []ArtifactEntry{
		{CandidateID: "CAND-xyz", Kind: "deferred", Reason: "requires live credentials"},
	})
	if errs := ValidateArtifacts(root, []consolidate.Finding{f}); len(errs) != 0 {
		t.Errorf("a deferred disposition with a reason should validate, got %v", errs)
	}

	// A PoC that does not mention the candidate ID/location is refused.
	os.MkdirAll(filepath.Join(root, "poc"), 0o755)
	os.WriteFile(filepath.Join(root, "poc", "p.py"), []byte("print('nothing canonical')\n"), 0o644)
	writeManifest(t, root, []ArtifactEntry{
		{CandidateID: "CAND-xyz", Kind: "poc", Path: "poc/p.py", Status: "authored"},
	})
	if errs := ValidateArtifacts(root, []consolidate.Finding{f}); !containsSub(errs, "canonical candidate ID or source location") {
		t.Errorf("a PoC missing the canonical ID/location must be refused, got %v", errs)
	}

	// An authored test with no assertion is refused.
	os.MkdirAll(filepath.Join(root, "exploit_tests"), 0o755)
	os.WriteFile(filepath.Join(root, "exploit_tests", "t.py"), []byte("# CAND-xyz app/db.py:42\nprint('ran')\n"), 0o644)
	writeManifest(t, root, []ArtifactEntry{
		{CandidateID: "CAND-xyz", Kind: "test", Path: "exploit_tests/t.py", Status: "authored"},
	})
	if errs := ValidateArtifacts(root, []consolidate.Finding{f}); !containsSub(errs, "no assertion") {
		t.Errorf("an authored test with no assertion must be refused, got %v", errs)
	}
	// The same test WITH an assertion validates (removing the earlier stray PoC).
	os.Remove(filepath.Join(root, "poc", "p.py"))
	os.WriteFile(filepath.Join(root, "exploit_tests", "t.py"), []byte("# CAND-xyz app/db.py:42\ndef test_it():\n    assert True\n"), 0o644)
	if errs := ValidateArtifacts(root, []consolidate.Finding{f}); len(errs) != 0 {
		t.Errorf("an authored test with an assertion should validate, got %v", errs)
	}
}

func containsSub(errs []string, sub string) bool {
	for _, e := range errs {
		if strings.Contains(e, sub) {
			return true
		}
	}
	return false
}
