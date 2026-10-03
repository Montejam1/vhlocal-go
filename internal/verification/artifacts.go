package verification

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"vhlocal/internal/consolidate"
	"vhlocal/internal/source"
)

var reAssertion = regexp.MustCompile(`(?m)(^|\s)assert\b|\.assert\w*\s*\(`)

// ArtifactEntry is one record in artifact_manifest.json (authored reproduction
// material). Execution is never claimed here — status is always "authored".
type ArtifactEntry struct {
	CandidateID string `json:"candidate_id"`
	Kind        string `json:"kind"` // poc | test | deferred
	Path        string `json:"path"`
	Status      string `json:"status"`
	Reason      string `json:"reason"`
}

// ValidateArtifacts validates authored reproduction artifacts against the supported
// candidates and the on-disk files (feature 006, FR-013; parity with the reference
// verification.validate_artifacts). It NEVER claims tests executed. Returns the
// list of problems (empty ⇒ every supported candidate has a valid disposition and
// no artifact file is orphaned/unregistered).
//
// Rules: each entry must bind to a supported candidate; a `deferred` entry needs a
// reason; a `poc`/`test` entry's file must live under poc/ or exploit_tests/
// respectively, be non-empty, contain the canonical candidate ID and the source
// location, and be status=authored; an authored .py test must carry an assertion.
// Every supported candidate needs a disposition, and every file under poc/ and
// exploit_tests/ must be registered.
func ValidateArtifacts(root string, findings []consolidate.Finding) []string {
	supported := map[string]consolidate.Finding{}
	for _, f := range findings {
		if f.VerificationStatus == "supported" {
			supported[f.ID] = f
		}
	}
	b, err := source.ReadFile(root, ArtifactManifestFile)
	if err != nil {
		return []string{"Phase 3 artifact_manifest.json is missing or malformed"}
	}
	var data []ArtifactEntry
	if json.Unmarshal(b, &data) != nil || data == nil {
		return []string{"Phase 3 artifact_manifest.json is missing or malformed"}
	}

	var errs []string
	registered := map[string]bool{} // clean absolute path -> registered
	accounted := map[string]bool{}  // finding id -> has a disposition
	for _, e := range data {
		f, ok := supported[e.CandidateID]
		if !ok {
			errs = append(errs, "artifact references an unknown or unverified candidate")
			continue
		}
		if e.Kind == "deferred" {
			if strings.TrimSpace(e.Reason) == "" {
				errs = append(errs, "deferred reproduction requires a reason")
				continue
			}
			accounted[f.ID] = true
			continue
		}
		if e.Kind != "poc" && e.Kind != "test" {
			errs = append(errs, "artifact kind must be poc or test")
			continue
		}
		if e.Path == "" || filepath.IsAbs(e.Path) || strings.Contains(e.Path, "..") {
			errs = append(errs, "artifact path must be relative")
			continue
		}
		expected := "poc"
		if e.Kind == "test" {
			expected = "exploit_tests"
		}
		rel := filepath.ToSlash(filepath.Clean(e.Path))
		if rel != expected && !strings.HasPrefix(rel, expected+"/") {
			errs = append(errs, "artifact path must be under "+expected+"/")
			continue
		}
		abs := filepath.Join(root, rel)
		if registered[abs] {
			errs = append(errs, "duplicate artifact path")
			continue
		}
		resolved, rerr := source.Resolve(root, rel)
		expectedRoot, rootErr := filepath.EvalSymlinks(filepath.Join(root, expected))
		if rerr != nil || rootErr != nil {
			errs = append(errs, "artifact path is missing or escapes root: "+rel)
			continue
		}
		expectedRoot, _ = filepath.Abs(expectedRoot)
		within, relErr := filepath.Rel(expectedRoot, resolved)
		if relErr != nil || within == ".." || strings.HasPrefix(within, ".."+string(filepath.Separator)) {
			errs = append(errs, "artifact path must resolve under "+expected+"/")
			continue
		}
		content, rerr := source.ReadFile(root, rel)
		if rerr != nil {
			errs = append(errs, "artifact file not found: "+rel)
			continue
		}
		text := string(content)
		if strings.TrimSpace(text) == "" || !strings.Contains(text, f.ID) || !strings.Contains(text, f.Location) {
			errs = append(errs, "artifact lacks canonical candidate ID or source location")
			continue
		}
		if e.Status != "authored" {
			errs = append(errs, "model artifact status must be authored; execution requires executor evidence")
			continue
		}
		if e.Kind == "test" && strings.HasSuffix(rel, ".py") && !reAssertion.MatchString(text) {
			errs = append(errs, "authored test has no assertion; printing output is not a test")
			continue
		}
		registered[abs] = true
		accounted[f.ID] = true
	}

	// Every supported candidate needs a reproduction disposition.
	var missing []string
	for id := range supported {
		if !accounted[id] {
			missing = append(missing, id)
		}
	}
	sortStrings(missing)
	for _, id := range missing {
		errs = append(errs, "no reproduction disposition for "+id)
	}

	// Every file under poc/ and exploit_tests/ must be registered.
	for _, dir := range []string{"poc", "exploit_tests"} {
		base := filepath.Join(root, dir)
		_ = filepath.WalkDir(base, func(p string, d os.DirEntry, werr error) error {
			if werr != nil || d.IsDir() {
				return nil
			}
			if !registered[p] {
				r, _ := filepath.Rel(root, p)
				errs = append(errs, "unregistered artifact: "+filepath.ToSlash(r))
			}
			return nil
		})
	}
	return errs
}

// ValidateEntry validates ONE artifact entry against its already-known supported
// candidate finding, returning "" when valid or the specific reason it is not
// (feature 007, FR-025/026 — the per-candidate reproduction loop's feedback).
// Cross-entry checks (duplicate path, unregistered files, missing dispositions)
// remain in ValidateArtifacts.
func ValidateEntry(root string, e ArtifactEntry, f consolidate.Finding) string {
	if e.CandidateID != f.ID {
		return "artifact references an unknown or unverified candidate"
	}
	if e.Kind == "deferred" {
		if strings.TrimSpace(e.Reason) == "" {
			return "deferred reproduction requires a reason"
		}
		return ""
	}
	if e.Kind != "poc" && e.Kind != "test" {
		return "artifact kind must be poc or test"
	}
	if e.Path == "" || filepath.IsAbs(e.Path) || strings.Contains(e.Path, "..") {
		return "artifact path must be relative"
	}
	expected := "poc"
	if e.Kind == "test" {
		expected = "exploit_tests"
	}
	rel := filepath.ToSlash(filepath.Clean(e.Path))
	if rel != expected && !strings.HasPrefix(rel, expected+"/") {
		return "artifact path must be under " + expected + "/"
	}
	resolved, rerr := source.Resolve(root, rel)
	expectedRoot, rootErr := filepath.EvalSymlinks(filepath.Join(root, expected))
	if rerr != nil || rootErr != nil {
		return "artifact path is missing or escapes root: " + rel
	}
	expectedRoot, _ = filepath.Abs(expectedRoot)
	within, relErr := filepath.Rel(expectedRoot, resolved)
	if relErr != nil || within == ".." || strings.HasPrefix(within, ".."+string(filepath.Separator)) {
		return "artifact path must resolve under " + expected + "/"
	}
	content, rerr := source.ReadFile(root, rel)
	if rerr != nil {
		return "artifact file not found: " + rel
	}
	text := string(content)
	if strings.TrimSpace(text) == "" || !strings.Contains(text, f.ID) || !strings.Contains(text, f.Location) {
		return "artifact lacks canonical candidate ID or source location"
	}
	if e.Status != "authored" {
		return "model artifact status must be authored; execution requires executor evidence"
	}
	if e.Kind == "test" && strings.HasSuffix(rel, ".py") && !reAssertion.MatchString(text) {
		return "authored test has no assertion; printing output is not a test"
	}
	return ""
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j-1] > s[j]; j-- {
			s[j-1], s[j] = s[j], s[j-1]
		}
	}
}
