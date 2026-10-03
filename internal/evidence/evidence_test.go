package evidence

import (
	"os"
	"path/filepath"
	"testing"
)

// mkRepo writes a minimal git repo at a temp dir whose HEAD is the given commit
// (detached), containing file rel with content. Returns the repo path.
func mkRepo(t *testing.T, commit, rel, content string) string {
	t.Helper()
	repo := t.TempDir()
	if err := os.MkdirAll(filepath.Join(repo, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, ".git", "HEAD"), []byte(commit+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	full := filepath.Join(repo, rel)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return repo
}

const sha = "0123456789abcdef0123456789abcdef01234567"

// T014 (FR-011/012): when the repo is at the recorded commit, source is returned
// bound to that revision with the finding's line highlighted.
func TestSourceAtRecordedRevision(t *testing.T) {
	repo := mkRepo(t, sha, "app.go", "line1\nline2\nvulnerable()\nline4\n")
	v := Build(Meta{Repo: repo, Commit: sha}, map[string]any{"location": "app.go:3"})
	if !v.Source.Available || v.Source.Reason != ReasonOK {
		t.Fatalf("source should be available: %+v", v.Source)
	}
	if v.Source.FocusLine != 3 {
		t.Fatalf("focus line = %d, want 3", v.Source.FocusLine)
	}
	var hl string
	for _, l := range v.Source.Lines {
		if l.Highlight {
			hl = l.Text
		}
	}
	if hl != "vulnerable()" {
		t.Fatalf("highlighted line = %q, want vulnerable()", hl)
	}
}

// T014 (FR-012): a repo at a DIFFERENT commit must not be read — the working tree
// is a different revision and is never substituted.
func TestRevisionMismatchNotSubstituted(t *testing.T) {
	repo := mkRepo(t, "ffffffffffffffffffffffffffffffffffffffff", "app.go", "secret\n")
	v := Build(Meta{Repo: repo, Commit: sha}, map[string]any{"location": "app.go:1"})
	if v.Source.Available || v.Source.Reason != ReasonRevisionUnavailable {
		t.Fatalf("mismatched revision must be unavailable, not read: %+v", v.Source)
	}
	if len(v.Source.Lines) != 0 {
		t.Fatal("no source lines may be returned on revision mismatch")
	}
}

// FR-012: a dirty scan tree yields revision-unavailable (the working tree differs
// from the recorded snapshot).
func TestDirtyTreeUnavailable(t *testing.T) {
	repo := mkRepo(t, sha, "app.go", "x\n")
	v := Build(Meta{Repo: repo, Commit: sha, Dirty: true}, map[string]any{"location": "app.go:1"})
	if v.Source.Available || v.Source.Reason != ReasonRevisionUnavailable {
		t.Fatalf("dirty tree must be unavailable: %+v", v.Source)
	}
}

// FR-013: narrative is taken from the verification record when present.
func TestNarrativeFromVerificationRecord(t *testing.T) {
	raw := map[string]any{
		"location":  "app.go:3",
		"data_flow": "req.body → query",
		"verification_record": map[string]any{
			"entry_point": "POST /login", "attacker_control": "username",
			"defenses_reviewed": "none", "security_impact": "auth bypass",
		},
	}
	v := Build(Meta{}, raw)
	if v.Narrative.EntryPoint != "POST /login" || v.Narrative.SecurityImpact != "auth bypass" {
		t.Fatalf("narrative not sourced from verification_record: %+v", v.Narrative)
	}
	// No repo → revision-unavailable, but narrative still returned.
	if v.Source.Available {
		t.Fatal("no repo should not yield available source")
	}
}

// Principle III: a path escaping the repo is refused.
func TestPathContainment(t *testing.T) {
	repo := mkRepo(t, sha, "app.go", "x\n")
	v := Build(Meta{Repo: repo, Commit: sha}, map[string]any{"location": "../../etc/passwd:1"})
	if v.Source.Available {
		t.Fatalf("path escape must not be served: %+v", v.Source)
	}
}

// No location → explicit no-location reason.
func TestNoLocation(t *testing.T) {
	v := Build(Meta{Repo: "/x", Commit: sha}, map[string]any{})
	if v.Source.Reason != ReasonNoLocation {
		t.Fatalf("reason = %q, want no-location", v.Source.Reason)
	}
}
