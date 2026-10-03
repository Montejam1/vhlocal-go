package tools

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func contains(s, sub string) bool { return strings.Contains(s, sub) }
func itoa(n int) string           { return strconv.Itoa(n) }

func setup(t *testing.T) (repo, skill, results string) {
	t.Helper()
	base := t.TempDir()
	repo = filepath.Join(base, "repo")
	skill = filepath.Join(base, "skill")
	results = filepath.Join(base, "results")
	for _, d := range []string{repo, skill, results} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(repo, "app.py"), []byte("import os\nq = execute(user)\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// a secret OUTSIDE all roots
	if err := os.WriteFile(filepath.Join(base, "secret.txt"), []byte("TOPSECRET"), 0o644); err != nil {
		t.Fatal(err)
	}
	return
}

func TestReadWithinRootOK(t *testing.T) {
	repo, skill, results := setup(t)
	sb, err := NewSandbox(repo, skill, results)
	if err != nil {
		t.Fatal(err)
	}
	got, err := sb.Read(filepath.Join(repo, "app.py"))
	if err != nil {
		t.Fatalf("read within repo: %v", err)
	}
	if got == "" {
		t.Fatal("expected file content")
	}
}

func TestReadTraversalRefused(t *testing.T) {
	repo, skill, results := setup(t)
	sb, _ := NewSandbox(repo, skill, results)
	// classic ../ escape to the sibling secret
	_, err := sb.Read(filepath.Join(repo, "..", "secret.txt"))
	if !errors.Is(err, ErrOutsideSandbox) {
		t.Fatalf("traversal read should be refused, got %v", err)
	}
}

func TestWriteConfinedToResults(t *testing.T) {
	repo, skill, results := setup(t)
	sb, _ := NewSandbox(repo, skill, results)
	// writing into the results dir is allowed
	if err := sb.Write(filepath.Join(results, "out.md"), "x"); err != nil {
		t.Fatalf("write to results: %v", err)
	}
	// writing into the repo (read root, not write root) is refused
	if err := sb.Write(filepath.Join(repo, "evil.py"), "x"); !errors.Is(err, ErrOutsideSandbox) {
		t.Fatalf("write to repo should be refused, got %v", err)
	}
	// writing outside all roots is refused
	if err := sb.Write(filepath.Join(results, "..", "escape.txt"), "x"); !errors.Is(err, ErrOutsideSandbox) {
		t.Fatalf("write traversal should be refused, got %v", err)
	}
}

func TestGrepFindsMatchAbsolute(t *testing.T) {
	repo, skill, results := setup(t)
	sb, _ := NewSandbox(repo, skill, results)
	out, err := sb.Grep(GrepOpts{Pattern: `execute\(`})
	if err != nil {
		t.Fatal(err)
	}
	// Absolute path + :line: so the model can re-Read the hit (FR-006).
	want := filepath.Join(repo, "app.py") + ":2:"
	if !contains(out, want) {
		t.Fatalf("grep out=%q want substring %q", out, want)
	}
}

func TestGlobFindsPythonAbsolute(t *testing.T) {
	repo, skill, results := setup(t)
	sb, _ := NewSandbox(repo, skill, results)
	got, err := sb.Glob("*.py")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != filepath.Join(repo, "app.py") {
		t.Fatalf("glob = %v (want one absolute path to app.py)", got)
	}
}

// C-1a: Read pages with a 1-based offset/limit, emits line-numbered content, and a
// continuation hint; a citation past the first page resolves.
func TestReadPagingAndLineNumbers(t *testing.T) {
	repo, skill, results := setup(t)
	sb, _ := NewSandbox(repo, skill, results)
	var lines []string
	for i := 1; i <= 50; i++ {
		lines = append(lines, "line"+itoa(i))
	}
	os.WriteFile(filepath.Join(repo, "big.txt"), []byte(strings.Join(lines, "\n")+"\n"), 0o644)
	// Page 2: lines 11..15.
	out, err := sb.ReadPaged(filepath.Join(repo, "big.txt"), 11, 5)
	if err != nil {
		t.Fatal(err)
	}
	if !contains(out, "    11\tline11") {
		t.Errorf("expected line-numbered content for line 11; got:\n%s", out)
	}
	if contains(out, "line10") || contains(out, "line16") {
		t.Errorf("offset/limit not respected; got:\n%s", out)
	}
	if !contains(out, "more lines") {
		t.Errorf("expected a continuation hint; got:\n%s", out)
	}
	// FR-008 preserve: the per-page limit caps output at MaxReadLines.
	full, _ := sb.ReadPaged(filepath.Join(repo, "big.txt"), 1, 100000)
	if strings.Count(full, "\t") > MaxReadLines {
		t.Errorf("Read must not exceed MaxReadLines lines")
	}
}

// C-1b: recursive glob matches nested files (fnmatch, not filepath.Match) and every
// returned path is absolute and directly readable regardless of CWD.
func TestGlobRecursiveRoundTrip(t *testing.T) {
	repo, skill, results := setup(t)
	os.MkdirAll(filepath.Join(repo, "app", "routers"), 0o755)
	os.WriteFile(filepath.Join(repo, "app", "routers", "auth.py"), []byte("x=1\n"), 0o644)
	sb, _ := NewSandbox(repo, skill, results)
	got, err := sb.Glob("**/*.py")
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, p := range got {
		if !filepath.IsAbs(p) {
			t.Errorf("glob path not absolute: %q", p)
		}
		if strings.HasSuffix(p, filepath.Join("app", "routers", "auth.py")) {
			found = true
			if _, err := sb.Read(p); err != nil {
				t.Errorf("glob result must round-trip to Read: %v", err)
			}
		}
	}
	if !found {
		t.Errorf("recursive glob must match the nested file; got %v", got)
	}
}

// C-1c: Grep honors glob filter + ignore_case + files_with_matches with absolute
// paths, and caps output.
func TestGrepOptions(t *testing.T) {
	repo, skill, results := setup(t)
	os.WriteFile(filepath.Join(repo, "notes.md"), []byte("EXECUTE something\n"), 0o644)
	sb, _ := NewSandbox(repo, skill, results)
	// ignore_case + glob filter to .py only → should NOT match notes.md.
	out, err := sb.Grep(GrepOpts{Pattern: "execute", IgnoreCase: true, Glob: "*.py"})
	if err != nil {
		t.Fatal(err)
	}
	if contains(out, "notes.md") {
		t.Errorf("glob=*.py must exclude notes.md; got:\n%s", out)
	}
	// files_with_matches returns absolute filenames.
	fout, _ := sb.Grep(GrepOpts{Pattern: "execute", FilesWithMatches: true})
	if !contains(fout, filepath.Join(repo, "app.py")) {
		t.Errorf("files_with_matches must list the absolute file; got:\n%s", fout)
	}
}

// C-1e: writes to harness-owned artifacts are refused; a legitimate results write
// through a symlinked parent is confined and succeeds.
func TestHarnessOwnedWriteRefused(t *testing.T) {
	repo, skill, results := setup(t)
	sb, _ := NewSandbox(repo, skill, results)
	if err := sb.Write(filepath.Join(results, "scan_meta.json"), "{}"); err == nil {
		t.Error("writing scan_meta.json must be refused (harness-owned)")
	}
	if err := sb.Write(filepath.Join(results, "candidate_manifest.json"), "[]"); err == nil {
		t.Error("writing candidate_manifest.json must be refused (harness-owned)")
	}
	// A normal deliverable is still allowed.
	if err := sb.Write(filepath.Join(results, "phase1_output.md"), "ok"); err != nil {
		t.Errorf("a normal deliverable write must be allowed: %v", err)
	}
}

func TestSymlinkedResultsParentWriteConfined(t *testing.T) {
	base := t.TempDir()
	repo := filepath.Join(base, "repo")
	skill := filepath.Join(base, "skill")
	realResults := filepath.Join(base, "real_results")
	for _, d := range []string{repo, skill, realResults} {
		os.MkdirAll(d, 0o755)
	}
	// results is a symlink to real_results.
	link := filepath.Join(base, "results")
	if err := os.Symlink(realResults, link); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	sb, err := NewSandbox(repo, skill, link)
	if err != nil {
		t.Fatal(err)
	}
	if err := sb.Write(filepath.Join(link, "out.md"), "x"); err != nil {
		t.Errorf("write through a symlinked results parent must succeed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(realResults, "out.md")); err != nil {
		t.Errorf("write did not land in the real results dir: %v", err)
	}
}
