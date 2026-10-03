// Package tools provides the sandboxed file tools exposed to the model:
// Read, Grep, Glob, Write. Two sandboxes enforced by resolved-path prefix
// checks (constitution Principle III, FR-018):
//
//	read roots  — the target repo plus the phase-prompt (skill) directory
//	write root  — the results directory only
//
// There is NO shell/exec tool: the target's code is never run. Every tool caps
// its own output so one call cannot dominate the model's context window.
package tools

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Output caps (parity with Python tools.py).
const (
	MaxReadLines   = 1200
	MaxLineChars   = 500
	MaxGrepMatches = 150
	MaxGlobResults = 400
	MaxResultChars = 60000
)

// SkipDirs are never worth spending context on (mirrors the skill's exclusions).
var SkipDirs = map[string]bool{
	".git": true, "node_modules": true, "vendor": true, "third_party": true,
	"third-party": true, "external": true, "deps": true, "generated": true,
	"gen": true, "dist": true, "build": true, "target": true, "__pycache__": true,
	".venv": true, "venv": true, ".tox": true, ".mypy_cache": true,
	".pytest_cache": true, ".idea": true, ".vscode": true, "site-packages": true,
}

// ErrOutsideSandbox is returned when a path escapes the allowed roots.
var ErrOutsideSandbox = errors.New("path is outside the sandbox")

// binaryExt are extensions treated as binary (never Read), mirroring tools.py.
var binaryExt = map[string]bool{
	".png": true, ".jpg": true, ".jpeg": true, ".gif": true, ".ico": true, ".pdf": true,
	".zip": true, ".gz": true, ".tar": true, ".jar": true, ".class": true, ".so": true,
	".dylib": true, ".dll": true, ".exe": true, ".bin": true, ".woff": true, ".woff2": true,
	".ttf": true, ".eot": true, ".mp4": true, ".mp3": true, ".wasm": true, ".pyc": true,
}

// harnessOwned names the results-dir artifacts the engine writes and the model
// MUST NOT overwrite (FR-007). Verification handoffs, reproduction assignments,
// and deterministic sweep output are authored by the harness.
var harnessOwned = map[string]bool{
	"candidate_manifest.json":          true,
	"hunt_execution.json":              true,
	"verification_decisions.json":      true,
	"verification_reconciliation.json": true,
	"verification_metrics.json":        true,
	"scan_meta.json":                   true,
	"findings.json":                    true,
	"run_manifest.json":                true,
	".vhlocal_state.json":              true,
	// Phase 2b is now the harness-written verification session (US3), so its output
	// and handoff are harness-owned — the model no longer authors them.
	"phase3_output.md":   true,
	"phase3d_output.md":  true,
	"phase2b_output.md":  true,
	"phase2b_handoff.md": true,
}

func isBinary(path string) bool {
	if binaryExt[strings.ToLower(filepath.Ext(path))] {
		return true
	}
	f, err := os.Open(path)
	if err != nil {
		return true
	}
	defer f.Close()
	buf := make([]byte, 2048)
	n, _ := f.Read(buf)
	return bytes.IndexByte(buf[:n], 0) >= 0
}

// Sandbox holds the resolved read roots and the single write root. Construct via
// NewSandbox so all roots are absolute/cleaned before any containment check
// (paths are resolved BEFORE the prefix comparison, so "../" cannot escape).
type Sandbox struct {
	readRoots []string
	writeRoot string
}

// NewSandbox builds a sandbox from the target repo, skill dir, and results dir.
// The results dir is both readable and the sole write root.
func NewSandbox(repo, skillDir, resultsDir string) (*Sandbox, error) {
	repoAbs, err := absClean(repo)
	if err != nil {
		return nil, err
	}
	skillAbs, err := absClean(skillDir)
	if err != nil {
		return nil, err
	}
	resAbs, err := absClean(resultsDir)
	if err != nil {
		return nil, err
	}
	return &Sandbox{
		readRoots: []string{repoAbs, skillAbs, resAbs},
		writeRoot: resAbs,
	}, nil
}

// WriteRoot returns the sole writable root (the results directory), used as a
// grounding hint when repairing a truncated tool-call path.
func (s *Sandbox) WriteRoot() string { return s.writeRoot }

func absClean(p string) (string, error) {
	a, err := filepath.Abs(p)
	if err != nil {
		return "", err
	}
	// Resolve symlinks where possible so a symlinked path can't point outside a
	// root after the prefix check. EvalSymlinks fails on not-yet-created paths;
	// fall back to the cleaned absolute path in that case.
	if resolved, err := filepath.EvalSymlinks(a); err == nil {
		return resolved, nil
	}
	return filepath.Clean(a), nil
}

// within reports whether target (already abs/clean) is inside root.
func within(target, root string) bool {
	if target == root {
		return true
	}
	rel, err := filepath.Rel(root, target)
	if err != nil {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator))
}

// resolveBase resolves raw against base when it is relative (so a bare "app.py"
// resolves against the repo root, not the process CWD — FR-006 round-trip), then
// resolves symlinks. For a not-yet-existent write target, EvalSymlinks fails on the
// full path, so the PARENT is resolved and the leaf rejoined (matches Python's
// Path.resolve(), which resolves symlinked parents even when the leaf is absent —
// FR-007).
func (s *Sandbox) resolveBase(raw, base string) string {
	raw = expandHome(raw)
	p := raw
	if !filepath.IsAbs(raw) {
		p = filepath.Join(base, raw)
	}
	if r, err := filepath.EvalSymlinks(p); err == nil {
		return r
	}
	if rp, err := filepath.EvalSymlinks(filepath.Dir(p)); err == nil {
		return filepath.Join(rp, filepath.Base(p))
	}
	return filepath.Clean(p)
}

func expandHome(p string) string {
	if p == "~" || strings.HasPrefix(p, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			if p == "~" {
				return home
			}
			return filepath.Join(home, p[2:])
		}
	}
	return p
}

// resolveRead resolves p (relative to the repo root) and checks it is inside a read root.
func (s *Sandbox) resolveRead(p string) (string, error) {
	abs := s.resolveBase(p, s.readRoots[0])
	for _, r := range s.readRoots {
		if within(abs, r) {
			return abs, nil
		}
	}
	return "", fmt.Errorf("%w (read): %s", ErrOutsideSandbox, p)
}

// resolveWrite resolves p (relative to the write root), refuses harness-owned
// artifacts, and checks it is inside the write root.
func (s *Sandbox) resolveWrite(p string) (string, error) {
	abs := s.resolveBase(p, s.writeRoot)
	if filepath.Dir(abs) == s.writeRoot {
		name := filepath.Base(abs)
		if harnessOwned[name] || strings.HasPrefix(name, ".vhlocal-") || strings.HasPrefix(name, "verification_candidate_") {
			return "", fmt.Errorf("harness-owned artifact cannot be written by a model: %s", name)
		}
	}
	if within(abs, s.writeRoot) {
		return abs, nil
	}
	return "", fmt.Errorf("%w (write): %s", ErrOutsideSandbox, p)
}

// Read reads a full file (offset 1, default limit); a convenience wrapper over
// ReadPaged for callers that don't page.
func (s *Sandbox) Read(path string) (string, error) {
	return s.ReadPaged(path, 1, MaxReadLines)
}

// ReadPaged returns line-numbered content ("%6d\t<line>") starting at the 1-based
// offset, up to limit lines (capped at MaxReadLines), each truncated to
// MaxLineChars, total capped at MaxResultChars. It rejects directories and binary
// files and appends a continuation hint when more lines remain (FR-003, parity
// with tools.py tool_read). This is what makes file:line citation reliable.
func (s *Sandbox) ReadPaged(path string, offset, limit int) (string, error) {
	abs, err := s.resolveRead(path)
	if err != nil {
		return "", err
	}
	info, err := os.Stat(abs)
	if err != nil {
		return "", fmt.Errorf("file not found: %s", path)
	}
	if info.IsDir() {
		return "", fmt.Errorf("%s is a directory. Use Glob to list its contents.", path)
	}
	if isBinary(abs) {
		return "", fmt.Errorf("%s appears to be binary; skipping.", path)
	}
	if offset < 1 {
		offset = 1
	}
	if limit <= 0 || limit > MaxReadLines {
		limit = MaxReadLines
	}
	f, err := os.Open(abs)
	if err != nil {
		return "", err
	}
	defer f.Close()
	var out []string
	total := 0
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		total++
		if total < offset || len(out) >= limit {
			continue
		}
		line := sc.Text()
		if len(line) > MaxLineChars {
			line = line[:MaxLineChars] + " …[line truncated]"
		}
		out = append(out, fmt.Sprintf("%6d\t%s", total, line))
	}
	if len(out) == 0 {
		return fmt.Sprintf("(file has %d lines; offset %d is past the end)", total, offset), nil
	}
	body := strings.Join(out, "\n")
	shownLast := offset + len(out) - 1
	if shownLast < total {
		body += fmt.Sprintf("\n... [%d more lines; total %d. Re-read with offset=%d]", total-shownLast, total, shownLast+1)
	}
	return truncate(body), nil
}

// Write writes content to path, confined to the results directory. Parent dirs
// are created as needed.
func (s *Sandbox) Write(path, content string) error {
	abs, err := s.resolveWrite(path)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
		return err
	}
	return os.WriteFile(abs, []byte(content), 0o644)
}

// Glob returns up to MaxGlobResults ABSOLUTE paths matching pattern under the
// first read root (the target repo), newest-first, skipping SkipDirs. Matching
// uses fnmatch semantics (globMatch: `*` spans `/`) against both the repo-relative
// path and the basename, so `**/*.py` and `*.py` both match nested files. Returning
// absolute paths makes Glob→Read round-trip regardless of CWD (FR-005/006).
func (s *Sandbox) Glob(pattern string) ([]string, error) {
	root := s.readRoots[0]
	type hit struct {
		path  string
		mtime int64
	}
	var hits []hit
	err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if SkipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		rel, _ := filepath.Rel(root, p)
		if globMatch(pattern, rel) || globMatch(pattern, filepath.Base(p)) {
			var mt int64
			if fi, e := d.Info(); e == nil {
				mt = fi.ModTime().UnixNano()
			}
			hits = append(hits, hit{path: p, mtime: mt})
		}
		if len(hits) > MaxGlobResults*4 {
			return filepath.SkipAll
		}
		return nil
	})
	sort.SliceStable(hits, func(i, j int) bool { return hits[i].mtime > hits[j].mtime })
	out := make([]string, 0, len(hits))
	for i, h := range hits {
		if i >= MaxGlobResults {
			break
		}
		out = append(out, h.path)
	}
	return out, err
}

// GrepOpts are the search options (parity with tools.py tool_grep).
type GrepOpts struct {
	Pattern          string
	Path             string // directory to search (default: repo root)
	Glob             string // filename filter (fnmatch)
	IgnoreCase       bool
	FilesWithMatches bool // return only filenames, not matching lines
}

// Grep searches the repo (or opts.Path) and returns a bounded, model-facing result
// string: a header plus ABSOLUTE `file:line:text` matches (or absolute filenames
// when FilesWithMatches). Uses ripgrep when available, else a pure-Go fallback;
// both honor SkipDirs and a per-file cap of 20. Absolute paths make matches
// directly re-readable (FR-004/006).
func (s *Sandbox) Grep(opts GrepOpts) (string, error) {
	root := s.readRoots[0]
	if opts.Path != "" {
		r, err := s.resolveRead(opts.Path)
		if err != nil {
			return "", err
		}
		root = r
	}
	lines, err := s.grepRipgrep(root, opts)
	if err != nil {
		return "", err
	}
	if lines == nil {
		if lines, err = s.grepPureGo(root, opts); err != nil {
			return "", err
		}
	}
	if len(lines) == 0 {
		g := ""
		if opts.Glob != "" {
			g = fmt.Sprintf(" (glob %q)", opts.Glob)
		}
		return fmt.Sprintf("No matches for %q%s", opts.Pattern, g), nil
	}
	total := len(lines)
	if len(lines) > MaxGrepMatches {
		lines = lines[:MaxGrepMatches]
	}
	header := fmt.Sprintf("%d match(es)", total)
	if total > MaxGrepMatches {
		header += fmt.Sprintf(" (showing first %d — narrow the pattern or pass glob= to see the rest)", MaxGrepMatches)
	}
	return truncate(header + ":\n" + strings.Join(lines, "\n")), nil
}

// grepRipgrep returns formatted match lines via ripgrep, or nil (not an error)
// when ripgrep is unavailable so the caller falls back to pure-Go.
func (s *Sandbox) grepRipgrep(root string, opts GrepOpts) ([]string, error) {
	if _, err := exec.LookPath("rg"); err != nil {
		return nil, nil
	}
	var args []string
	if opts.FilesWithMatches {
		args = []string{"--files-with-matches", "--color", "never"}
	} else {
		args = []string{"--no-heading", "--line-number", "--color", "never"}
	}
	if opts.IgnoreCase {
		args = append(args, "-i")
	}
	for d := range SkipDirs {
		args = append(args, "--glob", "!"+d+"/")
	}
	if opts.Glob != "" {
		args = append(args, "--glob", opts.Glob)
	}
	if !opts.FilesWithMatches {
		args = append(args, "--max-count", "20")
	}
	args = append(args, "-e", opts.Pattern, root)
	out, err := exec.Command("rg", args...).Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok && ee.ExitCode() == 1 {
			return []string{}, nil // no matches
		}
		return nil, nil // ripgrep error → fall back to pure-Go
	}
	var res []string
	for _, ln := range strings.Split(strings.TrimRight(string(out), "\n"), "\n") {
		if ln == "" {
			continue
		}
		res = append(res, ln)
		if len(res) > MaxGrepMatches*3 {
			break
		}
	}
	if res == nil {
		res = []string{}
	}
	return res, nil
}

func (s *Sandbox) grepPureGo(root string, opts GrepOpts) ([]string, error) {
	flags := ""
	if opts.IgnoreCase {
		flags = "(?i)"
	}
	re, err := regexp.Compile(flags + opts.Pattern)
	if err != nil {
		return nil, fmt.Errorf("invalid regex %q: %v", opts.Pattern, err)
	}
	var res []string
	walkErr := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if SkipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if opts.Glob != "" && !globMatch(opts.Glob, filepath.Base(p)) && !globMatch(opts.Glob, p) {
			return nil
		}
		if isBinary(p) {
			return nil
		}
		f, err := os.Open(p)
		if err != nil {
			return nil
		}
		defer f.Close()
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
		line, hits := 0, 0
		for sc.Scan() {
			line++
			if re.MatchString(sc.Text()) {
				if opts.FilesWithMatches {
					res = append(res, p)
					break
				}
				txt := sc.Text()
				if len(txt) > MaxLineChars {
					txt = txt[:MaxLineChars] + "…"
				}
				res = append(res, fmt.Sprintf("%s:%d:%s", p, line, txt))
				hits++
				if hits >= 20 {
					break
				}
			}
		}
		if len(res) > MaxGrepMatches*3 {
			return filepath.SkipAll
		}
		return nil
	})
	return res, walkErr
}

func truncate(s string) string {
	if len(s) > MaxResultChars {
		return s[:MaxResultChars] + "\n…(truncated)"
	}
	return s
}

func atoi(s string) int {
	n := 0
	for _, c := range strings.TrimSpace(s) {
		if c < '0' || c > '9' {
			break
		}
		n = n*10 + int(c-'0')
	}
	return n
}
