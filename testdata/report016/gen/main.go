//go:build ignore

// Fixture generator for feature 016 (task T001).
//
// Produces the frozen, sanitized acceptance corpus under testdata/report016 from a
// real completed scan. The source scan is READ ONLY: this program never writes,
// renames or deletes anything inside it, and it writes nothing outside the
// destination directory.
//
// Sanitizing rewrites the results directory, the scanned repository path and the
// inference host, redacts any other absolute operator path, and omits prompts.jsonl
// entirely. Count and group relationships are preserved byte-for-byte otherwise, so
// the acceptance targets in spec.md SC-002 and SC-010 still hold.
//
// Usage, from anywhere inside the repository:
//
//	go run ./testdata/report016/gen/main.go <source-results-dir>
//
// Re-running it reproduces the same output for the same input (feature 016, FR-028).
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// records are the files the acceptance corpus needs. prompts.jsonl is deliberately
// absent: it carries model transcripts and no acceptance check reads it.
var records = []string{
	"report_model.json",
	"findings.json",
	"remediation_groups.json",
	"verification_metrics.json",
	"verification_sessions.json",
	"verification_reconciliation.json",
	"coverage_ledger.json",
	"review_units.json",
	"scan_meta.json",
}

// The sanitized stand-ins. The repository path points at a stub tree that the
// corpus does not ship, so a reader cannot mistake it for real source.
const (
	destResults = "testdata/report016"
	destRepo    = "testdata/report016/target"
	destHost    = "http://127.0.0.1:11434"
	redacted    = "<redacted-path>"
)

// reHomePath matches any remaining absolute path under a user home directory.
var reHomePath = regexp.MustCompile(`/(?:home|Users)/[A-Za-z0-9._-]+`)

func main() {
	if len(os.Args) != 2 {
		fail("usage: go run ./testdata/report016/gen/main.go <source-results-dir>")
	}
	src, err := filepath.Abs(os.Args[1])
	if err != nil {
		fail("resolve source: %v", err)
	}
	// Destination is resolved from the repository root, found by walking up for go.mod,
	// so the generator works from any working directory and can never write into the
	// source. os.Args[0] is useless here because `go run` builds into a temp directory.
	dest := filepath.Join(repoRoot(), destResults)
	if within(dest, src) || within(src, dest) {
		fail("refusing to run: source %s and destination %s overlap", src, dest)
	}

	meta := readMeta(filepath.Join(src, "scan_meta.json"))
	if meta.Repo == "" || meta.ResultsDir == "" {
		fail("source scan_meta.json has no repo or results_dir; cannot sanitize safely")
	}
	// Longest paths first so a prefix cannot shadow a longer match.
	subs := [][2]string{
		{meta.ResultsDir, destResults},
		{meta.Repo, destRepo},
	}
	if meta.Host != "" {
		subs = append(subs, [2]string{meta.Host, destHost})
	}
	sort.SliceStable(subs, func(i, j int) bool { return len(subs[i][0]) > len(subs[j][0]) })

	if err := os.MkdirAll(dest, 0o755); err != nil {
		fail("create destination: %v", err)
	}
	fingerprints := map[string]string{}
	for _, name := range records {
		raw, err := os.ReadFile(filepath.Join(src, name))
		if err != nil {
			fail("read %s: %v", name, err)
		}
		fingerprints[name] = sha256Hex(raw)
		out := string(raw)
		for _, s := range subs {
			out = strings.ReplaceAll(out, s[0], s[1])
		}
		out = reHomePath.ReplaceAllString(out, redacted)
		if strings.Contains(out, "/home/") || strings.Contains(out, "/Users/") {
			fail("%s still contains an operator path after sanitizing", name)
		}
		if err := os.WriteFile(filepath.Join(dest, name), []byte(out), 0o644); err != nil {
			fail("write %s: %v", name, err)
		}
	}
	// Record the source fingerprints so the fixture's provenance is auditable and a
	// future regeneration against a different scan is visible rather than silent.
	names := make([]string, 0, len(fingerprints))
	for n := range fingerprints {
		names = append(names, n)
	}
	sort.Strings(names)
	var sb strings.Builder
	sb.WriteString("# Source fingerprints for the feature 016 acceptance fixture\n\n")
	sb.WriteString("sha256 of each record as read from the source scan, BEFORE sanitizing.\n")
	sb.WriteString("Regenerate with: go run ./testdata/report016/gen/main.go <source-results-dir>\n\n")
	for _, n := range names {
		fmt.Fprintf(&sb, "%s  %s\n", fingerprints[n], n)
	}
	if err := os.WriteFile(filepath.Join(dest, "SOURCE_FINGERPRINTS.txt"), []byte(sb.String()), 0o644); err != nil {
		fail("write fingerprints: %v", err)
	}
	fmt.Printf("wrote %d sanitized records to %s\n", len(records), dest)
}

type scanMeta struct {
	Repo       string `json:"repo"`
	ResultsDir string `json:"results_dir"`
	Host       string `json:"host"`
}

func readMeta(path string) scanMeta {
	b, err := os.ReadFile(path)
	if err != nil {
		fail("read scan_meta.json: %v", err)
	}
	var m scanMeta
	if err := json.Unmarshal(b, &m); err != nil {
		fail("parse scan_meta.json: %v", err)
	}
	return m
}

func within(parent, child string) bool {
	rel, err := filepath.Rel(parent, child)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "report016 fixture: "+format+"\n", args...)
	os.Exit(1)
}

// repoRoot walks up from the working directory to the module root (the directory
// holding go.mod), so the destination never depends on where the generator was run.
func repoRoot() string {
	dir, err := os.Getwd()
	if err != nil {
		fail("working directory: %v", err)
	}
	for i := 0; i < 12; i++ {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	fail("could not find the module root (no go.mod above %s)", dir)
	return ""
}
