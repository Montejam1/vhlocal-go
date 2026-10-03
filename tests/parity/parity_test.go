// Package parity holds the standing guard for FR-031: a Go scan must produce the
// same artifact set (by filename) that the spec/contracts declare. It runs the
// engine offline with a fake provider and asserts the produced files. When the
// reference Python implementation is available, this is also where a byte-level
// differential diff would hook in (see specs/002-golang-port/quickstart.md).
package parity

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"testing"

	"vhlocal/internal/client"
	"vhlocal/internal/engine"
)

// fakeProvider follows the "Write to <path>" instruction offline, emitting
// finding markdown for the confirmed (2b) output.
type fakeProvider struct{}

var reOut = regexp.MustCompile(`(/\S+\.md)`)

func (fakeProvider) Backend() client.Backend { return "fake" }
func (fakeProvider) Endpoint() string        { return "fake://local" }
func (fakeProvider) Chat(_ context.Context, req client.ChatRequest) (*client.ChatResponse, error) {
	if n := len(req.Messages); n > 0 && req.Messages[n-1].Role == "tool" {
		return &client.ChatResponse{Message: client.Message{Role: "assistant", Content: "done"}}, nil
	}
	task := ""
	for _, m := range req.Messages {
		if m.Role == "user" {
			task = m.Content
		}
	}
	// The write target is the LAST .md path named in the task (Reads are listed
	// before it), so pick the last match.
	all := reOut.FindAllString(task, -1)
	path := ""
	if len(all) > 0 {
		path = all[len(all)-1]
	}
	content := "# output\n"
	if filepath.Base(path) == "phase2b_output.md" {
		content = "### [VULN-001] SQLi in search\n- **CWE**: CWE-89\n- **Severity**: High\n- **Location**: app/db.py:42\n- **Entry point**: GET /api/search?q=\n- **Data flow**: q -> execute()\n"
	}
	args, _ := json.Marshal(map[string]string{"path": path, "content": content})
	return &client.ChatResponse{Model: "fake",
		Message: client.Message{Role: "assistant", ToolCalls: []client.ToolCall{{ID: "c1", Name: "Write", Arguments: string(args)}}},
	}, nil
}

type staticSkill struct{}

func (staticSkill) Preamble() string                { return "## Operating Principles\nx" }
func (staticSkill) Prompt(f string) (string, error) { return "prompt " + f, nil }

func moduleRoot(t *testing.T) string {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}

func TestArtifactSetParity(t *testing.T) {
	repo := filepath.Join(moduleRoot(t), "testdata", "vulnapp")
	if _, err := os.Stat(repo); err != nil {
		t.Skip("fixture missing")
	}
	results := t.TempDir()
	t.Setenv("VHLOCAL_LEDGER_DIR", filepath.Join(t.TempDir(), "ledger"))
	spec := engine.ScanSpec{
		Repo: repo, ResultsDir: results, Model: "gpt-oss:120b", Host: "h", Backend: "ollama",
		NumCtx: 4096, Phases: []string{"1", "2", "2b", "4"}, MaxPartitions: 8,
		EngineVersion: "0.1.0", QualityStrictness: "balanced", Ledger: true, Remediate: true,
		ScanTag: "2026-09-15-000000",
	}
	if _, err := engine.Execute(context.Background(), spec, engine.Providers{Hunt: fakeProvider{}}, staticSkill{}, nil); err != nil {
		t.Fatal(err)
	}

	// The artifact set the spec/contracts declare a scan produces.
	required := []string{
		"scan_meta.json", "findings.json", "findings.sarif", "coverage_ledger.json",
		"run_manifest.json", "authz_map.json", "candidate_manifest.json",
		"artifact_manifest.json", "SCAN_REPORT.md", "SCAN_REPORT.html",
		"phase1_output.md", "phase2b_output.md", "README.md",
	}
	for _, name := range required {
		if _, err := os.Stat(filepath.Join(results, name)); err != nil {
			t.Errorf("missing declared artifact %q", name)
		}
	}
	// results/ dir with per-agent hunt output.
	if entries, _ := os.ReadDir(filepath.Join(results, "results")); len(entries) == 0 {
		t.Error("missing per-agent hunt output under results/")
	}
	// remediation tree (opt-in, requested).
	if _, err := os.Stat(filepath.Join(results, "remediation", "index.json")); err != nil {
		t.Errorf("missing remediation/index.json")
	}

	// findings.json top-level blocks.
	b, _ := os.ReadFile(filepath.Join(results, "findings.json"))
	var doc map[string]any
	if json.Unmarshal(b, &doc) != nil {
		t.Fatal("findings.json invalid")
	}
	for _, k := range []string{"meta", "attribution", "run_status", "coverage", "counts",
		"assessment", "verification", "vulnerability_counts", "hypothesis_counts",
		"lifecycle", "vulnerability_ledger", "chains", "remediation",
		"application_intelligence", "findings"} {
		if _, ok := doc[k]; !ok {
			t.Errorf("findings.json missing declared block %q", k)
		}
	}
}
