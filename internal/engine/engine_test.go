package engine

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"vhlocal/internal/client"
)

// pathWriter is an offline provider that "follows instructions": on the first
// turn it emits a Write tool call to the output path named in the task; after the
// tool result comes back it completes. For finding-bearing outputs it writes
// finding markdown the extractor understands.
type pathWriter struct{ model string }

var reOutPath = regexp.MustCompile(`(/\S+\.md)`)

func (p *pathWriter) Backend() client.Backend { return "fake" }
func (p *pathWriter) Endpoint() string        { return "fake://local" }

func (p *pathWriter) Chat(_ context.Context, req client.ChatRequest) (*client.ChatResponse, error) {
	// If the last message is a tool result, we're done for this agent.
	if n := len(req.Messages); n > 0 && req.Messages[n-1].Role == "tool" {
		return &client.ChatResponse{Message: client.Message{Role: "assistant", Content: "done"},
			Usage: client.Usage{PromptTokens: 5, CompletionTokens: 2}}, nil
	}
	task := ""
	for _, m := range req.Messages {
		if m.Role == "user" {
			task = m.Content
		}
	}
	// The write target is the LAST .md path named in the task (Reads are listed
	// before it), so pick the last match — matches the real "Write to <path>".
	all := reOutPath.FindAllString(task, -1)
	path := ""
	if len(all) > 0 {
		path = all[len(all)-1]
	}
	content := "# output\n"
	if strings.Contains(path, "phase2b_output.md") || strings.Contains(path, "_hunt.md") || strings.Contains(path, "/results/") {
		content = "## Findings\n\n### [VULN-001] SQL injection in search\n\n" +
			"- **CWE**: CWE-89\n- **Severity**: High\n- **Location**: app/db.py:21\n" +
			"- **Entry point**: GET /api/search?q=\n- **Data flow**: q -> execute()\n- **Fix**: parameterize\n"
	}
	args, _ := json.Marshal(map[string]string{"path": path, "content": content})
	return &client.ChatResponse{
		Model: p.model,
		Message: client.Message{Role: "assistant", ToolCalls: []client.ToolCall{
			{ID: "c1", Name: "Write", Arguments: string(args)},
		}},
		Usage:      client.Usage{PromptTokens: 10, CompletionTokens: 4},
		Provenance: client.Provenance{Backend: "fake", Endpoint: "fake://local", RequestedModel: p.model},
	}, nil
}

// staticSkill returns trivial phase prompts offline.
type staticSkill struct{}

func (staticSkill) Preamble() string                   { return "## Operating Principles\nStay in scope." }
func (staticSkill) Prompt(file string) (string, error) { return "Phase prompt for " + file, nil }

func repoRoot(t *testing.T) string {
	t.Helper()
	wd, _ := os.Getwd()
	return filepath.Clean(filepath.Join(wd, "..", ".."))
}

func TestExecuteProducesArtifactSet(t *testing.T) {
	repo := filepath.Join(repoRoot(t), "testdata", "vulnapp")
	if _, err := os.Stat(repo); err != nil {
		t.Skip("fixture missing")
	}
	results := t.TempDir()
	spec := ScanSpec{
		Repo: repo, ResultsDir: results, SkillDir: "", Model: "gpt-oss:120b",
		Host: "http://localhost:11434", Backend: "ollama", NumCtx: 131072,
		Phases: []string{"1", "2", "2b", "4"}, MaxPartitions: 8, EngineVersion: "0.1.0",
		QualityStrictness: "balanced", ScanTag: "2026-09-14-000000",
	}
	prov := Providers{Hunt: &pathWriter{model: "gpt-oss:120b"}}
	rec, err := Execute(context.Background(), spec, prov, staticSkill{}, nil)
	if err != nil {
		t.Fatal(err)
	}

	// The full artifact set exists.
	for _, name := range []string{
		"scan_meta.json", "findings.json", "findings.sarif", "coverage_ledger.json",
		"run_manifest.json", "SCAN_REPORT.md", "SCAN_REPORT.html", "phase1_output.md",
		"phase2b_output.md",
	} {
		if _, err := os.Stat(filepath.Join(results, name)); err != nil {
			t.Errorf("missing artifact %s", name)
		}
	}

	// findings.json carries the top-level blocks and the extracted finding.
	b, _ := os.ReadFile(filepath.Join(results, "findings.json"))
	var doc map[string]any
	if json.Unmarshal(b, &doc) != nil {
		t.Fatal("findings.json invalid")
	}
	for _, k := range []string{"meta", "attribution", "run_status", "coverage", "counts",
		"assessment", "lifecycle", "application_intelligence", "findings"} {
		if _, ok := doc[k]; !ok {
			t.Errorf("findings.json missing block %q", k)
		}
	}
	findings := doc["findings"].([]any)
	if len(findings) == 0 {
		t.Fatal("expected at least one extracted finding")
	}
	f0 := findings[0].(map[string]any)
	if f0["normalized_cwe"] != "CWE-89" { // knowledge normalization applied
		t.Errorf("finding not normalized: %v", f0["normalized_cwe"])
	}
	// Under US3, pathWriter does not run the verification protocol (it never submits
	// a decision), so the candidate is honestly unresolved and NOT from_confirmed —
	// confirmation now requires a real, evidence-backed supported verdict.
	if f0["from_confirmed"] == true {
		t.Errorf("finding must not be from_confirmed without a supported verification decision")
	}
	if f0["verification_status"] != "unresolved" {
		t.Errorf("unverified candidate should be unresolved, got %v", f0["verification_status"])
	}

	// scan_meta records engine-observed phases + agents (Principle I).
	if len(rec.PhasesCompleted) == 0 || len(rec.Agents) == 0 {
		t.Errorf("scan_meta missing phases/agents: %+v", rec.PhasesCompleted)
	}
	// three status axes present in findings.json.
	rs := doc["run_status"].(map[string]any)
	for _, axis := range []string{"execution_status", "coverage_status", "validation_mode"} {
		if _, ok := rs[axis]; !ok {
			t.Errorf("run_status missing axis %q", axis)
		}
	}
	if rs["validation_mode"] != "static_reasoning" {
		t.Errorf("validation_mode = %v want static_reasoning", rs["validation_mode"])
	}
}

func TestResumeSkipsCompletedPhases(t *testing.T) {
	repo := filepath.Join(repoRoot(t), "testdata", "vulnapp")
	results := t.TempDir()
	base := ScanSpec{
		Repo: repo, ResultsDir: results, Model: "m", Host: "h", Backend: "ollama",
		NumCtx: 1024, Phases: []string{"1"}, MaxPartitions: 4, EngineVersion: "0.1.0",
	}
	prov := Providers{Hunt: &pathWriter{model: "m"}}
	if _, err := Execute(context.Background(), base, prov, staticSkill{}, nil); err != nil {
		t.Fatal(err)
	}
	// Second run with resume: phase 1 should be skipped (valid deliverable).
	base.Resume = true
	rec, err := Execute(context.Background(), base, prov, staticSkill{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	skipped := false
	for _, k := range rec.PhasesSkipped {
		if k == "1" {
			skipped = true
		}
	}
	if !skipped {
		t.Errorf("resume should skip phase 1; skipped=%v completed=%v", rec.PhasesSkipped, rec.PhasesCompleted)
	}
}
