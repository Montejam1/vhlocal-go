package engine

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"vhlocal/internal/client"
)

// C-C1 (feature 005): an absent/empty verification output yields ZERO findings —
// the raw hunt output is never resurrected.
func TestNoRawResurrection(t *testing.T) {
	results := t.TempDir()
	os.MkdirAll(filepath.Join(results, "results"), 0o755)
	findingMD := "## Findings\n\n### [VULN-001] SQL injection\n\n" +
		"- **CWE**: CWE-89\n- **Severity**: High\n- **Location**: app/db.py:21\n"
	os.WriteFile(filepath.Join(results, "results", "backend_hunt.md"), []byte(findingMD), 0o644)
	// No phase2b_output.md (verification produced nothing / all rejected).
	f, fromConfirmed := collectFindings(results)
	if len(f) != 0 || fromConfirmed {
		t.Errorf("absent 2b must yield zero findings (no raw resurrection); got %d fromConfirmed=%v", len(f), fromConfirmed)
	}
}

// cancelOnChat cancels the run's context on its first Chat, then returns a normal
// tool call so the agent proceeds to a turn where it observes the cancellation.
type cancelOnChat struct {
	cancel context.CancelFunc
	n      int
}

func (*cancelOnChat) Backend() client.Backend { return "fake" }
func (*cancelOnChat) Endpoint() string        { return "fake://local" }
func (c *cancelOnChat) Chat(_ context.Context, req client.ChatRequest) (*client.ChatResponse, error) {
	c.n++
	if c.n == 1 {
		c.cancel()
	}
	return &client.ChatResponse{
		Message: client.Message{Role: "assistant", ToolCalls: []client.ToolCall{{ID: "g", Name: "Glob", Arguments: `{"pattern":"*.py"}`}}},
		Usage:   client.Usage{PromptTokens: 5, CompletionTokens: 2},
	}, nil
}

// C-C5 (feature 005): a cancelled run reports execution_status=cancelled (not
// aborted), never labels the in-flight agent an endpoint failure, and still
// finalizes artifacts.
func TestCancellationStaysCancelled(t *testing.T) {
	repo := filepath.Join(repoRoot(t), "testdata", "vulnapp")
	results := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	rec, _ := Execute(ctx, brokenSpec(repo, results), Providers{Hunt: &cancelOnChat{cancel: cancel}}, staticSkill{}, nil)
	if !rec.Cancelled {
		t.Error("run must be marked cancelled")
	}
	if rec.Aborted != "" {
		t.Errorf("cancellation must not set aborted; got %q", rec.Aborted)
	}
	for _, a := range rec.Agents {
		if a.StoppedReason == "endpoint_failure" {
			t.Errorf("a cancelled agent must not be recorded as endpoint_failure; agent %s", a.Label)
		}
	}
	if _, e := os.Stat(filepath.Join(results, "scan_meta.json")); e != nil {
		t.Error("artifacts must finalize on cancellation")
	}
	rs := runStatus(t, results)
	if rs["execution_status"] != "cancelled" {
		t.Errorf("execution_status=%v want cancelled", rs["execution_status"])
	}
	// No spurious endpoint-failure degradation reason from the cancel.
	if contains2(degradedReasons(rs), "endpoint failure") {
		t.Errorf("cancellation must not produce an endpoint-failure degradation reason; reasons=%q", degradedReasons(rs))
	}
}

// C-C3 (feature 005): report regeneration preserves a real (non-empty) artifact
// manifest instead of overwriting it with [].
func TestArtifactManifestPreservedOnRegenerate(t *testing.T) {
	repo := filepath.Join(repoRoot(t), "testdata", "vulnapp")
	results := t.TempDir()
	if _, err := Execute(context.Background(), brokenSpec(repo, results), Providers{Hunt: &pathWriter{model: "m"}}, staticSkill{}, nil); err != nil {
		t.Fatal(err)
	}
	real := `[{"candidate_id":"CAND-1","path":"exploit_tests/t1.py","status":"authored"}]`
	os.WriteFile(filepath.Join(results, "artifact_manifest.json"), []byte(real), 0o644)
	if err := Regenerate(results); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(results, "artifact_manifest.json"))
	var arr []map[string]any
	if json.Unmarshal(b, &arr) != nil || len(arr) != 1 {
		t.Errorf("regeneration must preserve the real artifact manifest; got: %s", b)
	}
}

// C-C6 (feature 005): deterministic regeneration preserves the real backend (no
// fabricated ollama) and the endpoint-failure degradation reasons.
func TestRegeneratePreservesBackendAndEndpointReasons(t *testing.T) {
	repo := filepath.Join(repoRoot(t), "testdata", "vulnapp")
	results := t.TempDir()
	meta := `{"repo":"` + repo + `","results_dir":"` + results + `","model":"m","backend":"openai","num_ctx":4096,` +
		`"phases_requested":["1","2","2b","4"],"phases_completed":["1","2"],` +
		`"endpoint_failures":["phase 2b endpoint failure: connection reset by peer"],` +
		`"agents":[{"label":"2b","phase":"2b","stopped_reason":"endpoint_failure","turns":1}],` +
		`"usage":{},"engine_version":"x","quality_strictness":"balanced","started_at":1.0,"finished_at":2.0}`
	os.WriteFile(filepath.Join(results, "scan_meta.json"), []byte(meta), 0o644)
	if err := Regenerate(results); err != nil {
		t.Fatal(err)
	}
	mb, _ := os.ReadFile(filepath.Join(results, "run_manifest.json"))
	if !contains2(string(mb), `"openai"`) {
		t.Errorf("regeneration must preserve backend=openai; manifest=%s", mb)
	}
	if contains2(string(mb), `"ollama"`) {
		t.Errorf("regeneration must not fabricate an ollama backend; manifest=%s", mb)
	}
	rs := runStatus(t, results)
	if !contains2(degradedReasons(rs), "phase 2b endpoint failure") {
		t.Errorf("endpoint-failure reason lost on regeneration; reasons=%q", degradedReasons(rs))
	}
}
