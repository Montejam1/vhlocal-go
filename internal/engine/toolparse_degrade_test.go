package engine

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"vhlocal/internal/client"
)

// phaseFailer behaves like pathWriter (writes the deliverable named in the task,
// then completes) EXCEPT for the phase whose task names failSubstr, where it
// returns a generic (non-parse) endpoint failure — an unrecoverable per-phase
// outage. Offline; no network.
type phaseFailer struct{ failSubstr string }

func (phaseFailer) Backend() client.Backend { return "fake" }
func (phaseFailer) Endpoint() string        { return "fake://local" }

func (f *phaseFailer) Chat(_ context.Context, req client.ChatRequest) (*client.ChatResponse, error) {
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
	if f.failSubstr != "" && strings.Contains(task, f.failSubstr) {
		return nil, &client.TransportError{Backend: "fake", Endpoint: "fake://local",
			Status: 500, Kind: client.KindGeneric, Msg: "connection reset by peer", Retryable: false}
	}
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
	return &client.ChatResponse{Model: "m",
		Message: client.Message{Role: "assistant", ToolCalls: []client.ToolCall{{ID: "c1", Name: "Write", Arguments: string(args)}}},
		Usage:   client.Usage{PromptTokens: 10, CompletionTokens: 4}}, nil
}

// alwaysEndpointError fails every call at the endpoint (systemic outage).
type alwaysEndpointError struct{}

func (alwaysEndpointError) Backend() client.Backend { return "fake" }
func (alwaysEndpointError) Endpoint() string        { return "fake://local" }
func (alwaysEndpointError) Chat(context.Context, client.ChatRequest) (*client.ChatResponse, error) {
	return nil, &client.TransportError{Backend: "fake", Endpoint: "fake://local",
		Status: 500, Kind: client.KindGeneric, Msg: "outage", Retryable: false}
}

func runStatus(t *testing.T, dir string) map[string]any {
	t.Helper()
	doc := loadFindings(t, dir)
	rs, _ := doc["run_status"].(map[string]any)
	if rs == nil {
		t.Fatal("run_status missing")
	}
	return rs
}

func degradedReasons(rs map[string]any) string {
	s := ""
	for _, r := range rs["coverage_degraded_reasons"].([]any) {
		s += r.(string) + "|"
	}
	return s
}

// C-E1/E2/E3: one phase fails unrecoverably at the endpoint → that phase degrades,
// the remaining phases still run, the full artifact set is finalized, status is
// partial with the endpoint failure named, and scan_meta.aborted is NOT set.
func TestPerPhaseEndpointFailureDegradesNotAborts(t *testing.T) {
	repo := filepath.Join(repoRoot(t), "testdata", "vulnapp")
	results := t.TempDir()
	spec := brokenSpec(repo, results) // phases 1, 2, 2b, 4
	// Fail the phase-2b verification session (its per-candidate prompt), not the
	// hunt or report — the verification session is now what phase 2b runs.
	rec, err := Execute(context.Background(), spec, Providers{Hunt: &phaseFailer{failSubstr: "Verify EXACTLY this one candidate"}}, staticSkill{}, nil)
	if err != nil {
		t.Fatalf("a per-phase endpoint failure must not error the whole scan: %v", err)
	}

	// C-E1: full artifact set finalized despite the failed phase.
	for _, name := range []string{"scan_meta.json", "findings.json", "findings.sarif",
		"run_manifest.json", "SCAN_REPORT.md", "coverage_ledger.json"} {
		if _, statErr := os.Stat(filepath.Join(results, name)); statErr != nil {
			t.Errorf("missing artifact %s after a degraded phase", name)
		}
	}
	// C-E1: the remaining phases still ran (recon produced its map; 2b did not).
	if !contains2(strings.Join(rec.PhasesCompleted, "|"), "1") {
		t.Errorf("recon (phase 1) should have completed; completed=%v", rec.PhasesCompleted)
	}
	if contains2(strings.Join(rec.PhasesCompleted, "|"), "2b") {
		t.Errorf("the failed phase 2b must not be marked completed; completed=%v", rec.PhasesCompleted)
	}
	// C-E3: a single phase's endpoint failure does not set scan_meta.aborted.
	if rec.Aborted != "" {
		t.Errorf("a single-phase endpoint failure must not abort the run; aborted=%q", rec.Aborted)
	}
	// C-E2: status partial + endpoint failure named; distinct from a clean run.
	rs := runStatus(t, results)
	if rs["execution_status"] == "complete" || rs["execution_status"] == "aborted" {
		t.Errorf("execution_status=%v want partial/incomplete", rs["execution_status"])
	}
	if !contains2(degradedReasons(rs), "phase 2b endpoint failure") {
		t.Errorf("degraded reasons must name the endpoint-failed phase; got %q", degradedReasons(rs))
	}
	if rs["coverage_status"] != "degraded" {
		t.Errorf("coverage_status=%v want degraded", rs["coverage_status"])
	}
}

// C-E4: a systemic outage (every phase fails at the endpoint) is reported as a
// failed/incomplete run with the endpoint error surfaced, lifecycle suppressed,
// artifacts still finalized — never clean, and not aborted (degraded, not abort).
func TestSystemicOutageReportedFailed(t *testing.T) {
	repo := filepath.Join(repoRoot(t), "testdata", "vulnapp")
	results := t.TempDir()
	spec := brokenSpec(repo, results)
	rec, err := Execute(context.Background(), spec, Providers{Hunt: alwaysEndpointError{}}, staticSkill{}, nil)
	if err != nil {
		t.Fatalf("a systemic outage must still finalize, not error: %v", err)
	}
	for _, name := range []string{"scan_meta.json", "findings.json", "SCAN_REPORT.md"} {
		if _, statErr := os.Stat(filepath.Join(results, name)); statErr != nil {
			t.Errorf("missing artifact %s after a systemic outage", name)
		}
	}
	rs := runStatus(t, results)
	if rs["execution_status"] != "partial" {
		t.Errorf("only deterministic reporting completed during outage; want partial, got %v", rs["execution_status"])
	}
	if containsStr(rec.PhasesCompleted, "1") || containsStr(rec.PhasesCompleted, "2") || containsStr(rec.PhasesCompleted, "2b") {
		t.Errorf("outage completed a model phase: %v", rec.PhasesCompleted)
	}
	if !contains2(degradedReasons(rs), "endpoint failure") {
		t.Errorf("systemic outage must surface the endpoint failure; reasons=%q", degradedReasons(rs))
	}
	if rec.Aborted != "" {
		t.Errorf("a systemic endpoint outage degrades every phase; it is not a cancellation abort; aborted=%q", rec.Aborted)
	}
	// Lifecycle suppressed on the unreliable run (feature 003 invariant preserved).
	doc := loadFindings(t, results)
	lc := doc["lifecycle"].(map[string]any)
	if lc["comparison_status"] != "suppressed_unreliable_run" {
		t.Errorf("a total-outage run must suppress lifecycle, got %v", lc["comparison_status"])
	}
}
