package engine

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"vhlocal/internal/client"
)

// neverWrites always asks for a Glob and never writes a deliverable → every
// phase produces no output (a broken pipeline). It reports per-turn tokens so
// usage accounting can be asserted.
type neverWrites struct{ turns int }

func (neverWrites) Backend() client.Backend { return "fake" }
func (neverWrites) Endpoint() string        { return "fake://local" }
func (n *neverWrites) Chat(_ context.Context, req client.ChatRequest) (*client.ChatResponse, error) {
	return &client.ChatResponse{
		Model:   "m",
		Message: client.Message{Role: "assistant", ToolCalls: []client.ToolCall{{ID: "g", Name: "Glob", Arguments: `{"pattern":"*.py"}`}}},
		Usage:   client.Usage{PromptTokens: 5, CompletionTokens: 2},
	}, nil
}

func brokenSpec(repo, results string) ScanSpec {
	return ScanSpec{
		Repo: repo, ResultsDir: results, Model: "gpt-oss:120b", Host: "h", Backend: "ollama",
		NumCtx: 4096, Phases: []string{"1", "2", "2b", "4"}, MaxPartitions: 8,
		EngineVersion: "0.1.0", QualityStrictness: "balanced", ScanTag: "2026-09-15-000001",
	}
}

func loadFindings(t *testing.T, dir string) map[string]any {
	t.Helper()
	b, _ := os.ReadFile(filepath.Join(dir, "findings.json"))
	var d map[string]any
	if json.Unmarshal(b, &d) != nil {
		t.Fatal("findings.json invalid")
	}
	return d
}

// C-C1 / C-S1/2 / C-U1: a broken (never-writes) run reports honestly.
func TestBrokenRunHonestCoverageAndStatus(t *testing.T) {
	repo := filepath.Join(repoRoot(t), "testdata", "vulnapp")
	results := t.TempDir()
	rec, err := Execute(context.Background(), brokenSpec(repo, results), Providers{Hunt: &neverWrites{}}, staticSkill{}, nil)
	if err != nil {
		t.Fatal(err)
	}

	// C-C1: hunt produced nothing → zero routes reviewed_no_issue.
	var cl map[string]any
	b, _ := os.ReadFile(filepath.Join(results, "coverage_ledger.json"))
	json.Unmarshal(b, &cl)
	counts, _ := cl["counts"].(map[string]any)
	if rev, ok := counts["reviewed_no_issue"]; ok && rev.(float64) != 0 {
		t.Errorf("empty hunt must yield 0 reviewed_no_issue, got %v", rev)
	}
	if cl["complete"].(bool) {
		t.Error("a review-nothing run must not be coverage-complete")
	}

	// C-S1/2: degraded reasons name recon-no-map + hunt-no-candidates + failed agents.
	doc := loadFindings(t, results)
	rs := doc["run_status"].(map[string]any)
	reasons := ""
	for _, r := range rs["coverage_degraded_reasons"].([]any) {
		reasons += r.(string) + "|"
	}
	for _, want := range []string{"recon produced no attack-surface map", "hunt produced no candidates"} {
		if !contains2(reasons, want) {
			t.Errorf("degraded reasons missing %q; got %q", want, reasons)
		}
	}
	if rs["coverage_status"] != "degraded" {
		t.Errorf("coverage_status = %v want degraded", rs["coverage_status"])
	}

	// C-U1: usage.calls == sum(agent turns) (+ repairs; none here). Not agent count.
	sumTurns := 0
	for _, a := range rec.Agents {
		sumTurns += a.Turns
	}
	calls := intOfUsage(rec.Usage["calls"])
	if calls != sumTurns {
		t.Errorf("usage.calls=%d want sum(turns)=%d (agents=%d)", calls, sumTurns, len(rec.Agents))
	}
	if len(rec.Agents) > 0 && calls == len(rec.Agents) && sumTurns != len(rec.Agents) {
		t.Error("usage.calls looks like agent count, not turn count")
	}
}

// C-U3: per-agent token attribution.
func TestPerAgentTokens(t *testing.T) {
	repo := filepath.Join(repoRoot(t), "testdata", "vulnapp")
	results := t.TempDir()
	rec, err := Execute(context.Background(), brokenSpec(repo, results), Providers{Hunt: &neverWrites{}}, staticSkill{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	sumP, sumC := 0, 0
	for _, a := range rec.Agents {
		if a.PromptTokens == 0 && a.Turns > 0 {
			t.Errorf("agent %s has turns=%d but 0 prompt_tokens", a.Label, a.Turns)
		}
		sumP += a.PromptTokens
		sumC += a.CompletionTokens
	}
	if sumP != intOfUsage(rec.Usage["prompt_tokens"]) || sumC != intOfUsage(rec.Usage["completion_tokens"]) {
		t.Errorf("per-agent token sums (%d/%d) != run totals (%v/%v)", sumP, sumC, rec.Usage["prompt_tokens"], rec.Usage["completion_tokens"])
	}
}

// C-L1: broken run with a PRIOR report present → lifecycle suppressed, no fixed dump.
func TestLifecycleSuppressedOnUnreliableRun(t *testing.T) {
	repo := filepath.Join(repoRoot(t), "testdata", "vulnapp")
	base := t.TempDir()

	// Plant a prior reliable report of the same repo with findings + fixed_keys.
	prior := filepath.Join(base, "prior_VULNHUNT_RESULTS_m_2026-09-14-000000")
	os.MkdirAll(prior, 0o755)
	os.WriteFile(filepath.Join(prior, "scan_meta.json"),
		[]byte(`{"repo":"`+repo+`","started_at":1.0,"model":"m","git_commit":"abc"}`), 0o644)
	os.WriteFile(filepath.Join(prior, "findings.json"),
		[]byte(`{"findings":[{"id":"VULN-001","cwe":"CWE-89","normalized_cwe":"CWE-89","location":"app/db.py:21","root_cause_key":"sql-injection:db.py:execute:q","duplicate_of":null}],"lifecycle":{"fixed_keys":[]}}`), 0o644)

	// Broken current run under base (so findPriorReport sees the sibling prior).
	results := filepath.Join(base, "cur_VULNHUNT_RESULTS_m_2026-09-15-000002")
	spec := brokenSpec(repo, results)
	if _, err := Execute(context.Background(), spec, Providers{Hunt: &neverWrites{}}, staticSkill{}, nil); err != nil {
		t.Fatal(err)
	}
	doc := loadFindings(t, results)
	lc := doc["lifecycle"].(map[string]any)
	if lc["comparison_status"] != "suppressed_unreliable_run" {
		t.Fatalf("lifecycle not suppressed on broken run: %v", lc["comparison_status"])
	}
	if ff, _ := lc["fixed_findings"].([]any); len(ff) != 0 {
		t.Errorf("suppressed lifecycle must emit no fixed_findings, got %d", len(ff))
	}
	if fk, _ := lc["fixed_keys"].([]any); len(fk) != 0 {
		t.Errorf("suppressed lifecycle must emit no fixed_keys, got %d", len(fk))
	}
	// bounded: the block must be small (no ~56KB false-fixed dump).
	if bz, _ := json.Marshal(lc); len(bz) > 2000 {
		t.Errorf("suppressed lifecycle block too large: %d bytes", len(bz))
	}
}

// C-L2 / [T1]: a reliable run (recon+hunt produced output, execution complete)
// reconciles normally even if coverage is degraded — it is NOT suppressed.
func TestReliableRunReconciles(t *testing.T) {
	repo := sinkRepo(t)
	results := t.TempDir()
	spec := ScanSpec{
		Repo: repo, ResultsDir: results, Model: "gpt-oss:120b", Host: "h", Backend: "ollama",
		NumCtx: 4096, Phases: []string{"1", "2", "2b", "4"}, MaxPartitions: 8,
		EngineVersion: "0.1.0", QualityStrictness: "balanced", ScanTag: "2026-09-15-000003",
	}
	// Hunt writes real deliverables and verification submits a complete review.
	if _, err := Execute(context.Background(), spec, Providers{Hunt: &pathWriter{model: "m"}, Verify: verifyingProvider{verdict: "supported"}}, staticSkill{}, nil); err != nil {
		t.Fatal(err)
	}
	doc := loadFindings(t, results)
	lc := doc["lifecycle"].(map[string]any)
	if lc["comparison_status"] == "suppressed_unreliable_run" {
		t.Errorf("a reliable run must reconcile lifecycle, not suppress it: %v", lc)
	}
	// And it should be a clean-vs-broken-distinct reliable run (execution complete).
	if doc["run_status"].(map[string]any)["execution_status"] != "complete" {
		t.Errorf("expected execution complete for the reliable run")
	}
}

func intOfUsage(v any) int {
	switch n := v.(type) {
	case int:
		return n
	case float64:
		return int(n)
	}
	return -1
}

func contains2(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
