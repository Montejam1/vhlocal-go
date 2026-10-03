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

func agentLabels(rec *RunRecord) []string {
	var out []string
	for _, a := range rec.Agents {
		out = append(out, a.Label)
	}
	return out
}

func anyHasSuffix(labels []string, suffix string) bool {
	for _, l := range labels {
		if strings.HasSuffix(l, suffix) {
			return true
		}
	}
	return false
}

func manifestMode2(t *testing.T, dir string) string {
	t.Helper()
	b, _ := os.ReadFile(filepath.Join(dir, "run_manifest.json"))
	var m map[string]any
	json.Unmarshal(b, &m)
	if v, ok := m["phase2_mode"].(string); ok {
		return v
	}
	// nested under a block
	for _, v := range m {
		if sub, ok := v.(map[string]any); ok {
			if s, ok := sub["phase2_mode"].(string); ok {
				return s
			}
		}
	}
	return ""
}

// C-2c: split mode dispatches one agent per (partition × INJ/NAV/LOG) plus the
// sink-driven pass, and the manifest records the executed mode.
func TestHuntClassSplitAndMode(t *testing.T) {
	repo := filepath.Join(repoRoot(t), "testdata", "vulnapp")
	results := t.TempDir()
	rec, err := Execute(context.Background(), brokenSpec(repo, results), Providers{Hunt: &pathWriter{model: "m"}}, staticSkill{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	labels := agentLabels(rec)
	for _, suf := range []string{":inj", ":nav", ":log"} {
		if !anyHasSuffix(labels, suf) {
			t.Errorf("split hunt must dispatch a %s class agent; labels=%v", suf, labels)
		}
	}
	found := false
	for _, l := range labels {
		if l == "hunt:sink" {
			found = true
		}
	}
	if !found {
		t.Errorf("split hunt must run the sink-driven pass; labels=%v", labels)
	}
	if rec.Phase2Mode != "split" {
		t.Errorf("executed mode = %q want split", rec.Phase2Mode)
	}
	if manifestMode2(t, results) != "split" {
		t.Errorf("manifest phase2_mode = %q want split", manifestMode2(t, results))
	}
}

// C-2c: combined mode runs one hunt agent per partition (no class split) and the
// manifest records "combined".
func TestHuntCombinedMode(t *testing.T) {
	repo := filepath.Join(repoRoot(t), "testdata", "vulnapp")
	results := t.TempDir()
	spec := brokenSpec(repo, results)
	spec.Phase2Mode = "combined"
	rec, err := Execute(context.Background(), spec, Providers{Hunt: &pathWriter{model: "m"}}, staticSkill{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	labels := agentLabels(rec)
	if anyHasSuffix(labels, ":inj") {
		t.Errorf("combined mode must NOT split into class agents; labels=%v", labels)
	}
	if rec.Phase2Mode != "combined" || manifestMode2(t, results) != "combined" {
		t.Errorf("combined mode not recorded: rec=%q manifest=%q", rec.Phase2Mode, manifestMode2(t, results))
	}
}

// C-2d: sample merge unions candidate blocks by identity and counts distinct-sample
// votes (not per-prose).
func TestMergeSamplesVotes(t *testing.T) {
	s1 := "# Candidate A\n\nSQL injection at app/db.py:21 (CWE-89)\n"
	s2 := "# Candidate A (restated)\n\nThe same sink app/db.py:21 is CWE-89 injectable\n"
	s3 := "# Candidate B\n\nXSS at app/views.py:10 (CWE-79)\n"
	merged, entries := mergeSamples([]string{s1, s2, s3}, "backend", "inj")
	if !strings.Contains(merged, "union of 3 hunt samples") {
		t.Errorf("merged header missing; got:\n%s", merged)
	}
	// A: reported by 2 distinct samples (grouped by location+CWE); B by 1.
	var aVotes, bVotes int
	for _, e := range entries {
		for _, k := range e.Keys {
			if strings.Contains(k, "db.py:21") {
				aVotes = e.Votes
			}
			if strings.Contains(k, "views.py:10") {
				bVotes = e.Votes
			}
		}
	}
	if aVotes != 2 {
		t.Errorf("candidate A should have 2 votes (2 distinct samples), got %d", aVotes)
	}
	if bVotes != 1 {
		t.Errorf("candidate B should have 1 vote, got %d", bVotes)
	}
}

// C-2d: hunt_samples>1 runs N samples per unit (writes .sN files).
func TestHuntSamplesWritesSampleFiles(t *testing.T) {
	repo := filepath.Join(repoRoot(t), "testdata", "vulnapp")
	results := t.TempDir()
	spec := brokenSpec(repo, results)
	spec.HuntSamples = 2
	if _, err := Execute(context.Background(), spec, Providers{Hunt: &pathWriter{model: "m"}}, staticSkill{}, nil); err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(filepath.Join(results, "results"))
	sampleFiles := 0
	for _, e := range entries {
		if strings.Contains(e.Name(), ".s1.") || strings.Contains(e.Name(), ".s2.") {
			sampleFiles++
		}
	}
	if sampleFiles == 0 {
		t.Errorf("hunt_samples=2 must produce per-sample files; got %v", dirNames(entries))
	}
}

func dirNames(es []os.DirEntry) []string {
	var out []string
	for _, e := range es {
		out = append(out, e.Name())
	}
	return out
}

// C-2e: hasIaC detects infra files and is false for a plain app.
func TestHasIaC(t *testing.T) {
	repo := t.TempDir()
	os.WriteFile(filepath.Join(repo, "app.py"), []byte("x=1\n"), 0o644)
	if hasIaC(repo) {
		t.Error("a plain app must not be detected as IaC")
	}
	os.WriteFile(filepath.Join(repo, "Dockerfile"), []byte("FROM scratch\n"), 0o644)
	if !hasIaC(repo) {
		t.Error("a Dockerfile must be detected as IaC")
	}
}

// tableRecon writes a Phase-1 output containing a Subgraph-Partitions table, and
// finding markdown for hunt units — to exercise US1's model-table partition parse.
type tableRecon struct{}

func (tableRecon) Backend() client.Backend { return "fake" }
func (tableRecon) Endpoint() string        { return "fake://local" }
func (tableRecon) Chat(_ context.Context, req client.ChatRequest) (*client.ChatResponse, error) {
	if n := len(req.Messages); n > 0 && req.Messages[n-1].Role == "tool" {
		return &client.ChatResponse{Message: client.Message{Role: "assistant", Content: "done"}, Usage: client.Usage{PromptTokens: 5, CompletionTokens: 2}}, nil
	}
	task := ""
	for _, m := range req.Messages {
		if m.Role == "user" {
			task = m.Content
		}
	}
	all := reOutPath.FindAllString(task, -1)
	path := ""
	if len(all) > 0 {
		path = all[len(all)-1]
	}
	content := "# output\n"
	if strings.Contains(path, "phase1_output.md") {
		content = "## Subgraph Partitions\n\n| ID | Subsystem | Entry points |\n|----|----|----|\n| SG-1 | auth | POST /login |\n| SG-2 | orders | GET /orders |\n\n## Next\n(end)\n"
	} else if strings.Contains(path, "/results/") {
		content = "## Findings\n\n### [VULN-001] SQLi\n\n- **CWE**: CWE-89\n- **Location**: app/db.py:21\n"
	}
	args, _ := json.Marshal(map[string]string{"path": path, "content": content})
	return &client.ChatResponse{Model: "m",
		Message: client.Message{Role: "assistant", ToolCalls: []client.ToolCall{{ID: "c1", Name: "Write", Arguments: string(args)}}},
		Usage:   client.Usage{PromptTokens: 10, CompletionTokens: 4}}, nil
}

// canaryFailer succeeds every call EXCEPT the hunt canary preflight, which it
// fails with a transport (KindGeneric) error — to exercise the canary abort.
type canaryFailer struct{ pw *pathWriter }

func (canaryFailer) Backend() client.Backend { return "fake" }
func (canaryFailer) Endpoint() string        { return "fake://canary" }
func (c canaryFailer) Chat(ctx context.Context, req client.ChatRequest) (*client.ChatResponse, error) {
	for _, m := range req.Messages {
		if strings.Contains(m.Content, "Reply with exactly one word: READY") {
			return nil, &client.TransportError{Backend: "fake", Endpoint: "fake://canary",
				Msg: "connection refused", Kind: client.KindGeneric}
		}
	}
	return c.pw.Chat(ctx, req)
}

// C-4c (feature 006, FR-014): a transport canary failure halts the hunt before
// fan-out with a recorded reason, and dispatches no hunt agents.
func TestHuntCanaryHaltsOnTransportFailure(t *testing.T) {
	repo := filepath.Join(repoRoot(t), "testdata", "vulnapp")
	results := t.TempDir()
	rec, err := Execute(context.Background(), brokenSpec(repo, results),
		Providers{Hunt: canaryFailer{pw: &pathWriter{model: "m"}}}, staticSkill{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(rec.HuntHaltedReason, "canary") {
		t.Errorf("a transport canary failure must halt the hunt with a recorded reason, got %q", rec.HuntHaltedReason)
	}
	for _, l := range agentLabels(rec) {
		if strings.HasPrefix(l, "hunt:") {
			t.Errorf("no hunt agent should dispatch after a canary abort; got %v", agentLabels(rec))
			break
		}
	}
}

// C-1a end-to-end: a Phase-1 partition table drives a multi-partition hunt, and the
// resolution is recorded as model_table.
func TestHuntUsesModelPartitionTable(t *testing.T) {
	repo := filepath.Join(repoRoot(t), "testdata", "vulnapp")
	results := t.TempDir()
	rec, err := Execute(context.Background(), brokenSpec(repo, results), Providers{Hunt: tableRecon{}}, staticSkill{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if rec.PartitionSource != "model_table" {
		t.Errorf("partition_source = %q want model_table", rec.PartitionSource)
	}
	// The hunt dispatched over the parsed partitions (SG-1 auth, SG-2 orders).
	labels := strings.Join(agentLabels(rec), " ")
	if !strings.Contains(labels, "hunt:sg-1:") || !strings.Contains(labels, "hunt:sg-2:") {
		t.Errorf("hunt did not fan out over the parsed partitions; labels=%s", labels)
	}
}

// The partition resolution is always recorded (idents SG-N), even on the
// deterministic fallback path.
func TestHuntRecordsPartitionResolution(t *testing.T) {
	repo := filepath.Join(repoRoot(t), "testdata", "vulnapp")
	results := t.TempDir()
	rec, err := Execute(context.Background(), brokenSpec(repo, results), Providers{Hunt: &pathWriter{model: "m"}}, staticSkill{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if rec.PartitionSource == "" {
		t.Error("partition_source must be recorded")
	}
	for _, id := range rec.Partitions {
		if !strings.HasPrefix(id, "SG-") {
			t.Errorf("partition idents should be SG-N, got %v", rec.Partitions)
			break
		}
	}
}
