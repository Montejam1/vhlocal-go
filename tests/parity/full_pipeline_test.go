package parity

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"vhlocal/internal/client"
	"vhlocal/internal/engine"
	"vhlocal/internal/verification"
	"vhlocal/tests/parity/transcript"
)

// The reproduction fixture supplies authored material, never execution results.
// Expected outcomes below are explicit contract assertions, not a Go-generated golden.
type artifactProvider struct{ authorCalls int }

func (*artifactProvider) Backend() client.Backend { return "fake" }
func (*artifactProvider) Endpoint() string        { return "fake://artifacts" }

var reFPDeliv = regexp.MustCompile(`(/[^\s]+/repro/(CAND-[a-f0-9]+)\.json)`)
var reFPCand = regexp.MustCompile(`(CAND-[a-f0-9]+) \| (CWE-[0-9]+) \| ([^\s|]+)`)

// Per-candidate reproduction protocol (feature 007): one supported candidate per
// call; author a valid test for the SQL sink and an explicit deferral for the
// command-injection sink. The harness owns artifact_manifest.json.
func (p *artifactProvider) Chat(_ context.Context, req client.ChatRequest) (*client.ChatResponse, error) {
	if len(req.Messages) > 0 && req.Messages[len(req.Messages)-1].Role == "tool" {
		return textResp("done"), nil
	}
	task := lastUser(req)
	if !strings.Contains(task, "Author reproduction material for EXACTLY") {
		return nil, fmt.Errorf("unexpected model phase: %s", task)
	}
	p.authorCalls++
	dm := reFPDeliv.FindStringSubmatch(task)
	if dm == nil {
		return nil, fmt.Errorf("no per-candidate deliverable assignment")
	}
	deliv, id := dm[1], dm[2]
	out := filepath.Dir(filepath.Dir(deliv))
	loc := ""
	if cm := reFPCand.FindStringSubmatch(task); cm != nil {
		loc = cm[3]
	}
	if loc == "app/files.py:16" {
		entry, _ := json.Marshal(verification.ArtifactEntry{CandidateID: id, Kind: "deferred", Reason: "requires an isolated renderer and filesystem fixture"})
		a, _ := json.Marshal(map[string]string{"path": deliv, "content": string(entry)})
		return &client.ChatResponse{Message: client.Message{Role: "assistant",
			ToolCalls: []client.ToolCall{{ID: "d", Name: "Write", Arguments: string(a)}}}}, nil
	}
	if loc != "app/db.py:21" {
		return nil, fmt.Errorf("unverified or unknown candidate handed to reproduction: %s", loc)
	}
	rel := "exploit_tests/" + id + ".py"
	content := fmt.Sprintf("# %s %s\nfrom app.db import build_search_query\n\ndef test_query_composition():\n    payload = \"x' OR 1=1 --\"\n    assert payload in build_search_query(payload, None)\n    assert \"OR 1=1\" not in build_search_query('ordinary', None)\n", id, loc)
	pocArgs, _ := json.Marshal(map[string]string{"path": filepath.Join(out, rel), "content": content})
	entry, _ := json.Marshal(verification.ArtifactEntry{CandidateID: id, Path: rel, Kind: "test", Status: "authored"})
	delivArgs, _ := json.Marshal(map[string]string{"path": deliv, "content": string(entry)})
	return &client.ChatResponse{Message: client.Message{Role: "assistant", ToolCalls: []client.ToolCall{
		{ID: "t", Name: "Write", Arguments: string(pocArgs)},
		{ID: "m", Name: "Write", Arguments: string(delivArgs)},
	}}}, nil
}

func TestFullPipelineArtifactsAndDeterministicPhases(t *testing.T) {
	repo := filepath.Join(moduleRoot(t), "testdata", "vulnapp")
	tr, err := transcript.Load(filepath.Join(moduleRoot(t), "tests", "parity", "transcript", "vulnapp.json"))
	if err != nil {
		t.Fatal(err)
	}
	out := t.TempDir()
	p := transcriptProvider{tr: tr}
	artifacts := &artifactProvider{}
	spec := engine.ScanSpec{Repo: repo, ResultsDir: out, Model: "fixture", Backend: "ollama", Host: "fake", NumCtx: 8192, MaxPartitions: 8, Phases: []string{"1", "2", "2b", "3", "3d", "4"}, QualityStrictness: "balanced"}
	rec, err := engine.Execute(context.Background(), spec, engine.Providers{Hunt: p, Verify: p, Reproduce: artifacts}, staticSkill{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(rec.PhasesCompleted) != 6 || len(rec.ArtifactErrors) > 0 {
		t.Fatalf("incomplete full pipeline: %v errors=%v", rec.PhasesCompleted, rec.ArtifactErrors)
	}
	got, err := Project(out)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Candidates) != 3 || got.RunStatus.Execution != "complete" || got.RunStatus.ValidationMode != "static_reasoning" {
		t.Fatalf("unexpected findings/status: %+v", got)
	}
	if strings.Join(got.Artifacts, ",") != "deferred,test" {
		t.Fatalf("missing reproduction dispositions: %v", got.Artifacts)
	}
	if artifacts.authorCalls != 2 {
		t.Fatalf("expected one authoring call per supported candidate (2), got %d", artifacts.authorCalls)
	}
	for _, a := range rec.Agents {
		if (a.Phase == "3d" || a.Phase == "4") && (a.Model != "deterministic" || a.Turns != 0) {
			t.Fatalf("deterministic phase used a model: %+v", a)
		}
	}
	b, _ := os.ReadFile(filepath.Join(out, "phase3d_output.md"))
	if !strings.Contains(string(b), "app/db.py:26") || !strings.Contains(string(b), "**LEAD**") {
		t.Fatal("sweep omitted sibling SQL sink")
	}
	before, _ := os.ReadFile(filepath.Join(out, "artifact_manifest.json"))
	if err := engine.Regenerate(out); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(filepath.Join(out, "artifact_manifest.json"))
	if string(before) != string(after) {
		t.Fatal("regeneration changed authored artifact records")
	}
	projected, err := Project(out)
	if err != nil {
		t.Fatal(err)
	}
	if diffs := Compare(projected, got); len(diffs) > 0 {
		t.Fatalf("regeneration changed semantic results: %v", diffs)
	}
}
