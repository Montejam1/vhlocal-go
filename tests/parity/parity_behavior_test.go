package parity

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"vhlocal/internal/client"
	"vhlocal/internal/engine"
	"vhlocal/tests/parity/transcript"
)

func mkVerifyReq(loc string) client.ChatRequest {
	return client.ChatRequest{
		Messages: []client.Message{{Role: "user", Content: "Verify the candidate at " + loc + " (CWE-89)."}},
		Tools:    []client.Tool{{Name: "capture_evidence"}, {Name: "submit_verification"}},
	}
}

// runTranscript runs the Go engine over the shared transcript on testdata/vulnapp
// and returns the results dir (offline; no Ollama, no Python).
func runTranscript(t *testing.T) (string, *transcript.Transcript) {
	t.Helper()
	repo := filepath.Join(moduleRoot(t), "testdata", "vulnapp")
	if _, err := os.Stat(repo); err != nil {
		t.Skip("fixture missing")
	}
	tr, err := transcript.Load(filepath.Join(moduleRoot(t), "tests", "parity", "transcript", "vulnapp.json"))
	if err != nil {
		t.Fatalf("load transcript: %v", err)
	}
	results := t.TempDir()
	t.Setenv("VHLOCAL_LEDGER_DIR", filepath.Join(t.TempDir(), "ledger"))
	spec := engine.ScanSpec{
		Repo: repo, ResultsDir: results, Model: "gpt-oss:120b", Host: "h", Backend: "ollama",
		NumCtx: 8192, Phases: []string{"1", "2", "2b", "4"}, MaxPartitions: 8,
		EngineVersion: "0.1.0", QualityStrictness: "balanced",
		ScanTag: "2026-09-16-000000",
	}
	prov := transcriptProvider{tr: tr}
	if _, err := engine.Execute(context.Background(), spec,
		engine.Providers{Hunt: prov, Verify: prov}, staticSkill{}, nil); err != nil {
		t.Fatalf("engine: %v", err)
	}
	return results, tr
}

func loadGolden(t *testing.T) Projection {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(moduleRoot(t), "tests", "parity", "golden", "vulnapp.json"))
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	var p Projection
	if err := json.Unmarshal(b, &p); err != nil {
		t.Fatalf("parse golden: %v", err)
	}
	return p
}

// C-D1 (feature 006, FR-004/005): the Go engine's projection on the shared fixture
// equals the committed reference-derived expected projection across every dimension.
func TestParityBehavior(t *testing.T) {
	results, _ := runTranscript(t)
	got, err := Project(results)
	if err != nil {
		t.Fatal(err)
	}
	want := loadGolden(t)
	if d := Compare(got, want); len(d) != 0 {
		gb, _ := json.MarshalIndent(got, "", "  ")
		t.Fatalf("projection diverges from expected:\n%v\n--- got ---\n%s", d, gb)
	}
}

// C-D2 (feature 006, FR-007): a seeded divergence (a flipped disposition) makes the
// projection differ from expected, and the comparator names the diverging
// dimension + candidate.
func TestParitySeededDivergence(t *testing.T) {
	results, _ := runTranscript(t)
	got, err := Project(results)
	if err != nil {
		t.Fatal(err)
	}
	want := loadGolden(t)
	// Flip one candidate's disposition in the EXPECTED side.
	var victim string
	for id := range want.Dispositions {
		victim = id
		break
	}
	if victim == "" {
		t.Skip("no dispositions to seed")
	}
	orig := want.Dispositions[victim]
	if orig == "supported" {
		want.Dispositions[victim] = "rejected"
	} else {
		want.Dispositions[victim] = "supported"
	}
	d := Compare(got, want)
	named := false
	for _, dv := range d {
		if dv.Dimension == "dispositions" && dv.Detail == victim {
			named = true
		}
	}
	if !named {
		t.Errorf("a seeded disposition flip must be named by the comparator, got %v", d)
	}
}

// C-D5 (feature 006): the transcript provider errors loudly on a verify candidate
// it has no rule for, so the fixture cannot silently under-exercise verification.
func TestTranscriptCompletenessLoud(t *testing.T) {
	tr := &transcript.Transcript{} // empty: no verify rules
	prov := transcriptProvider{tr: tr}
	req := mkVerifyReq("app/db.py:21")
	if _, err := prov.Chat(context.Background(), req); err == nil {
		t.Errorf("an unmatched verify candidate must error loudly, got nil")
	}
}
