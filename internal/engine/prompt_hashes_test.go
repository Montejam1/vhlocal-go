package engine

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"vhlocal/internal/client"
)

// Feature 015 (FR-027/029, T009): every prompt record carries the sha256 of the
// system text and tool envelope actually sent; 2b records name their candidate and
// in-session validation feedback is recorded as kind=repair; scan_meta carries the
// per-phase hashes.
func TestPromptRecordsCarryHashesAndCandidateIdentity(t *testing.T) {
	results := t.TempDir()
	sink, err := newPromptSink(results)
	if err != nil {
		t.Fatal(err)
	}
	inner := &pathWriter{model: "m"}
	tools := []client.Tool{{Name: "Read"}, {Name: "submit_verification"}}
	p := recordPrompts(inner, sink, promptMeta{scanTag: "t", phase: "2b", label: "verify", role: "verify", model: "m"})
	// Main 2b call: system + candidate task.
	_, _ = p.Chat(context.Background(), client.ChatRequest{Tools: tools, Messages: []client.Message{
		{Role: "system", Content: "You verify one candidate."},
		{Role: "user", Content: "Verify EXACTLY this one candidate.\n\nCandidate: CAND-0123456789abcdef01234567\nTitle: x\n"},
	}})
	// In-session repair feedback (3 messages, last user turn is validation feedback).
	_, _ = p.Chat(context.Background(), client.ChatRequest{Tools: tools, Messages: []client.Message{
		{Role: "system", Content: "You verify one candidate."},
		{Role: "user", Content: "Verify EXACTLY this one candidate.\n\nCandidate: CAND-0123456789abcdef01234567\n"},
		{Role: "assistant", Content: ""},
		{Role: "user", Content: "Contract violated — quotes must byte-match the live source. Correct the submission or submit 'unresolved' with a reason."},
	}})
	// A hunt call with a different system prompt → different hash, no candidate.
	ph := recordPrompts(inner, sink, promptMeta{scanTag: "t", phase: "2", label: "hunt:sg-1:inj", role: "hunt", model: "m"})
	_, _ = ph.Chat(context.Background(), client.ChatRequest{Tools: tools[:1], Messages: []client.Message{
		{Role: "system", Content: "You hunt."}, {Role: "user", Content: "Write to /r/results/sg-1_inj.md"},
	}})
	sink.Close()

	f, err := os.Open(filepath.Join(results, PromptsFile))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var recs []PromptRecord
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var r PromptRecord
		if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
			t.Fatal(err)
		}
		recs = append(recs, r)
	}
	if len(recs) != 3 {
		t.Fatalf("records = %d, want 3", len(recs))
	}
	main2b, repair2b, hunt := recs[0], recs[1], recs[2]
	if main2b.CandidateID != "CAND-0123456789abcdef01234567" || main2b.Label != "verify:CAND-0123456789abcdef01234567" {
		t.Errorf("2b record lacks candidate identity: %+v", main2b)
	}
	if main2b.Kind != "main" || repair2b.Kind != "repair" {
		t.Errorf("kinds = %s/%s, want main/repair", main2b.Kind, repair2b.Kind)
	}
	if len(main2b.PromptHash) != 64 || main2b.PromptHash != repair2b.PromptHash {
		t.Errorf("prompt hash must be the sha256 of the same system text: %q vs %q", main2b.PromptHash, repair2b.PromptHash)
	}
	if main2b.PromptHash == hunt.PromptHash {
		t.Error("different system prompts must hash differently")
	}
	if len(main2b.ToolSchemaHash) != 64 || main2b.ToolSchemaHash == hunt.ToolSchemaHash {
		t.Errorf("tool schema hash must reflect the envelope sent: %q vs %q", main2b.ToolSchemaHash, hunt.ToolSchemaHash)
	}
	if hunt.CandidateID != "" {
		t.Errorf("hunt record must not carry a candidate id: %q", hunt.CandidateID)
	}
	ph1, th1 := sink.Hashes()
	if ph1["2b"] != main2b.PromptHash || ph1["2"] != hunt.PromptHash || th1["2b"] != main2b.ToolSchemaHash {
		t.Errorf("sink hashes = %v / %v", ph1, th1)
	}
}

// The end-to-end run persists the per-phase hashes on scan_meta.json.
func TestScanMetaCarriesPromptHashes(t *testing.T) {
	repo := filepath.Join(repoRoot(t), "testdata", "vulnapp")
	results := t.TempDir()
	spec := brokenSpec(repo, results)
	spec.Phases = []string{"1", "2"}
	rec, err := Execute(context.Background(), spec, Providers{Hunt: &pathWriter{model: "m"}}, staticSkill{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(rec.PromptHashes) == 0 || rec.PromptHashes["2"] == "" {
		t.Errorf("scan_meta prompt_hashes missing: %v", rec.PromptHashes)
	}
	b, _ := os.ReadFile(filepath.Join(results, ScanMetaFile))
	if !strings.Contains(string(b), `"prompt_hashes"`) {
		t.Error("scan_meta.json lacks prompt_hashes")
	}
}
