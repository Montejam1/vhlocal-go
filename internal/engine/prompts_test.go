package engine

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// readPromptRecords parses prompts.jsonl into generic maps.
func readPromptRecords(t *testing.T, results string) []map[string]any {
	t.Helper()
	f, err := os.Open(filepath.Join(results, "prompts.jsonl"))
	if err != nil {
		t.Fatalf("prompts.jsonl missing: %v", err)
	}
	defer f.Close()
	var recs []map[string]any
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	for sc.Scan() {
		var m map[string]any
		if err := json.Unmarshal(sc.Bytes(), &m); err != nil {
			t.Fatalf("malformed prompt record line: %v — %q", err, sc.Text())
		}
		recs = append(recs, m)
	}
	return recs
}

// Feature 014 (FR-005/007, SC-003, T016): every model call yields one PromptRecord
// with increasing seq, phase/label/role/model/kind/ts, and the ACTUAL sent content;
// a credentialed host planted in the spec never appears; canary and main kinds are
// present; scan_meta records prompt_capture_version. Run under -race with
// concurrency 3 to prove the sink is safe for parallel units.
func TestPromptRecordsCapturedForEveryCall(t *testing.T) {
	repo := filepath.Join(repoRoot(t), "testdata", "vulnapp")
	results := t.TempDir()
	spec := brokenSpec(repo, results)
	spec.Host = "http://svc:SECRETPW-9f3@h:11434" // credential must never be persisted
	spec.Concurrency = 3
	rw := &recordingWriter{pw: &pathWriter{model: "m"}}
	rec, err := Execute(context.Background(), spec, Providers{Hunt: rw}, staticSkill{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	recs := readPromptRecords(t, results)
	if len(recs) == 0 {
		t.Fatal("no prompt records captured")
	}
	if len(recs) != rw.count() {
		t.Errorf("one record per real call: %d records vs %d calls", len(recs), rw.count())
	}
	// seq strictly increasing; required fields present; content is the real system prompt.
	prev := -1.0
	kinds := map[string]bool{}
	for _, r := range recs {
		seq, _ := r["seq"].(float64)
		if seq <= prev {
			t.Errorf("seq not strictly increasing: %v after %v", seq, prev)
		}
		prev = seq
		for _, k := range []string{"ts", "phase", "label", "role", "model", "kind", "system", "task"} {
			if _, ok := r[k]; !ok {
				t.Errorf("record %v missing %q", seq, k)
			}
		}
		kinds[r["kind"].(string)] = true
		if sys, _ := r["system"].(string); r["kind"] == "main" && !strings.Contains(sys, "VulnHunter") {
			t.Errorf("main record %v does not carry the actual system prompt: %.60q", seq, sys)
		}
	}
	if !kinds["main"] || !kinds["canary"] {
		t.Errorf("expected main and canary kinds, got %v", kinds)
	}
	raw, _ := os.ReadFile(filepath.Join(results, "prompts.jsonl"))
	if strings.Contains(string(raw), "SECRETPW") {
		t.Error("planted credential leaked into prompt records")
	}
	if rec.PromptCaptureVersion == 0 {
		t.Error("scan_meta must record prompt_capture_version")
	}
}

// FR-005: a repair call (the agent's fresh-context tool-call repair) is captured
// as its own record with kind "repair".
func TestPromptRecordsIncludeRepairCalls(t *testing.T) {
	repo := filepath.Join(repoRoot(t), "testdata", "vulnapp")
	results := t.TempDir()
	spec := brokenSpec(repo, results)
	spec.Phases = []string{"1"}
	// A provider whose first phase-1 turn emits a malformed tool call → repair.
	p := &repairOnceWriter{pw: &pathWriter{model: "m"}}
	if _, err := Execute(context.Background(), spec, Providers{Hunt: p}, staticSkill{}, nil); err != nil {
		t.Fatal(err)
	}
	for _, r := range readPromptRecords(t, results) {
		if r["kind"] == "repair" {
			return
		}
	}
	t.Error("no prompt record of kind=repair although a repair call was made")
}
