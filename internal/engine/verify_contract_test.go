package engine

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"vhlocal/internal/client"
	"vhlocal/internal/verification"
)

// plantedRun plants one CWE-862 finding on svc01 /svc01/items and returns the
// reading writer, the verify plan keyed by the cited location, the cited location
// and the route identity — the shared setup of the feature-015 session tests.
func plantedRun(t *testing.T) (repo string, rw *readingWriter, plans map[string]verifyPlan, cited, entry string) {
	t.Helper()
	repo, routes, spans := coverageFixture(t)
	all := make([]string, 0, len(spans))
	for _, s := range spans {
		all = append(all, s)
	}
	rw = newReadingWriter(all)
	plans = map[string]verifyPlan{}
	hs := newHandlerSpans(repo)
	for _, r := range routes {
		if r.File == "svc01/routes.py" && r.Path == "/svc01/items" {
			sc := hs.scopeFor(r)
			cited = fmt.Sprintf("%s:%d", r.File, sc.Start+1)
			entry = r.Method + " " + r.Path
			rw.findings[r.File] = plantedFinding{Location: cited, CWE: "CWE-862", EntryPoint: entry, Title: "Missing authorization on " + entry}
			plans[cited] = verifyPlan{File: r.File, Start: sc.Start, End: sc.End, EntryPoint: entry}
		}
	}
	return repo, rw, plans, cited, entry
}

func promptRecordsOf(t *testing.T, results string) []PromptRecord {
	t.Helper()
	fh, err := os.Open(filepath.Join(results, PromptsFile))
	if err != nil {
		t.Fatal(err)
	}
	defer fh.Close()
	var out []PromptRecord
	sc := bufio.NewScanner(fh)
	sc.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	for sc.Scan() {
		var r PromptRecord
		if json.Unmarshal(sc.Bytes(), &r) == nil {
			out = append(out, r)
		}
	}
	return out
}

// T064 (C-C5): the session task carries the canonical facts — handler span, route
// identity separate from the display label, file length, required evidence span —
// and the system prompt carries the worked-example block.
func TestVerifySessionTaskCarriesCanonicalFacts(t *testing.T) {
	repo, rw, plans, cited, entry := plantedRun(t)
	// The hunt writes a DISPLAY label that differs from the identity.
	pf := rw.findings["svc01/routes.py"]
	pf.EntryPoint = entry + " (items_svc01 handler)"
	rw.findings["svc01/routes.py"] = pf
	results := t.TempDir()
	spec := coverageSpec(repo, results)
	spec.Phases = []string{"1", "2", "2b"}
	if _, err := Execute(context.Background(), spec, Providers{Hunt: newVerifyingWriter(rw, plans)}, staticSkill{}, nil); err != nil {
		t.Fatal(err)
	}
	var task, system string
	for _, r := range promptRecordsOf(t, results) {
		if r.Phase == "2b" && r.Kind == "main" && strings.HasPrefix(r.Task, "Verify EXACTLY this one candidate") {
			task, system = r.Task, r.System
			if r.CandidateID == "" || r.PromptHash == "" || r.ToolSchemaHash == "" {
				t.Errorf("2b record lacks candidate/prompt/tool identity: %+v", r.CandidateID)
			}
			break
		}
	}
	if task == "" {
		t.Fatal("no 2b main prompt record")
	}
	for _, want := range []string{
		"Cited location: " + cited,
		"Route identity (your entry_point must equal this EXACTLY): " + entry,
		"Display label (as the hunt wrote it): " + entry + " (items_svc01 handler)",
		"Handler span: svc01/routes.py:",
		"Required evidence span: lines",
		"File length: ",
		"Binding certainty: resolved",
	} {
		if !strings.Contains(task, want) {
			t.Errorf("task lacks %q", want)
		}
	}
	if !strings.Contains(system, "Phase prompt for phase2b_session.md") {
		t.Error("the worked-example block must ride in the system prompt")
	}
	if !strings.Contains(system, "structured error {code, field, received, expected, repairable, aids}") {
		t.Error("system prompt must describe the structured feedback contract")
	}
	// The shipped skill file holds the tested examples.
	sk, err := os.ReadFile(filepath.Join(repoRoot(t), "skill", "phases", "phase2b_session.md"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"E_CITATION_AMBIGUOUS", "E_RANGE_OUT_OF_BOUNDS", "E_HANDLER_MISMATCH", "E_REPEATED_SUBMISSION", "amend_candidate", `"verdict": "unresolved"`, `"verdict": "rejected"`, `"verdict": "supported"`} {
		if !strings.Contains(string(sk), want) {
			t.Errorf("phase2b_session.md lacks %q", want)
		}
	}
}

// badArgsVerifier: turn 1 Read with a wrong-typed file_path, turn 2 capture_evidence
// with malformed JSON, turn 3 an explicit unresolved verdict.
type badArgsVerifier struct {
	pw    *pathWriter
	mu    sync.Mutex
	turns map[string]int
}

func (b *badArgsVerifier) Backend() client.Backend { return "fake" }
func (b *badArgsVerifier) Endpoint() string        { return "fake://local" }
func (b *badArgsVerifier) Chat(ctx context.Context, req client.ChatRequest) (*client.ChatResponse, error) {
	task := ""
	for _, m := range req.Messages {
		if m.Role == "user" {
			task = m.Content
			break
		}
	}
	if !strings.HasPrefix(task, "Verify EXACTLY this one candidate") {
		return b.pw.Chat(ctx, req)
	}
	cid := ""
	if mm := reCandidate.FindStringSubmatch(task); mm != nil {
		cid = mm[1]
	}
	b.mu.Lock()
	b.turns[cid]++
	n := b.turns[cid]
	b.mu.Unlock()
	call := func(name, args string) (*client.ChatResponse, error) {
		return &client.ChatResponse{Model: "m", Message: client.Message{Role: "assistant",
			ToolCalls: []client.ToolCall{{ID: fmt.Sprintf("c%d", n), Name: name, Arguments: args}}}}, nil
	}
	switch n {
	case 1:
		return call("Read", `{"file_path": 12, "offset": 1}`)
	case 2:
		return call("capture_evidence", `{"path": "svc01/routes.py", "start_line": `)
	case 3:
		return call("capture_evidence", `{"path": "svc01/routes.py", "start_line": "6", "end_line": 10}`)
	}
	return call("submit_verification", `{"verdict":"unresolved","rationale":"cannot establish the gate","entry_point":"GET /svc01/items","evidence_ids":[],"unresolved_questions":["is the gate enforced?"]}`)
}

// T064 (C-C6, C-C8): malformed JSON / wrong-typed arguments are rejected with their
// own codes and never coerced; an explicit unresolved verdict is a decision
// (unresolved_explicit), not a failure.
func TestVerifyStrictArgsAndExplicitUnresolved(t *testing.T) {
	repo, rw, _, _, _ := plantedRun(t)
	results := t.TempDir()
	spec := coverageSpec(repo, results)
	spec.Phases = []string{"1", "2", "2b"}
	// Hunt via the reading writer (plants the finding); verify via badArgsVerifier.
	hunt := newVerifyingWriter(rw, map[string]verifyPlan{})
	if _, err := Execute(context.Background(), spec, Providers{Hunt: hunt, Verify: &badArgsVerifier{pw: &pathWriter{model: "m"}, turns: map[string]int{}}}, staticSkill{}, nil); err != nil {
		t.Fatal(err)
	}
	calls := verification.LoadCalls(results)
	if len(calls) == 0 {
		t.Fatal("verification_calls.jsonl missing")
	}
	codes := map[string]verification.CallRecord{}
	for _, c := range calls {
		if c.Code != "" {
			codes[c.Code] = c
		}
	}
	var readType verification.CallRecord
	for _, c := range calls {
		if c.Code == "E_TOOL_ARGS_TYPE" && c.Operation == "Read" {
			readType = c
		}
	}
	if readType.Operation != "Read" || readType.Class != verification.FailInvalidToolArgs || !strings.Contains(readType.Feedback, `"field":"file_path"`) {
		t.Errorf("wrong-typed file_path: %+v", readType)
	}
	if c, ok := codes["E_TOOL_ARGS_JSON"]; !ok || c.Operation != "capture_evidence" || c.Class != verification.FailInvalidToolArgs {
		t.Errorf("malformed JSON: %+v", codes["E_TOOL_ARGS_JSON"])
	}
	// The string "6" for start_line is a TYPE error (never coerced to 6).
	typeErrs := 0
	for _, c := range calls {
		if c.Code == "E_TOOL_ARGS_TYPE" {
			typeErrs++
		}
		if c.Operation == "Read" && c.Outcome == "ok" {
			t.Error("a wrong-typed Read must not execute")
		}
	}
	if typeErrs != 2 {
		t.Errorf("type errors = %d, want 2 (file_path, start_line)", typeErrs)
	}
	ss := sessionsOf(t, results)
	for _, s := range ss {
		if !s.ExplicitUnresolved || s.StopReason != "complete" || s.Calls != len(calls) || s.Model == "" {
			t.Errorf("session = %+v", s)
		}
		if s.Provenance == nil || s.Provenance.Backend != "fake" {
			t.Errorf("session provenance = %+v", s.Provenance)
		}
	}
	fj := loadFindings(t, results)
	cc, _ := fj["class_counts"].(map[string]any)
	if failed, _ := cc["unresolved_failed"].(float64); cc["unresolved_explicit"] != float64(1) || failed != 0 {
		t.Errorf("explicit unresolved must be counted as a decision: %v", cc)
	}
	// Prompt records: the 2b nudges are `kind: repair`, mains carry the candidate id.
	for _, r := range promptRecordsOf(t, results) {
		if r.Phase == "2b" && r.CandidateID == "" {
			t.Errorf("2b record without candidate_id: %+v", r.Label)
		}
	}
}

// repeatVerifier always submits the same rejected decision.
type repeatVerifier struct{ pw *pathWriter }

func (r *repeatVerifier) Backend() client.Backend { return "fake" }
func (r *repeatVerifier) Endpoint() string        { return "fake://local" }
func (r *repeatVerifier) Chat(ctx context.Context, req client.ChatRequest) (*client.ChatResponse, error) {
	task := ""
	for _, m := range req.Messages {
		if m.Role == "user" {
			task = m.Content
			break
		}
	}
	if !strings.HasPrefix(task, "Verify EXACTLY this one candidate") {
		return r.pw.Chat(ctx, req)
	}
	return &client.ChatResponse{Model: "m", Message: client.Message{Role: "assistant",
		ToolCalls: []client.ToolCall{{ID: "s", Name: "submit_verification", Arguments: `{"verdict":"supported","rationale":"r","entry_point":"GET /svc01/items","evidence_ids":[]}`}}}}, nil
}

// T064 (C-C6): structured feedback names code/field/expected; an identical repeated
// rejected submission stops the session after the second with E_REPEATED_SUBMISSION.
func TestVerifyStructuredFeedbackAndRepeatedSubmissionStop(t *testing.T) {
	repo, rw, _, _, _ := plantedRun(t)
	results := t.TempDir()
	spec := coverageSpec(repo, results)
	spec.Phases = []string{"1", "2", "2b"}
	if _, err := Execute(context.Background(), spec, Providers{Hunt: newVerifyingWriter(rw, map[string]verifyPlan{}), Verify: &repeatVerifier{pw: &pathWriter{model: "m"}}}, staticSkill{}, nil); err != nil {
		t.Fatal(err)
	}
	calls := verification.LoadCalls(results)
	var first verification.CallRecord
	submissions := 0
	for _, c := range calls {
		if c.Operation == "submit_verification" {
			submissions++
			if submissions == 1 {
				first = c
			}
		}
	}
	if submissions != 2 {
		t.Errorf("submissions = %d, want exactly 2 (second identical one stops)", submissions)
	}
	var fb struct {
		Error verification.Feedback `json:"error"`
	}
	if err := json.Unmarshal([]byte(first.Feedback), &fb); err != nil {
		t.Fatalf("feedback is not structured JSON: %q", first.Feedback)
	}
	if fb.Error.Code != verification.EFieldRequired || fb.Error.Field != "attacker_control" || fb.Error.Expected == "" || !fb.Error.Repairable {
		t.Errorf("feedback = %+v", fb.Error)
	}
	for _, s := range sessionsOf(t, results) {
		if s.StopReason != "repeated_submission" || s.StopCode != "E_REPEATED_SUBMISSION" || s.FailuresByClass[verification.FailRepeated] != 1 || s.FailuresByClass[verification.FailInvalidSubmission] != 1 {
			t.Errorf("session = %+v", s)
		}
	}
}
