package engine

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"vhlocal/internal/client"
	"vhlocal/internal/verification"
)

// T066 (C-C10, C-C11, SC-011): one session with an argument error, a submission
// error and turn exhaustion records three distinct call entries with their own
// class/code/message; the session counts each class; the aggregates separate
// occurrences from sessions from stop reasons; the tool_failure events carry the
// per-class operation; the diagnostic record replays the failure offline.
func TestVerificationCallsRecordEveryFailureDistinctly(t *testing.T) {
	repo, rw, _, _, _ := plantedRun(t)
	results := t.TempDir()
	spec := coverageSpec(repo, results)
	spec.Phases = []string{"1", "2", "2b"}
	var mu sync.Mutex
	events := map[string][]map[string]any{}
	emit := func(ev string, p map[string]any) {
		mu.Lock()
		events[ev] = append(events[ev], p)
		mu.Unlock()
	}
	prov := newMixedFailureVerifier("svc01/routes.py")
	if _, err := Execute(context.Background(), spec, Providers{Hunt: newVerifyingWriter(rw, map[string]verifyPlan{}), Verify: prov}, staticSkill{}, emit); err != nil {
		t.Fatal(err)
	}
	calls := verification.LoadCalls(results)
	classes := map[string]verification.CallRecord{}
	for _, c := range calls {
		if c.Outcome == "error" {
			classes[c.Class] = c
		}
	}
	args, sub, exh := classes[verification.FailInvalidToolArgs], classes[verification.FailInvalidSubmission], classes[verification.FailTurnExhaustion]
	if args.Operation != "Read" || sub.Operation != "submit_verification" || exh.Operation != "turn limit" {
		t.Fatalf("three distinct failure entries expected: args=%+v sub=%+v exh=%+v", args, sub, exh)
	}
	if sub.Code != verification.EVerdict || !strings.Contains(sub.Feedback, `"field":"verdict"`) || args.Message == sub.Message || sub.Message == exh.Message {
		t.Errorf("entries must carry their own code/message: %+v %+v %+v", args, sub, exh)
	}
	if calls[0].CallSeq != 1 || calls[len(calls)-1].CallSeq != len(calls) {
		t.Error("call_seq must be contiguous")
	}
	ss := sessionsOf(t, results)
	var s verification.SessionOutcome
	for _, v := range ss {
		s = v
	}
	if s.FailuresByClass[verification.FailInvalidToolArgs] != 1 || s.FailuresByClass[verification.FailInvalidSubmission] != 1 || s.FailuresByClass[verification.FailTurnExhaustion] != 1 {
		t.Errorf("failures_by_class = %v", s.FailuresByClass)
	}
	if s.Calls != len(calls) || s.StopReason != "max_turns" {
		t.Errorf("session = %+v", s)
	}
	// Aggregates on verification_metrics.json.
	mb, _ := os.ReadFile(filepath.Join(results, verification.MetricsFile))
	var metrics struct {
		Agg struct {
			Occ   map[string]int `json:"occurrences_by_class"`
			Sess  map[string]int `json:"sessions_by_class"`
			Stops map[string]int `json:"stop_reasons"`
			Note  string         `json:"overlap_note"`
			Calls int            `json:"calls"`
		} `json:"session_aggregates"`
	}
	if err := json.Unmarshal(mb, &metrics); err != nil {
		t.Fatal(err)
	}
	a := metrics.Agg
	if a.Occ[verification.FailInvalidToolArgs] != 1 || a.Sess[verification.FailInvalidSubmission] != 1 || a.Stops["max_turns"] != 1 || a.Note == "" || a.Calls != len(calls) {
		t.Errorf("aggregates = %+v", a)
	}
	// tool_failure events: one per class, each with ITS operation (not the session's last).
	ops := map[string]string{}
	for _, p := range events["tool_failure"] {
		ops[p["class"].(string)] = p["operation"].(string)
	}
	if ops[verification.FailInvalidToolArgs] != "Read" || ops[verification.FailInvalidSubmission] != "submit_verification" || ops[verification.FailTurnExhaustion] != "turn limit" {
		t.Errorf("tool_failure operations by class = %v", ops)
	}
	// Diagnostic record: complete failing submission + exact feedback + hashes; the
	// failure replays offline through Reconcile with no model.
	entries, _ := os.ReadDir(filepath.Join(results, DiagnosticsDir))
	if len(entries) != 1 {
		t.Fatalf("diagnostics = %d files, want 1", len(entries))
	}
	db, _ := os.ReadFile(filepath.Join(results, DiagnosticsDir, entries[0].Name()))
	var diag DiagnosticRecord
	if err := json.Unmarshal(db, &diag); err != nil {
		t.Fatal(err)
	}
	if diag.CandidateID != s.CandidateID || diag.PromptHash == "" || diag.ToolSchemaHash == "" || len(diag.FailingSubmissions) != 1 || diag.Context != "bounded" || diag.TruncatedFields == nil || diag.SizeBytes == 0 {
		t.Errorf("diagnostic = %+v", diag)
	}
	fs := diag.FailingSubmissions[0]
	if fs.Code != verification.EVerdict || fs.Args["verdict"] != "maybe" || fs.Feedback.Field != "verdict" {
		t.Errorf("failing submission = %+v", fs)
	}
	if !strings.Contains(diag.Note, "not model-context truncation") {
		t.Error("telemetry truncation must be described as a stored clamp, never as model-context truncation")
	}
	// Offline replay: the recorded submission still fails the contract.
	man := verification.Manifest{}
	mbRaw, _ := os.ReadFile(filepath.Join(results, verification.CandidateManifestFile))
	_ = json.Unmarshal(mbRaw, &man)
	dec := verification.Decision{CandidateID: diag.CandidateID, Verdict: fs.Args["verdict"].(string), Rationale: "x", Revision: man.Revision, Reviewer: "replay"}
	if rc := verification.Reconcile(&man, []verification.Decision{dec}, repo); rc.Complete || rc.Counts["supported"] != 0 {
		t.Error("the recorded failing submission must still fail offline reconciliation")
	}
	if strings.Contains(strings.ToLower(string(db)), "password=") {
		t.Error("diagnostics must not carry credentials")
	}
}

// T066/T075: full-mode capture stores the sanitized call context once per prompt
// hash and never a credential; retention keeps the newest 200 records.
func TestDiagnosticFullModeAndRetention(t *testing.T) {
	dir := t.TempDir()
	res := agentResult{Model: "m", StoppedReason: "max_turns", PromptHash: "abc", ToolSchemaHash: "def",
		failing: []verification.FailingSubmission{{CallSeq: 2, Args: map[string]any{"verdict": "maybe", "rationale": "token=sk-live-ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"}, Code: "E_VERDICT", Feedback: verification.Feedback{Code: "E_VERDICT", Field: "verdict"}}},
		Calls:   []verification.CallRecord{{CandidateID: "CAND-1", CallSeq: 1, Operation: "Read", Outcome: "ok"}, {CandidateID: "CAND-1", CallSeq: 2, Operation: "submit_verification", Outcome: "error", Class: "invalid_submission", Message: "password=hunter2 leaked"}},
	}
	c := verification.Candidate{ID: "CAND-1"}
	writeDiagnostic(dir, DiagnosticFull, c, res, "rev")
	b, err := os.ReadFile(filepath.Join(dir, DiagnosticsDir, "CAND-1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var d DiagnosticRecord
	_ = json.Unmarshal(b, &d)
	if d.Context != "full" || d.ContextRef == "" {
		t.Errorf("full mode must reference the shared context: %+v", d)
	}
	if strings.Contains(string(b), "hunter2") || strings.Contains(string(b), "sk-live-ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789") {
		t.Error("credentials must be masked")
	}
	if _, err := os.Stat(filepath.Join(dir, d.ContextRef)); err != nil {
		t.Errorf("context file missing: %v", err)
	}
	// Dedup by prompt hash: a second candidate with the same hash reuses the file.
	c2 := verification.Candidate{ID: "CAND-2"}
	writeDiagnostic(dir, DiagnosticFull, c2, res, "rev")
	ctxFiles, _ := os.ReadDir(filepath.Join(dir, DiagnosticsDir, "context"))
	if len(ctxFiles) != 1 {
		t.Errorf("context files = %d, want 1 (deduplicated by prompt hash)", len(ctxFiles))
	}
	// Retention: newest 200 records.
	for i := 0; i < DiagnosticsKeep+5; i++ {
		writeDiagnostic(dir, DiagnosticBounded, verification.Candidate{ID: "CAND-R" + itoaTest(i)}, res, "rev")
	}
	files, _ := os.ReadDir(filepath.Join(dir, DiagnosticsDir))
	n := 0
	for _, f := range files {
		if !f.IsDir() {
			n++
		}
	}
	if n != DiagnosticsKeep {
		t.Errorf("retained %d records, want %d", n, DiagnosticsKeep)
	}
}

func TestDiagnosticNestedRedactionAndDistinctContext(t *testing.T) {
	dir := t.TempDir()
	res := agentResult{PromptHash: "shared-system", ContextMessages: []client.Message{{Role: "user", Content: "first candidate"}}, failing: []verification.FailingSubmission{{Args: map[string]any{"evidence": []any{map[string]any{"quote": "password=secret-one", "api_key": "secret-two"}}, "unresolved_questions": []any{"token=secret-three"}}}}}
	writeDiagnostic(dir, DiagnosticFull, verification.Candidate{ID: "one"}, res, "rev")
	res.ContextMessages[0].Content = "second candidate"
	writeDiagnostic(dir, DiagnosticFull, verification.Candidate{ID: "two"}, res, "rev")
	contexts, _ := os.ReadDir(filepath.Join(dir, DiagnosticsDir, "context"))
	if len(contexts) != 2 {
		t.Fatal("candidate contexts collided under shared prompt hash")
	}
	b, _ := os.ReadFile(filepath.Join(dir, DiagnosticsDir, "one.json"))
	for _, secret := range []string{"secret-one", "secret-two", "secret-three"} {
		if strings.Contains(string(b), secret) {
			t.Fatalf("nested credential retained: %s", secret)
		}
	}
}

func itoaTest(n int) string {
	b, _ := json.Marshal(n)
	return string(b)
}
