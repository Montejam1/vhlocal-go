package agent

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"vhlocal/internal/client"
	"vhlocal/internal/tools"
)

func sandbox(t *testing.T) (*tools.Sandbox, string) {
	t.Helper()
	base := t.TempDir()
	repo := filepath.Join(base, "repo")
	skill := filepath.Join(base, "skill")
	results := filepath.Join(base, "results")
	for _, d := range []string{repo, skill, results} {
		os.MkdirAll(d, 0o755)
	}
	os.WriteFile(filepath.Join(repo, "app.py"), []byte("q = execute(user_input)\n"), 0o644)
	sb, err := tools.NewSandbox(repo, skill, results)
	if err != nil {
		t.Fatal(err)
	}
	return sb, results
}

func writeCall(id, path, content string) client.ToolCall {
	args, _ := json.Marshal(map[string]string{"path": path, "content": content})
	return client.ToolCall{ID: id, Name: "Write", Arguments: string(args)}
}

// scriptProvider gives per-call control and records the endpoint of every call
// (for C-A6/C-A2/C-X2). fn receives the 0-based call index and the request; errFn,
// when set, may return a per-call error (feature 004: a provider tool-call-parse
// TransportError on a chosen call, then nil) which takes precedence over fn.
type scriptProvider struct {
	fn        func(call int, req client.ChatRequest) client.ChatResponse
	err       error
	errFn     func(call int, req client.ChatRequest) error
	calls     int
	endpoints []string
	endpoint  string
}

func (s *scriptProvider) Backend() client.Backend { return "fake" }
func (s *scriptProvider) Endpoint() string {
	if s.endpoint == "" {
		return "fake://primary"
	}
	return s.endpoint
}
func (s *scriptProvider) Chat(_ context.Context, req client.ChatRequest) (*client.ChatResponse, error) {
	s.endpoints = append(s.endpoints, s.Endpoint())
	call := s.calls
	s.calls++
	if s.err != nil {
		return nil, s.err
	}
	if s.errFn != nil {
		if e := s.errFn(call, req); e != nil {
			return nil, e
		}
	}
	r := s.fn(call, req)
	return &r, nil
}

func asst(tcs ...client.ToolCall) client.ChatResponse {
	return client.ChatResponse{Message: client.Message{Role: "assistant", ToolCalls: tcs},
		Usage: client.Usage{PromptTokens: 10, CompletionTokens: 3}}
}
func done() client.ChatResponse {
	return client.ChatResponse{Message: client.Message{Role: "assistant", Content: "done"}}
}

// isRepairReq detects the minimal fresh-context repair call (2 messages, system
// mentions the invalid tool call).
func isRepairReq(req client.ChatRequest) bool {
	return len(req.Messages) == 2 && strings.Contains(req.Messages[0].Content, "invalid tool call")
}

// C-A1: one malformed tool call, then valid turns → completes, repair succeeded.
func TestRepairNotPrematureDeath(t *testing.T) {
	sb, results := sandbox(t)
	out := filepath.Join(results, "phase1_output.md")
	p := &scriptProvider{fn: func(call int, req client.ChatRequest) client.ChatResponse {
		switch {
		case call == 0: // main turn 1: malformed Write (bad JSON)
			return asst(client.ToolCall{ID: "c1", Name: "Write", Arguments: "{bad json"})
		case isRepairReq(req): // repair call → valid Write
			return asst(writeCall("c1", out, "# recon"))
		default: // main turn 2: done
			return done()
		}
	}}
	res, err := Run(context.Background(), p, sb, Config{Model: "m", MaxTurns: 10}, "sys", "task")
	if err != nil {
		t.Fatal(err)
	}
	if res.StoppedReason != StopComplete {
		t.Fatalf("stopped=%q want complete", res.StoppedReason)
	}
	if res.RepairAttempts < 1 || res.RepairSuccesses < 1 {
		t.Errorf("expected a successful repair, got attempts=%d successes=%d", res.RepairAttempts, res.RepairSuccesses)
	}
	if b, _ := os.ReadFile(out); string(b) != "# recon" {
		t.Errorf("repaired Write did not land: %q", b)
	}
}

// Feature 013 (FR-018/T045): the bounded fresh-context repair call carries the
// inference params (temperature — including 0 — and reasoning effort), not just
// the main-loop calls. Previously repairChat dropped them.
func TestRepairCarriesInferenceParams(t *testing.T) {
	sb, results := sandbox(t)
	out := filepath.Join(results, "phase1_output.md")
	zero := 0.0
	var repairReq *client.ChatRequest
	p := &scriptProvider{fn: func(call int, req client.ChatRequest) client.ChatResponse {
		switch {
		case call == 0:
			return asst(client.ToolCall{ID: "c1", Name: "Write", Arguments: "{bad json"})
		case isRepairReq(req):
			r := req // capture the repair request
			repairReq = &r
			return asst(writeCall("c1", out, "# recon"))
		default:
			return done()
		}
	}}
	cfg := Config{Model: "m", MaxTurns: 10, Temperature: &zero, ReasoningEffort: "high"}
	if _, err := Run(context.Background(), p, sb, cfg, "sys", "task"); err != nil {
		t.Fatal(err)
	}
	if repairReq == nil {
		t.Fatal("no repair call was made")
	}
	if repairReq.Temperature == nil || *repairReq.Temperature != 0 {
		t.Errorf("repair call dropped temperature (want *0): %v", repairReq.Temperature)
	}
	if repairReq.ReasoningEffort != "high" {
		t.Errorf("repair call dropped reasoning_effort: %q", repairReq.ReasoningEffort)
	}
}

// Feature 014 (FR-012/014, T010): a successful Read records the span actually read
// (1-based, End 0 = to EOF); a failed Read records nothing; Grep records nothing.
func TestReadSpansRecordedOnlyForSuccessfulReads(t *testing.T) {
	sb, results := sandbox(t)
	src := filepath.Join(results, "handler.py")
	os.WriteFile(src, []byte("l1\nl2\nl3\nl4\nl5\nl6\n"), 0o644)
	out := filepath.Join(results, "o.md")
	p := &scriptProvider{fn: func(call int, req client.ChatRequest) client.ChatResponse {
		switch call {
		case 0: // paged read: lines 2..4
			return asst(client.ToolCall{ID: "c1", Name: "Read", Arguments: `{"file_path":"` + src + `","offset":2,"limit":3}`})
		case 1: // whole-file read
			return asst(client.ToolCall{ID: "c2", Name: "Read", Arguments: `{"file_path":"` + src + `"}`})
		case 2: // failed read (missing file) → recoverable, no span
			return asst(client.ToolCall{ID: "c3", Name: "Read", Arguments: `{"file_path":"` + filepath.Join(results, "nope.py") + `"}`})
		case 3: // grep is a search, not a span read
			return asst(client.ToolCall{ID: "c4", Name: "Grep", Arguments: `{"pattern":"l1"}`})
		case 4:
			return asst(writeCall("c5", out, "x"))
		default:
			return done()
		}
	}}
	res, err := Run(context.Background(), p, sb, Config{Model: "m", MaxTurns: 10}, "s", "t")
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Reads) != 2 {
		t.Fatalf("want exactly 2 read spans (paged + whole), got %d: %+v", len(res.Reads), res.Reads)
	}
	if r := res.Reads[0]; r.File != src || r.Start != 2 || r.End != 4 {
		t.Errorf("paged read span = %+v, want {%s 2 4}", r, src)
	}
	if r := res.Reads[1]; r.File != src || r.Start != 1 || r.End != 0 {
		t.Errorf("whole-file read span = %+v, want {%s 1 0}", r, src)
	}
}

// C-A2: recoverable problems (missing arg, alias tool) → continue, no give-up.
func TestRecoverableNotGiveup(t *testing.T) {
	sb, results := sandbox(t)
	out := filepath.Join(results, "o.md")
	p := &scriptProvider{fn: func(call int, req client.ChatRequest) client.ChatResponse {
		switch call {
		case 0: // Read with no path → recoverable
			return asst(client.ToolCall{ID: "c1", Name: "Read", Arguments: `{}`})
		case 1: // unknown-but-aliasable tool name "search_files" (→Grep) missing pattern → recoverable
			return asst(client.ToolCall{ID: "c2", Name: "search_files", Arguments: `{}`})
		case 2: // now a valid write, then done
			return asst(writeCall("c3", out, "x"))
		default:
			return done()
		}
	}}
	res, err := Run(context.Background(), p, sb, Config{Model: "m", MaxTurns: 10}, "s", "t")
	if err != nil {
		t.Fatal(err)
	}
	if res.StoppedReason != StopComplete {
		t.Fatalf("recoverable errors must not end the agent; stopped=%q", res.StoppedReason)
	}
	if res.RepairAttempts != 0 {
		t.Errorf("recoverable errors must not trigger repair; attempts=%d", res.RepairAttempts)
	}
}

// C-A3: persistent unrecoverable calls whose repair also fails → tool_repair only
// after the repair budget (not after 1-2 turns).
func TestBoundedGiveup(t *testing.T) {
	sb, _ := sandbox(t)
	p := &scriptProvider{fn: func(call int, req client.ChatRequest) client.ChatResponse {
		// Every main turn: malformed; every repair: also malformed (no tool call).
		if isRepairReq(req) {
			return client.ChatResponse{Message: client.Message{Role: "assistant", Content: "sorry"}} // no tool call → repair fails
		}
		return asst(client.ToolCall{ID: "c1", Name: "Write", Arguments: "{still bad"})
	}}
	res, err := Run(context.Background(), p, sb, Config{Model: "m", MaxTurns: 20}, "s", "t")
	if err != nil {
		t.Fatalf("should end gracefully, not error: %v", err)
	}
	if res.StoppedReason != StopToolRepair {
		t.Fatalf("stopped=%q want tool_repair", res.StoppedReason)
	}
	if res.RepairAttempts != repairBudget {
		t.Errorf("give-up after %d repair failures; got RepairAttempts=%d", repairBudget, res.RepairAttempts)
	}
	if res.Turns > 2 {
		t.Errorf("with 2 unrecoverable calls per turn the budget should trip within ~1 turn; turns=%d", res.Turns)
	}
}

// C-A4: long transcript → context is pruned so the per-turn prompt stays bounded.
func TestContextPruningBoundsPrompt(t *testing.T) {
	sb, _ := sandbox(t)
	big := strings.Repeat("A", 20000)
	var sizeAtTurn10, sizeAtLast int
	p := &scriptProvider{fn: func(call int, req client.ChatRequest) client.ChatResponse {
		sz := 0
		for _, m := range req.Messages {
			sz += len(m.Content)
			for _, tc := range m.ToolCalls {
				sz += len(tc.Arguments)
			}
		}
		if call == 10 {
			sizeAtTurn10 = sz
		}
		sizeAtLast = sz
		if call < 30 {
			// Grow the transcript aggressively each turn (huge assistant content).
			return client.ChatResponse{Message: client.Message{Role: "assistant", Content: big,
				ToolCalls: []client.ToolCall{{ID: "c", Name: "Glob", Arguments: `{"pattern":"*.py"}`}}}}
		}
		return done()
	}}
	// Small NumCtx → small byte budget → pruning must engage and PLATEAU the
	// prompt: size at turn 30 must not grow proportionally to turn count vs turn 10.
	res, _ := Run(context.Background(), p, sb, Config{Model: "m", MaxTurns: 40, NumCtx: 4096}, "s", "t")
	if res.Turns < 25 {
		t.Fatalf("test needs >=25 turns to observe plateau, got %d", res.Turns)
	}
	if sizeAtLast > sizeAtTurn10*3/2 {
		t.Errorf("prompt did not plateau (grew with turns): turn10=%d last=%d", sizeAtTurn10, sizeAtLast)
	}
}

// C-A5: a fan-out agent nearing max_turns is nudged and then writes its deliverable.
func TestWriteNudgeProducesDeliverable(t *testing.T) {
	sb, results := sandbox(t)
	out := filepath.Join(results, "hunt.md")
	p := &scriptProvider{fn: func(call int, req client.ChatRequest) client.ChatResponse {
		// Only write once the nudge (a user message naming the path) appears.
		for _, m := range req.Messages {
			if m.Role == "user" && strings.Contains(m.Content, "nearing your turn limit") {
				return asst(writeCall("w", out, "# findings"))
			}
		}
		return asst(client.ToolCall{ID: "g", Name: "Glob", Arguments: `{"pattern":"*.py"}`})
	}}
	res, _ := Run(context.Background(), p, sb, Config{Model: "m", MaxTurns: 10, DeliverablePath: out}, "s", "t")
	if !res.Produced {
		t.Errorf("expected Produced=true after nudge")
	}
	if b, _ := os.ReadFile(out); string(b) != "# findings" {
		t.Errorf("deliverable not written: %q", b)
	}
}

// C-A6: the repair call targets the SAME endpoint as the agent (Principle III/V).
func TestRepairStaysOnSameEndpoint(t *testing.T) {
	sb, results := sandbox(t)
	out := filepath.Join(results, "o.md")
	p := &scriptProvider{endpoint: "fake://primary", fn: func(call int, req client.ChatRequest) client.ChatResponse {
		if call == 0 {
			return asst(client.ToolCall{ID: "c1", Name: "Write", Arguments: "{bad"})
		}
		if isRepairReq(req) {
			return asst(writeCall("c1", out, "x"))
		}
		return done()
	}}
	if _, err := Run(context.Background(), p, sb, Config{Model: "m", MaxTurns: 5}, "s", "t"); err != nil {
		t.Fatal(err)
	}
	if p.RepairHappened() == false {
		t.Fatal("expected a repair call")
	}
	for i, ep := range p.endpoints {
		if ep != "fake://primary" {
			t.Errorf("call %d hit a different endpoint %q — repair must stay on-endpoint", i, ep)
		}
	}
}

func (s *scriptProvider) RepairHappened() bool { return s.calls >= 2 }

// --- retained behavior from before feature 003 ---

func TestMaxTurns(t *testing.T) {
	sb, _ := sandbox(t)
	p := &scriptProvider{fn: func(call int, req client.ChatRequest) client.ChatResponse {
		return asst(client.ToolCall{ID: "c", Name: "Glob", Arguments: `{"pattern":"*.py"}`})
	}}
	res, _ := Run(context.Background(), p, sb, Config{Model: "m", MaxTurns: 3}, "s", "t")
	if res.StoppedReason != StopMaxTurns {
		t.Fatalf("stopped=%q want max_turns", res.StoppedReason)
	}
}

func TestTransportErrorPropagates(t *testing.T) {
	sb, _ := sandbox(t)
	p := &scriptProvider{err: errors.New("endpoint unreachable"), fn: func(int, client.ChatRequest) client.ChatResponse { return done() }}
	if _, err := Run(context.Background(), p, sb, Config{Model: "m", MaxTurns: 5}, "s", "t"); err == nil {
		t.Fatal("transport error must propagate")
	}
}

func TestReadAliasAndComplete(t *testing.T) {
	sb, _ := sandbox(t)
	p := &scriptProvider{fn: func(call int, req client.ChatRequest) client.ChatResponse {
		if call == 0 {
			return asst(client.ToolCall{ID: "c1", Name: "read_file", Arguments: `{"path":"app.py"}`})
		}
		return done()
	}}
	res, err := Run(context.Background(), p, sb, Config{Model: "m", MaxTurns: 5}, "s", "t")
	if err != nil || res.StoppedReason != StopComplete {
		t.Fatalf("read alias loop: %q err=%v", res.StoppedReason, err)
	}
}

// --- feature 004: provider tool-call-parse recovery + deliverable-aware completion ---

// isRepairFromRawReq detects the provider-side fresh-context repair call (2
// messages; system says the previous call was rejected BY THE PROVIDER).
func isRepairFromRawReq(req client.ChatRequest) bool {
	return len(req.Messages) == 2 && strings.Contains(req.Messages[0].Content, "rejected by the provider")
}

// C-A1: one provider tool-call-parse error (carrying a recoverable Raw), then
// valid → repairs from Raw, dispatches the recovered call, continues to
// completion; the run is NOT returned as an error.
func TestProviderToolParseRecovered(t *testing.T) {
	sb, results := sandbox(t)
	out := filepath.Join(results, "phase1_output.md")
	raw := `We need to list the tree.{"pattern":"*.py"}`
	p := &scriptProvider{
		errFn: func(call int, req client.ChatRequest) error {
			if call == 0 {
				return &client.TransportError{Backend: "fake", Endpoint: "fake://primary",
					Status: 500, Kind: client.KindToolParse, Raw: raw, Retryable: false}
			}
			return nil
		},
		fn: func(call int, req client.ChatRequest) client.ChatResponse {
			if isRepairFromRawReq(req) {
				return asst(writeCall("c1", out, "# recon"))
			}
			return done()
		},
	}
	res, err := Run(context.Background(), p, sb, Config{Model: "m", MaxTurns: 10, DeliverablePath: out}, "sys", "task")
	if err != nil {
		t.Fatalf("a provider tool-call-parse error must be recovered, not returned: %v", err)
	}
	if res.StoppedReason != StopComplete {
		t.Fatalf("stopped=%q want complete", res.StoppedReason)
	}
	if res.RepairAttempts < 1 || res.RepairSuccesses < 1 {
		t.Errorf("expected a successful repair from raw; attempts=%d successes=%d", res.RepairAttempts, res.RepairSuccesses)
	}
	if b, _ := os.ReadFile(out); string(b) != "# recon" {
		t.Errorf("recovered call did not land the deliverable: %q", b)
	}
}

// C-A2: the provider-parse repair Chat targets the SAME endpoint (Principle V; no
// provider switch).
func TestProviderToolParseRepairStaysOnEndpoint(t *testing.T) {
	sb, results := sandbox(t)
	out := filepath.Join(results, "o.md")
	p := &scriptProvider{endpoint: "fake://primary",
		errFn: func(call int, req client.ChatRequest) error {
			if call == 0 {
				return &client.TransportError{Kind: client.KindToolParse, Raw: `x{"pattern":"*.py"}`, Retryable: false}
			}
			return nil
		},
		fn: func(call int, req client.ChatRequest) client.ChatResponse {
			if isRepairFromRawReq(req) {
				return asst(writeCall("c1", out, "x"))
			}
			return done()
		}}
	if _, err := Run(context.Background(), p, sb, Config{Model: "m", MaxTurns: 5}, "s", "t"); err != nil {
		t.Fatal(err)
	}
	if p.calls < 2 {
		t.Fatal("expected a repair call")
	}
	for i, ep := range p.endpoints {
		if ep != "fake://primary" {
			t.Errorf("call %d hit %q — provider-parse repair must stay on the configured endpoint", i, ep)
		}
	}
}

// C-A3: a provider tool-call-parse error that recurs unrecoverably ends the agent
// as tool_repair after the bounded budget, returns NIL error (engine degrades the
// phase), and RECORDS the give-up (RepairAttempts incremented, no successes).
func TestProviderToolParsePersistentDegrades(t *testing.T) {
	sb, _ := sandbox(t)
	p := &scriptProvider{
		errFn: func(call int, req client.ChatRequest) error {
			// Every MAIN turn errors with a tool-parse 500; repair calls are let
			// through so fn can fail them (no usable tool call).
			if !isRepairFromRawReq(req) {
				return &client.TransportError{Kind: client.KindToolParse, Raw: "noise, no json", Retryable: false}
			}
			return nil
		},
		fn: func(call int, req client.ChatRequest) client.ChatResponse {
			return client.ChatResponse{Message: client.Message{Role: "assistant", Content: "sorry"}} // repair fails
		}}
	res, err := Run(context.Background(), p, sb, Config{Model: "m", MaxTurns: 20}, "s", "t")
	if err != nil {
		t.Fatalf("persistent tool-parse must degrade gracefully, not error: %v", err)
	}
	if res.StoppedReason != StopToolRepair {
		t.Fatalf("stopped=%q want tool_repair", res.StoppedReason)
	}
	if res.RepairAttempts != repairBudget { // give-up recorded (FR-005)
		t.Errorf("give-up must be recorded after %d repair attempts; got %d", repairBudget, res.RepairAttempts)
	}
	if res.RepairSuccesses != 0 {
		t.Errorf("no repair should have succeeded; got successes=%d", res.RepairSuccesses)
	}
}

// C-A4: a generic (non-parse) transport error still propagates as an error — a
// real outage is never silently swallowed as a tool-parse recovery.
func TestGenericTransportErrorPropagatesTyped(t *testing.T) {
	sb, _ := sandbox(t)
	p := &scriptProvider{
		errFn: func(call int, req client.ChatRequest) error {
			return &client.TransportError{Kind: client.KindGeneric, Msg: "connection refused", Retryable: true}
		},
		fn: func(int, client.ChatRequest) client.ChatResponse { return done() }}
	if _, err := Run(context.Background(), p, sb, Config{Model: "m", MaxTurns: 5}, "s", "t"); err == nil {
		t.Fatal("a generic transport error must propagate, not be swallowed")
	}
}

// C-N1: an agent that stops (would complete) with a DeliverablePath set but no
// deliverable is nudged once, then writes → Produced.
func TestCompletionNudgeProducesDeliverable(t *testing.T) {
	sb, results := sandbox(t)
	out := filepath.Join(results, "phase1_output.md")
	p := &scriptProvider{fn: func(call int, req client.ChatRequest) client.ChatResponse {
		for _, m := range req.Messages {
			if m.Role == "user" && strings.Contains(m.Content, "Before finishing, write your deliverable") {
				return asst(writeCall("w", out, "# recon"))
			}
		}
		return done() // premature completion, no deliverable
	}}
	res, err := Run(context.Background(), p, sb, Config{Model: "m", MaxTurns: 10, DeliverablePath: out}, "s", "t")
	if err != nil {
		t.Fatal(err)
	}
	if !res.Produced {
		t.Errorf("the completion nudge should have driven the deliverable write")
	}
	if b, _ := os.ReadFile(out); string(b) != "# recon" {
		t.Errorf("deliverable not written after completion nudge: %q", b)
	}
}

// C-N2: the completion nudge fires at most once (no loop); if the deliverable is
// still not written, the phase ends complete and is NOT marked produced.
func TestCompletionNudgeFiresOnce(t *testing.T) {
	sb, results := sandbox(t)
	out := filepath.Join(results, "phase1_output.md")
	p := &scriptProvider{fn: func(call int, req client.ChatRequest) client.ChatResponse {
		return done() // never writes, even after the nudge
	}}
	res, err := Run(context.Background(), p, sb, Config{Model: "m", MaxTurns: 10, DeliverablePath: out}, "s", "t")
	if err != nil {
		t.Fatal(err)
	}
	if res.StoppedReason != StopComplete {
		t.Fatalf("stopped=%q want complete", res.StoppedReason)
	}
	if res.Turns != 2 { // turn 1 stops → nudge; turn 2 stops → finalize. One-shot, no loop.
		t.Errorf("completion nudge must fire once then finalize; turns=%d want 2", res.Turns)
	}
	if res.Produced {
		t.Error("no deliverable was written; the phase must not be marked produced")
	}
	if _, statErr := os.Stat(out); statErr == nil {
		t.Error("no deliverable file should exist")
	}
}

// C-C4 (feature 005): a Write to an unrelated path does not set Produced and does
// not suppress the completion nudge; Produced flips only when the DECLARED
// deliverable is written non-empty.
func TestProducedKeyedToDeliverable(t *testing.T) {
	sb, results := sandbox(t)
	deliverable := filepath.Join(results, "phase1_output.md")
	other := filepath.Join(results, "scratch.md")
	p := &scriptProvider{fn: func(call int, req client.ChatRequest) client.ChatResponse {
		for _, m := range req.Messages {
			if m.Role == "user" && strings.Contains(m.Content, "Before finishing, write your deliverable") {
				return asst(writeCall("w2", deliverable, "# recon"))
			}
		}
		if call == 0 {
			return asst(writeCall("w1", other, "noise")) // write to the WRONG path
		}
		return done() // would complete without the deliverable
	}}
	res, err := Run(context.Background(), p, sb, Config{Model: "m", MaxTurns: 10, DeliverablePath: deliverable}, "s", "t")
	if err != nil {
		t.Fatal(err)
	}
	if !res.Produced {
		t.Errorf("Produced must flip only when the declared deliverable is written")
	}
	if b, _ := os.ReadFile(deliverable); string(b) != "# recon" {
		t.Errorf("the wrong-path write must not have suppressed the nudge; deliverable=%q", b)
	}
}

// C-C4 (feature 005): an empty write to the deliverable path does not count as produced.
func TestEmptyWriteNotProduced(t *testing.T) {
	sb, results := sandbox(t)
	deliverable := filepath.Join(results, "phase1_output.md")
	p := &scriptProvider{fn: func(call int, req client.ChatRequest) client.ChatResponse {
		return asst(writeCall("w", deliverable, "")) // always empty content
	}}
	res, _ := Run(context.Background(), p, sb, Config{Model: "m", MaxTurns: 4, DeliverablePath: deliverable}, "s", "t")
	if res.Produced {
		t.Error("an empty deliverable file must not count as produced")
	}
}

// C-X2: the provider-parse repair preserves the safety invariants — same endpoint
// only (no provider switch), and only the sandbox tool envelope is ever advertised
// (no shell/exec; Principles III/V).
func TestToolParseRepairPreservesInvariants(t *testing.T) {
	sb, results := sandbox(t)
	out := filepath.Join(results, "o.md")
	var repairToolNames []string
	p := &scriptProvider{endpoint: "fake://primary",
		errFn: func(call int, req client.ChatRequest) error {
			if call == 0 {
				return &client.TransportError{Kind: client.KindToolParse, Raw: `x{"pattern":"*.py"}`, Retryable: false}
			}
			return nil
		},
		fn: func(call int, req client.ChatRequest) client.ChatResponse {
			if isRepairFromRawReq(req) {
				for _, tl := range req.Tools {
					repairToolNames = append(repairToolNames, tl.Name)
				}
				return asst(writeCall("c1", out, "x"))
			}
			return done()
		}}
	if _, err := Run(context.Background(), p, sb, Config{Model: "m", MaxTurns: 5}, "s", "t"); err != nil {
		t.Fatal(err)
	}
	for i, ep := range p.endpoints {
		if ep != "fake://primary" {
			t.Errorf("call %d hit %q — repair must stay on the configured endpoint", i, ep)
		}
	}
	if len(repairToolNames) == 0 {
		t.Fatal("repair path was not exercised")
	}
	allowed := map[string]bool{"Read": true, "Grep": true, "Glob": true, "Write": true}
	for _, n := range repairToolNames {
		if !allowed[n] {
			t.Errorf("repair advertised a non-sandbox tool %q — the static-only boundary was widened", n)
		}
	}
}
