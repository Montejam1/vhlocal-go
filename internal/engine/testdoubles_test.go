package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"

	"vhlocal/internal/client"
)

// Feature 014 offline provider doubles (T002). None contacts a network or model.

// delayedWriter behaves like pathWriter but, after writing its deliverable on the
// first tool turn, blocks on Release before completing — so a test can observe
// evidence (artifact, prompt record, log line) while the job is still running.
type delayedWriter struct {
	pw      *pathWriter
	release chan struct{}
	once    sync.Once
	wrote   chan struct{} // closed after the first Write tool call is issued
}

func newDelayedWriter() *delayedWriter {
	return &delayedWriter{pw: &pathWriter{model: "m"}, release: make(chan struct{}), wrote: make(chan struct{})}
}

func (d *delayedWriter) Backend() client.Backend { return "fake" }
func (d *delayedWriter) Endpoint() string        { return "fake://local" }
func (d *delayedWriter) Release()                { d.once.Do(func() { close(d.release) }) }
func (d *delayedWriter) Chat(ctx context.Context, req client.ChatRequest) (*client.ChatResponse, error) {
	// After the tool result comes back (deliverable written), hold the run open
	// until released so the test window stays "running".
	if n := len(req.Messages); n > 0 && req.Messages[n-1].Role == "tool" {
		select {
		case <-d.wrote:
		default:
			close(d.wrote)
		}
		select {
		case <-d.release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return d.pw.Chat(ctx, req)
}

// readingWriter drives the US2 coverage tests. For each hunt unit it issues Read
// tool calls over the spans whose FILE is named in the unit's task (its assigned
// scope), then writes a valid deliverable: finding blocks for `findings` located in
// files of that scope, else a no-findings deliverable. Modes: followUpOnly reads
// nothing until a follow-up unit runs; proseClaim writes a "reviewed everything"
// sentence WITHOUT reading (must never count as review).
// plantedFinding is a hunt finding the double emits for a file in its scope. The
// authorization class (CWE-862) has no syntactic sink, so a complete evidence-backed
// review of it is accepted by verification (FR-024) — the same class the Go e2e
// transcript uses. EntryPoint must equal the route guard ("METHOD PATH").
type plantedFinding struct {
	Location   string // "file:line" inside the handler span
	CWE        string
	EntryPoint string
	Title      string
}

type readingWriter struct {
	pw           *pathWriter
	spans        []string                  // "file:start-end" (repo-relative)
	findings     map[string]plantedFinding // repo-relative file -> planted finding
	followUpOnly bool
	proseClaim   bool
	mu           sync.Mutex
	prog         map[string]int  // per-unit read progress keyed by deliverable path
	wrote        map[string]bool // per-unit: the Write tool call has been issued
	// extra, when set, is appended to every hunt deliverable (feature 015: the v2
	// "## Handler dispositions" section is produced here by dispositionWriter).
	extra func(task string) string
}

func newReadingWriter(spans []string) *readingWriter {
	return &readingWriter{pw: &pathWriter{model: "m"}, spans: spans, prog: map[string]int{}, wrote: map[string]bool{}, findings: map[string]plantedFinding{}}
}

func (r *readingWriter) Backend() client.Backend { return "fake" }
func (r *readingWriter) Endpoint() string        { return "fake://local" }

func (r *readingWriter) deliverable(task string) string {
	var b strings.Builder
	n := 0
	files := make([]string, 0, len(r.findings))
	for f := range r.findings {
		files = append(files, f)
	}
	sort.Strings(files)
	for _, f := range files {
		// Emit a finding only for files in THIS unit's assigned scope (subsystem or file
		// named in the task) — the same scope rule the reads follow.
		sub := f
		if i := strings.IndexByte(f, '/'); i >= 0 {
			sub = f[:i]
		}
		if !strings.Contains(task, f) && !strings.Contains(task, sub+" ") && !strings.Contains(task, sub+"\n") {
			continue
		}
		pf := r.findings[f]
		n++
		if n == 1 {
			b.WriteString("## Findings\n\n")
		}
		fmt.Fprintf(&b, "### [VULN-%03d] %s\n\n- **CWE**: %s\n- **Severity**: High\n- **Location**: %s\n- **Entry point**: %s\n- **Data flow**: request -> handler without an authorization check\n- **Fix**: require authorization before handling\n\n",
			n, pf.Title, pf.CWE, pf.Location, pf.EntryPoint)
	}
	if n == 0 {
		b.WriteString("# output\n\nNo findings identified in the assigned scope.\n")
	}
	if r.proseClaim {
		b.WriteString("\nI reviewed every handler in svc01/routes.py and svc06/routes.go thoroughly; no issues found.\n")
	}
	return b.String()
}

func (r *readingWriter) Chat(ctx context.Context, req client.ChatRequest) (*client.ChatResponse, error) {
	task := ""
	for _, m := range req.Messages {
		if m.Role == "user" {
			task = m.Content
			break
		}
	}
	key := task
	if all := reOutPath.FindAllString(task, -1); len(all) > 0 {
		key = all[len(all)-1]
	}
	if !strings.Contains(key, "/results/") {
		return r.pw.Chat(ctx, req) // recon etc. behave like pathWriter
	}
	// After a tool result: finish only once OUR Write has been issued; a Read's tool
	// result must be followed by the next read (or the write), not by "done".
	if n := len(req.Messages); n > 0 && req.Messages[n-1].Role == "tool" {
		r.mu.Lock()
		done := r.wrote[key]
		r.mu.Unlock()
		if done {
			return &client.ChatResponse{Message: client.Message{Role: "assistant", Content: "done"}, Usage: client.Usage{PromptTokens: 5, CompletionTokens: 2}}, nil
		}
	}
	write := func() (*client.ChatResponse, error) {
		r.mu.Lock()
		r.wrote[key] = true
		r.mu.Unlock()
		content := r.deliverable(task)
		if r.extra != nil && !(r.followUpOnly && !strings.Contains(key, "_followup")) {
			content += r.extra(task)
		}
		args, _ := json.Marshal(map[string]string{"path": key, "content": content})
		return &client.ChatResponse{Model: "m",
			Message: client.Message{Role: "assistant", ToolCalls: []client.ToolCall{{ID: "w", Name: "Write", Arguments: string(args)}}},
			Usage:   client.Usage{PromptTokens: 10, CompletionTokens: 4}}, nil
	}
	if r.followUpOnly && !strings.Contains(key, "_followup") {
		return write()
	}
	// A unit reads the spans of ITS assigned scope: the hunt task names the
	// partition (subsystem = first path segment) in its scope description.
	var relevant []string
	for _, s := range r.spans {
		f, _, _ := parseSpan(s)
		sub := f
		if i := strings.IndexByte(f, '/'); i >= 0 {
			sub = f[:i]
		}
		if strings.Contains(task, sub+" ") || strings.Contains(task, sub+"\n") || strings.Contains(task, f) {
			relevant = append(relevant, s)
		}
	}
	r.mu.Lock()
	i := r.prog[key]
	if i < len(relevant) {
		r.prog[key] = i + 1
	}
	r.mu.Unlock()
	if i < len(relevant) {
		file, start, limit := parseSpan(relevant[i])
		args := map[string]any{"file_path": file}
		if start > 0 {
			args["offset"] = start
		}
		if limit > 0 {
			args["limit"] = limit
		}
		b, _ := json.Marshal(args)
		return &client.ChatResponse{Model: "m",
			Message: client.Message{Role: "assistant", ToolCalls: []client.ToolCall{{ID: "r", Name: "Read", Arguments: string(b)}}},
			Usage:   client.Usage{PromptTokens: 5, CompletionTokens: 2}}, nil
	}
	return write()
}

// parseSpan parses "file:start-end" into file, offset (start), limit (end-start+1).
func parseSpan(s string) (file string, start, limit int) {
	file = s
	if i := strings.LastIndex(s, ":"); i > 0 {
		file = s[:i]
		var a, b int
		if _, err := fmt.Sscanf(s[i+1:], "%d-%d", &a, &b); err == nil && a > 0 {
			start = a
			if b >= a {
				limit = b - a + 1
			}
		}
	}
	return
}

// failureClassProvider fails verification sessions in one specific way so the
// per-operation taxonomy can be asserted (feature 014, FR-018). Non-verification
// phases behave like pathWriter.
type failureClassProvider struct {
	pw    *pathWriter
	class string // transport | tool_envelope | tool_envelope_repairable | invalid_tool_args | invalid_submission | turn_exhaustion
	mu    sync.Mutex
	calls map[string]int
}

func newFailureClassProvider(class string) *failureClassProvider {
	return &failureClassProvider{pw: &pathWriter{model: "m"}, class: class, calls: map[string]int{}}
}

func (f *failureClassProvider) Backend() client.Backend { return "fake" }
func (f *failureClassProvider) Endpoint() string        { return "fake://local" }
func (f *failureClassProvider) Chat(ctx context.Context, req client.ChatRequest) (*client.ChatResponse, error) {
	isVerify := false
	for _, m := range req.Messages {
		if m.Role == "system" && strings.Contains(strings.ToLower(m.Content), "verif") {
			isVerify = true
		}
	}
	if !isVerify {
		return f.pw.Chat(ctx, req)
	}
	f.mu.Lock()
	f.calls[f.class]++
	n := f.calls[f.class]
	f.mu.Unlock()
	switch f.class {
	case "transport":
		return nil, &client.TransportError{Backend: "fake", Endpoint: "fake://local", Msg: "connection reset", Kind: client.KindGeneric}
	case "tool_envelope":
		return nil, &client.TransportError{Backend: "fake", Endpoint: "fake://local", Msg: "bad tool json", Kind: client.KindToolParse}
	case "tool_envelope_repairable":
		if n == 1 {
			return nil, &client.TransportError{Backend: "fake", Endpoint: "fake://local", Msg: "bad tool json", Kind: client.KindToolParse}
		}
		return f.pw.Chat(ctx, req) // subsequent calls behave (repair succeeds)
	case "invalid_tool_args":
		return &client.ChatResponse{Model: "m", Message: client.Message{Role: "assistant",
			ToolCalls: []client.ToolCall{{ID: "x", Name: "Read", Arguments: `{}`}}}}, nil // missing file_path
	case "invalid_submission":
		return &client.ChatResponse{Model: "m", Message: client.Message{Role: "assistant",
			ToolCalls: []client.ToolCall{{ID: "x", Name: "submit_verification", Arguments: `{"verdict":"maybe","rationale":"x","entry_point":"GET /x","evidence_ids":[]}`}}}}, nil // bad verdict → contract violation
	case "turn_exhaustion":
		// Never submit: keep issuing a VALID read (a real vulnapp file) until max_turns,
		// so the only failure class is turn exhaustion itself.
		return &client.ChatResponse{Model: "m", Message: client.Message{Role: "assistant",
			ToolCalls: []client.ToolCall{{ID: "x", Name: "Read", Arguments: `{"file_path":"app/main.py","offset":1,"limit":5}`}}}}, nil
	}
	return f.pw.Chat(ctx, req)
}

// repairOnceWriter emits one malformed tool call on its first phase-1 turn (forcing
// the agent's fresh-context repair), then behaves like pathWriter — so a test can
// assert the repair call is captured as its own prompt record (kind=repair).
type repairOnceWriter struct {
	pw   *pathWriter
	mu   sync.Mutex
	done bool
}

func (r *repairOnceWriter) Backend() client.Backend { return "fake" }
func (r *repairOnceWriter) Endpoint() string        { return "fake://local" }
func (r *repairOnceWriter) Chat(ctx context.Context, req client.ChatRequest) (*client.ChatResponse, error) {
	r.mu.Lock()
	first := !r.done
	// Only the very first main-loop turn of the run is malformed; a repair request
	// (2 messages, system mentions the invalid tool call) must succeed.
	isRepair := len(req.Messages) == 2 && strings.Contains(req.Messages[0].Content, "invalid tool call")
	if first && !isRepair {
		r.done = true
	}
	r.mu.Unlock()
	if first && !isRepair {
		return &client.ChatResponse{Model: "m", Message: client.Message{Role: "assistant",
			ToolCalls: []client.ToolCall{{ID: "bad", Name: "Write", Arguments: "{not json"}}}}, nil
	}
	return r.pw.Chat(ctx, req)
}

// verifyPlan tells the verifying double how to support one candidate: the complete
// handler span to capture as evidence and the route guard to cite as entry point.
type verifyPlan struct {
	File       string
	Start, End int
	EntryPoint string
}

// verifyingWriter drives Phase-2b verification sessions through the REAL evidence
// contract — capture_evidence over the complete handler span, then
// submit_verification(supported) citing the returned evidence_id — for candidates
// whose cited location has a plan; unknown candidates are submitted unresolved.
// Everything that is not a verification session is delegated to readingWriter.
type verifyingWriter struct {
	rw    *readingWriter
	plans map[string]verifyPlan // "file:line" (cited location) -> plan
	mu    sync.Mutex
	step  map[string]int // candidate id -> 0 capture, 1 submit, 2 done
}

func newVerifyingWriter(rw *readingWriter, plans map[string]verifyPlan) *verifyingWriter {
	return &verifyingWriter{rw: rw, plans: plans, step: map[string]int{}}
}

func (v *verifyingWriter) Backend() client.Backend { return "fake" }
func (v *verifyingWriter) Endpoint() string        { return "fake://local" }

var reCandidate = regexp.MustCompile(`Candidate: (\S+)\n`)
var reCited = regexp.MustCompile(`Cited location: (\S+)\n`)

func (v *verifyingWriter) Chat(ctx context.Context, req client.ChatRequest) (*client.ChatResponse, error) {
	task := ""
	for _, m := range req.Messages {
		if m.Role == "user" {
			task = m.Content
			break
		}
	}
	if !strings.HasPrefix(task, "Verify EXACTLY this one candidate") {
		return v.rw.Chat(ctx, req)
	}
	cid := ""
	if m := reCandidate.FindStringSubmatch(task); m != nil {
		cid = m[1]
	}
	cited := ""
	if m := reCited.FindStringSubmatch(task); m != nil {
		cited = m[1]
	}
	call := func(name string, args any) (*client.ChatResponse, error) {
		b, _ := json.Marshal(args)
		return &client.ChatResponse{Model: "m", Message: client.Message{Role: "assistant",
			ToolCalls: []client.ToolCall{{ID: "v", Name: name, Arguments: string(b)}}},
			Usage: client.Usage{PromptTokens: 8, CompletionTokens: 3}}, nil
	}
	v.mu.Lock()
	step := v.step[cid]
	v.mu.Unlock()
	plan, ok := v.plans[cited]
	last := req.Messages[len(req.Messages)-1]
	switch {
	case !ok:
		if step == 0 {
			v.mu.Lock()
			v.step[cid] = 2
			v.mu.Unlock()
			return call("submit_verification", map[string]any{"verdict": "unresolved", "rationale": "no plan for this candidate in the fixture",
				"entry_point": "unknown", "evidence_ids": []string{}, "unresolved_questions": []string{"fixture has no plan"}})
		}
	case step == 0:
		v.mu.Lock()
		v.step[cid] = 1
		v.mu.Unlock()
		return call("capture_evidence", map[string]any{"path": plan.File, "start_line": plan.Start, "end_line": plan.End})
	case step == 1 && last.Role == "tool":
		var ev struct {
			ID string `json:"evidence_id"`
		}
		_ = json.Unmarshal([]byte(last.Content), &ev)
		v.mu.Lock()
		v.step[cid] = 2
		v.mu.Unlock()
		return call("submit_verification", map[string]any{
			"verdict": "supported", "rationale": "the handler serves the request without any authorization check",
			"entry_point": plan.EntryPoint, "attacker_control": "any unauthenticated client can reach the route",
			"preconditions": "none", "defenses_reviewed": "no session or role check in the handler",
			"security_impact": "unauthorized access to the operation", "evidence_ids": []string{ev.ID},
		})
	}
	// Accepted (or anything else): stop with no tool call.
	return &client.ChatResponse{Model: "m", Message: client.Message{Role: "assistant", Content: "done"},
		Usage: client.Usage{PromptTokens: 5, CompletionTokens: 2}}, nil
}

// retryOnceWriter stops "complete" WITHOUT writing on a unit's first session and
// writes normally on its second (the bounded re-run) — the recoverable variant of
// the missing-deliverable failure (feature 014, FR-017).
type retryOnceWriter struct {
	pw   *pathWriter
	mu   sync.Mutex
	seen map[string]int // deliverable key -> sessions started
}

func newRetryOnceWriter() *retryOnceWriter {
	return &retryOnceWriter{pw: &pathWriter{model: "m"}, seen: map[string]int{}}
}
func (r *retryOnceWriter) Backend() client.Backend { return "fake" }
func (r *retryOnceWriter) Endpoint() string        { return "fake://local" }
func (r *retryOnceWriter) Chat(ctx context.Context, req client.ChatRequest) (*client.ChatResponse, error) {
	task := ""
	for _, m := range req.Messages {
		if m.Role == "user" {
			task = m.Content
			break
		}
	}
	key := task
	if all := reOutPath.FindAllString(task, -1); len(all) > 0 {
		key = all[len(all)-1]
	}
	if !strings.Contains(key, "/results/") {
		return r.pw.Chat(ctx, req)
	}
	fresh := len(req.Messages) == 2 // system + task = a new session
	r.mu.Lock()
	if fresh {
		r.seen[key]++
	}
	n := r.seen[key]
	r.mu.Unlock()
	if n == 1 { // first session: say done, write nothing
		return &client.ChatResponse{Model: "m", Message: client.Message{Role: "assistant", Content: "done"}, Usage: client.Usage{PromptTokens: 3, CompletionTokens: 1}}, nil
	}
	return r.pw.Chat(ctx, req)
}

// envelopeOnce wraps a provider and fails the FIRST verification-session call with a
// provider tool-envelope parse error, then delegates — the repairable case.
type envelopeOnce struct {
	inner client.Provider
	mu    sync.Mutex
	done  bool
}

func (e *envelopeOnce) Backend() client.Backend { return "fake" }
func (e *envelopeOnce) Endpoint() string        { return "fake://local" }
func (e *envelopeOnce) Chat(ctx context.Context, req client.ChatRequest) (*client.ChatResponse, error) {
	task := ""
	for _, m := range req.Messages {
		if m.Role == "user" {
			task = m.Content
			break
		}
	}
	if strings.HasPrefix(task, "Verify EXACTLY this one candidate") {
		e.mu.Lock()
		first := !e.done
		e.done = true
		e.mu.Unlock()
		if first {
			return nil, &client.TransportError{Backend: "fake", Endpoint: "fake://local", Msg: "bad tool json", Kind: client.KindToolParse}
		}
	}
	return e.inner.Chat(ctx, req)
}

// cancelOnVerify cancels the run context on the first verification-session call
// (checkpoint-on-cancel test); other calls delegate.
type cancelOnVerify struct {
	inner  client.Provider
	cancel func()
	mu     sync.Mutex
	done   bool
}

func (c *cancelOnVerify) Backend() client.Backend { return "fake" }
func (c *cancelOnVerify) Endpoint() string        { return "fake://local" }
func (c *cancelOnVerify) Chat(ctx context.Context, req client.ChatRequest) (*client.ChatResponse, error) {
	task := ""
	for _, m := range req.Messages {
		if m.Role == "user" {
			task = m.Content
			break
		}
	}
	if strings.HasPrefix(task, "Verify EXACTLY this one candidate") {
		c.mu.Lock()
		first := !c.done
		c.done = true
		c.mu.Unlock()
		if first {
			c.cancel()
			return nil, ctx.Err()
		}
	}
	return c.inner.Chat(ctx, req)
}

// ---------------------------------------------------------------------------
// Feature 015 offline doubles (T006). None contacts a network or model.

// dispositionModes for dispositionWriter.
const (
	dispValid          = "valid"           // one validated block per in-scope handler
	dispNone           = "none"            // reads only, no section (source exposure)
	dispOutOfScope     = "out_of_scope"    // blocks for handlers NOT in this unit's scope
	dispFabricated     = "fabricated"      // handler ids that do not exist
	dispUnresolved     = "unresolved"      // this pass's check left unresolved
	dispEvidenceUnread = "evidence_unread" // cites ranges the unit never read
	dispProseOnly      = "prose_only"      // "I reviewed everything" sentence, no blocks
)

var reTaskClass = regexp.MustCompile(`Vulnerability class for THIS pass:\*\* ([A-Z]+)`)

// dispositionWriter is a readingWriter whose deliverable carries the v2
// "## Handler dispositions" section (data-model, feature 015). handlers are
// "file:line METHOD PATH" route ids; spans are the "file:start-end" handler spans
// it reads (same scope rule as readingWriter). classes lists the planned passes
// (e.g. INJ, NAV, LOG); only the task's own class is marked done.
func newDispositionWriter(spans []string, handlerSpans map[string]string, classes []string, mode string) *readingWriter {
	rw := newReadingWriter(spans)
	handlers := make([]string, 0, len(handlerSpans))
	for h := range handlerSpans {
		handlers = append(handlers, h)
	}
	sort.Strings(handlers)
	// spanFor cites the handler's OWN function span ("file:start-end" keyed by
	// route id — for Go registration-style routes the id line is the registration,
	// not the handler, so the map is the only honest source).
	spanFor := func(h string) string {
		s := handlerSpans[h]
		if i := strings.IndexByte(s, ':'); i >= 0 {
			return s[i+1:]
		}
		return "1-1"
	}
	rw.extra = func(task string) string {
		if mode == dispNone {
			return ""
		}
		if mode == dispProseOnly {
			return "\nI reviewed every handler in the assigned scope thoroughly; no issues found.\n"
		}
		cls := "INJ"
		if m := reTaskClass.FindStringSubmatch(task); m != nil {
			cls = m[1]
		}
		var b strings.Builder
		b.WriteString("\n## Handler dispositions\n\n")
		for _, h := range handlers {
			file := h
			if i := strings.IndexByte(h, ':'); i >= 0 {
				file = h[:i]
			}
			sub := file
			if i := strings.IndexByte(file, '/'); i >= 0 {
				sub = file[:i]
			}
			inScope := strings.Contains(task, sub+" ") || strings.Contains(task, sub+"\n") || strings.Contains(task, file)
			if mode == dispOutOfScope {
				inScope = !inScope
			}
			if !inScope {
				continue
			}
			id := h
			if mode == dispFabricated {
				id = "ghost/" + h
			}
			ev := spanFor(h)
			if mode == dispEvidenceUnread {
				ev = "900-950"
			}
			fmt.Fprintf(&b, "- **Handler**: %s\n", id)
			var checks []string
			for _, c := range classes {
				switch {
				case c == cls && mode == dispUnresolved:
					checks = append(checks, c+"=unresolved(needs a second pass on the auth branch)")
				case c == cls:
					checks = append(checks, c+"=done")
				default:
					checks = append(checks, c+"=n/a(not this pass)")
				}
			}
			fmt.Fprintf(&b, "- **Checks**: %s\n", strings.Join(checks, ", "))
			b.WriteString("- **Defenses reviewed**: input validation and the route guard\n")
			fmt.Fprintf(&b, "- **Evidence**: %s:%s\n", file, ev)
			b.WriteString("- **Rationale**: handler body read in full; no sink reachable from request input for this class\n")
			b.WriteString("- **Unresolved**: none\n\n")
		}
		return b.String()
	}
	return rw
}

// citationRepairWriter emits a hunt finding whose Location is one of the audited
// malformed strings; when the session carries citation feedback (a user message
// naming an E_CITATION_ code), it rewrites the deliverable with a valid citation.
type citationRepairWriter struct {
	pw       *pathWriter
	bad      string // the malformed original location
	good     string // the corrected "file:line" citation
	mu       sync.Mutex
	repaired map[string]bool
}

func newCitationRepairWriter(bad, good string) *citationRepairWriter {
	return &citationRepairWriter{pw: &pathWriter{model: "m"}, bad: bad, good: good, repaired: map[string]bool{}}
}

func (c *citationRepairWriter) Backend() client.Backend { return "fake" }
func (c *citationRepairWriter) Endpoint() string        { return "fake://local" }
func (c *citationRepairWriter) Chat(ctx context.Context, req client.ChatRequest) (*client.ChatResponse, error) {
	task, feedback := "", false
	for _, m := range req.Messages {
		if m.Role == "user" {
			if task == "" {
				task = m.Content
			}
			if strings.Contains(m.Content, "E_CITATION_") {
				feedback = true
			}
		}
	}
	key := task
	if all := reOutPath.FindAllString(task, -1); len(all) > 0 {
		key = all[len(all)-1]
	}
	if !strings.Contains(key, "/results/") {
		return c.pw.Chat(ctx, req)
	}
	if n := len(req.Messages); n > 0 && req.Messages[n-1].Role == "tool" && !feedback {
		return &client.ChatResponse{Message: client.Message{Role: "assistant", Content: "done"}}, nil
	}
	loc := c.bad
	c.mu.Lock()
	if feedback {
		c.repaired[key] = true
		loc = c.good
	}
	done := c.repaired[key]
	c.mu.Unlock()
	if feedback && done && len(req.Messages) > 0 && req.Messages[len(req.Messages)-1].Role == "tool" {
		return &client.ChatResponse{Message: client.Message{Role: "assistant", Content: "done"}}, nil
	}
	content := "## Findings\n\n#### [VULN-001] SQL injection in search\n\n- **CWE**: CWE-89\n- **Severity**: High\n" +
		"- **Location**: " + loc + "\n- **Entry Point**: GET /api/search\n- **Data Flow**: q -> execute()\n- **Root Cause**: string concatenation\n- **Fix**: parameterize\n"
	args, _ := json.Marshal(map[string]string{"path": key, "content": content})
	return &client.ChatResponse{Model: "m", Message: client.Message{Role: "assistant",
		ToolCalls: []client.ToolCall{{ID: "w", Name: "Write", Arguments: string(args)}}}}, nil
}

// amendPlan is where amendingVerifier moves a candidate's citation before verifying.
type amendPlan struct {
	Path       string
	Start, End int
	Reason     string
}

// amendingVerifier issues one amend_candidate call for candidates it has a plan
// for, then verifies through the real evidence contract (verifyingWriter).
type amendingVerifier struct {
	vw     *verifyingWriter
	amends map[string]amendPlan // cited location -> amendment
	mu     sync.Mutex
	did    map[string]bool
}

func newAmendingVerifier(vw *verifyingWriter, amends map[string]amendPlan) *amendingVerifier {
	return &amendingVerifier{vw: vw, amends: amends, did: map[string]bool{}}
}

func (a *amendingVerifier) Backend() client.Backend { return "fake" }
func (a *amendingVerifier) Endpoint() string        { return "fake://local" }
func (a *amendingVerifier) Chat(ctx context.Context, req client.ChatRequest) (*client.ChatResponse, error) {
	task := ""
	for _, m := range req.Messages {
		if m.Role == "user" {
			task = m.Content
			break
		}
	}
	if !strings.HasPrefix(task, "Verify EXACTLY this one candidate") {
		return a.vw.Chat(ctx, req)
	}
	cid, cited := "", ""
	if m := reCandidate.FindStringSubmatch(task); m != nil {
		cid = m[1]
	}
	if m := reCited.FindStringSubmatch(task); m != nil {
		cited = m[1]
	}
	plan, ok := a.amends[cited]
	a.mu.Lock()
	first := ok && !a.did[cid]
	if first {
		a.did[cid] = true
	}
	a.mu.Unlock()
	if first {
		args, _ := json.Marshal(map[string]any{"candidate_id": cid, "path": plan.Path, "start_line": plan.Start, "end_line": plan.End, "reason": plan.Reason})
		return &client.ChatResponse{Model: "m", Message: client.Message{Role: "assistant",
			ToolCalls: []client.ToolCall{{ID: "a", Name: "amend_candidate", Arguments: string(args)}}}}, nil
	}
	return a.vw.Chat(ctx, req)
}

// mixedFailureVerifier: per candidate, turn 1 = Read with empty args (invalid
// tool args), turn 2 = submit_verification with a bad verdict (invalid
// submission), then VALID reads until the turn limit (turn exhaustion) — three
// distinct failure classes in one session.
type mixedFailureVerifier struct {
	pw    *pathWriter
	read  string // a real repo-relative file for the valid reads
	mu    sync.Mutex
	turns map[string]int
}

func newMixedFailureVerifier(read string) *mixedFailureVerifier {
	return &mixedFailureVerifier{pw: &pathWriter{model: "m"}, read: read, turns: map[string]int{}}
}

func (m *mixedFailureVerifier) Backend() client.Backend { return "fake" }
func (m *mixedFailureVerifier) Endpoint() string        { return "fake://local" }
func (m *mixedFailureVerifier) Chat(ctx context.Context, req client.ChatRequest) (*client.ChatResponse, error) {
	task := ""
	for _, msg := range req.Messages {
		if msg.Role == "user" {
			task = msg.Content
			break
		}
	}
	if !strings.HasPrefix(task, "Verify EXACTLY this one candidate") {
		return m.pw.Chat(ctx, req)
	}
	cid := ""
	if mm := reCandidate.FindStringSubmatch(task); mm != nil {
		cid = mm[1]
	}
	m.mu.Lock()
	m.turns[cid]++
	n := m.turns[cid]
	m.mu.Unlock()
	call := func(name, args string) (*client.ChatResponse, error) {
		return &client.ChatResponse{Model: "m", Message: client.Message{Role: "assistant",
			ToolCalls: []client.ToolCall{{ID: fmt.Sprintf("c%d", n), Name: name, Arguments: args}}}}, nil
	}
	switch n {
	case 1:
		return call("Read", `{}`)
	case 2:
		return call("submit_verification", `{"verdict":"maybe","rationale":"x","entry_point":"GET /x","evidence_ids":[]}`)
	}
	return call("Read", fmt.Sprintf(`{"file_path":%q,"offset":1,"limit":5}`, m.read))
}

// identityRecordingProvider wraps a provider and stamps its own name into every
// response's provenance (and records each call), so a test can prove which
// provider actually served each verifier call (feature 015, comparison harness).
type identityRecordingProvider struct {
	name  string
	inner client.Provider
	mu    sync.Mutex
	calls []string // first line of the user task per call
}

func newIdentityRecordingProvider(name string, inner client.Provider) *identityRecordingProvider {
	return &identityRecordingProvider{name: name, inner: inner}
}

func (p *identityRecordingProvider) Backend() client.Backend { return client.Backend("fake-" + p.name) }
func (p *identityRecordingProvider) Endpoint() string        { return "fake://" + p.name }
func (p *identityRecordingProvider) Chat(ctx context.Context, req client.ChatRequest) (*client.ChatResponse, error) {
	task := ""
	for _, m := range req.Messages {
		if m.Role == "user" {
			task = m.Content
			break
		}
	}
	if i := strings.IndexByte(task, '\n'); i >= 0 {
		task = task[:i]
	}
	p.mu.Lock()
	p.calls = append(p.calls, task)
	p.mu.Unlock()
	resp, err := p.inner.Chat(ctx, req)
	if resp != nil {
		resp.Provenance.Backend = p.Backend()
		resp.Provenance.Endpoint = p.Endpoint()
		resp.Provenance.RequestedModel = p.name
		resp.Provenance.ReturnedModel = p.name
	}
	return resp, err
}

func (p *identityRecordingProvider) Calls() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.calls...)
}
