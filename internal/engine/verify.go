package engine

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"vhlocal/internal/citation"
	"vhlocal/internal/client"
	"vhlocal/internal/consolidate"
	"vhlocal/internal/source"
	"vhlocal/internal/tools"
	"vhlocal/internal/verification"
)

const (
	verifyTurnsPerCandidate = 20
	verifyMaxFailures       = 3
	// verifyRepeatLimit: an identical rejected submission repeated this many times
	// ends the session with E_REPEATED_SUBMISSION (feature 015, C-C6).
	verifyRepeatLimit = 2
)

// reSampleFile matches per-sample hunt files (results/<unit>.s<N>.md), which are
// merged into <unit>.md and must not be re-read as separate candidates.
var reSampleFile = regexp.MustCompile(`\.s\d+\.md$`)

// verifyOptions carries the feature-015 session settings into verification.
type verifyOptions struct {
	frozenManifest    *verification.Manifest // comparison input, copied before amendments
	sessionPrompt     string                 // skill/phases/phase2b_session.md (worked examples)
	diagnosticCapture string                 // bounded | full
}

// runVerification is Phase 2b as the reference adversarial, candidate-bound
// verifier (feature 005, US3): it builds the candidate manifest from the hunt
// output, runs ONE fresh session per candidate (exposing capture_evidence +
// submit_verification + amend_candidate alongside read-only Read/Grep), reconciles
// every candidate to supported/rejected/unresolved fail-closed, and renders the
// disposition table + supported-only handoff. Returns whether the disposition
// output was produced.
func runVerification(ctx context.Context, rec *RunRecord, p client.Provider, sb *tools.Sandbox, spec ScanSpec, system string, emit Emit) bool {
	return runVerificationWith(ctx, rec, p, sb, spec, system, verifyOptions{diagnosticCapture: spec.DiagnosticCapture}, emit)
}

func runVerificationWith(ctx context.Context, rec *RunRecord, p client.Provider, sb *tools.Sandbox, spec ScanSpec, system string, vo verifyOptions, emit Emit) bool {
	cands := collectHuntCandidates(spec.ResultsDir)
	rev := "tree-sha256:unknown"
	if rec.GitCommit != "" {
		rev = rec.GitCommit
	}
	// Feature 015 (C-C7): a prior manifest's accepted amendments are replayed on
	// resume (same revision) or recorded as rejected (revision mismatch).
	var prior *verification.Manifest
	if b, err := os.ReadFile(filepath.Join(spec.ResultsDir, verification.CandidateManifestFile)); err == nil {
		var pm verification.Manifest
		if json.Unmarshal(b, &pm) == nil {
			prior = &pm
		}
	}
	var man *verification.Manifest
	var err error
	if vo.frozenManifest != nil {
		b, e := json.Marshal(vo.frozenManifest)
		if e != nil {
			return false
		}
		man = &verification.Manifest{}
		err = json.Unmarshal(b, man)
		if err == nil {
			err = verification.WriteManifest(spec.ResultsDir, man)
		}
	} else {
		man, err = verification.BuildManifest(spec.ResultsDir, spec.Repo, rev, cands)
	}
	if err != nil {
		markPhaseFailed(rec, "2b", err)
		return false
	}
	if prior != nil {
		verification.ReplayAmendments(man, prior, spec.Repo)
		if err := verification.WriteManifest(spec.ResultsDir, man); err != nil {
			markPhaseFailed(rec, "2b", err)
			return false
		}
	}
	model := roleModel(spec, "2b")
	var decisions []verification.Decision
	var sessions []verification.SessionOutcome
	checkpoint := func() bool {
		if err := verification.WriteDecisions(spec.ResultsDir, decisions); err != nil {
			markPhaseFailed(rec, "2b", err)
			return false
		}
		_ = verification.WriteSessions(spec.ResultsDir, sessions)
		rc := verification.Reconcile(man, decisions, spec.Repo)
		verification.EnrichReasons(rc, verification.LoadSessions(spec.ResultsDir))
		if err := verification.Render(spec.ResultsDir, man, rc); err != nil {
			markPhaseFailed(rec, "2b", err)
			return false
		}
		return true
	}
	// Invalidate previous decisions before starting and persist every accepted
	// candidate so cancellation cannot expose stale support or lose finished work.
	if !checkpoint() {
		return false
	}
	endpointFails := 0
	// flushSessions persists session outcomes after EVERY session and on cancellation
	// (feature 014, FR-018) — a decision-less session is never lost to a cancel.
	flushSessions := func() { _ = verification.WriteSessions(spec.ResultsDir, sessions) }
	outcomeOf := func(c verification.Candidate, res agentResult) verification.SessionOutcome {
		so := verification.SessionOutcome{
			CandidateID: c.ID, StopReason: res.StoppedReason, Turns: res.Turns, Failures: res.Failures,
			FailuresByClass: res.ByClass, LastOperation: res.LastOp, LastContractViolation: res.LastViolation,
			Calls: len(res.Calls), Model: res.Model, ExplicitUnresolved: res.ExplicitUnresolved, Amended: res.Amended, StopCode: res.StopCode,
		}
		if res.Provenance.Backend != "" || res.Provenance.RequestedModel != "" {
			so.Provenance = &verification.Provenance{Backend: string(res.Provenance.Backend), Endpoint: res.Provenance.Endpoint,
				RequestedModel: res.Provenance.RequestedModel, ReturnedModel: res.Provenance.ReturnedModel}
		}
		return so
	}
	n := len(man.Candidates)
	for i := 0; i < n; i++ { // amendments may append candidates; those are verified in their originating session
		c := man.Candidates[i]
		if ctx.Err() != nil {
			rec.Cancelled = true
			flushSessions()
			return false
		}
		if !c.HasValidCitation() {
			// Feature 015 (C-C1): an invalid citation is visible in the manifest and the
			// report but never earns a session — there is nothing sound to verify.
			emit.emit("citation_invalid", map[string]any{"label": "verify:" + c.ID, "code": c.Citation.Error.Code, "received": c.Citation.Original})
			continue
		}
		if c.Superseded != "" {
			continue
		}
		emit.emit("agent_start", map[string]any{"label": "verify:" + c.ID, "model": model})
		cur := c // the session works on a copy; amendments update the manifest slot explicitly
		d, res, final := verifyCandidate(ctx, p, sb, spec, model, system, vo, man, &cur)
		_ = verification.AppendCalls(spec.ResultsDir, res.Calls)
		if res.Amended {
			if err := verification.WriteManifest(spec.ResultsDir, man); err != nil {
				markPhaseFailed(rec, "2b", err)
				return false
			}
			emit.emit("amendment", map[string]any{"label": "verify:" + c.ID, "candidate": final.ID, "identity": res.AmendIdentity})
		}
		if len(res.failing) > 0 {
			writeDiagnostic(spec.ResultsDir, vo.diagnosticCapture, final, res, man.Revision)
		}
		if res.StoppedReason == "cancelled" {
			rec.Cancelled = true
			sessions = append(sessions, outcomeOf(final, res))
			flushSessions()
			return false
		}
		recordVerifyAgent(rec, "2b", "verify:"+c.ID, model, final.ID, res)
		sessions = append(sessions, outcomeOf(final, res))
		for class, n := range res.ByClass { // feature 014 (FR-006): tool failures are logged events
			op, msg, code := res.LastOp, res.LastViolation, ""
			if ci, ok := res.perClass[class]; ok { // feature 015 (C-C10): per-class operation/message
				op, msg, code = ci.op, ci.msg, ci.code
			}
			emit.emit("tool_failure", map[string]any{"label": "verify:" + c.ID, "class": class, "count": n, "operation": op, "message": msg, "code": code})
		}
		if res.StoppedReason == "endpoint_failure" && res.Err != nil {
			endpointFails++
			markPhaseFailed(rec, "2b", res.Err)
		}
		pt, ct := usageTiles(rec)
		emit.emit("agent_done", map[string]any{"label": "verify:" + c.ID, "turns": res.Turns, "stopped_reason": res.StoppedReason, "prompt_tokens": pt, "completion_tokens": ct})
		if d != nil {
			decisions = append(decisions, *d)
			if !checkpoint() {
				return false
			}
		} else {
			flushSessions()
		}
	}
	_ = verification.WriteSessions(spec.ResultsDir, sessions)
	rc := verification.Reconcile(man, decisions, spec.Repo)
	verification.EnrichReasons(rc, verification.LoadSessions(spec.ResultsDir))
	if err := verification.WriteDecisions(spec.ResultsDir, decisions); err != nil {
		markPhaseFailed(rec, "2b", err)
		return false
	}
	if err := verification.Render(spec.ResultsDir, man, rc); err != nil {
		markPhaseFailed(rec, "2b", err)
		return false
	}
	// Explicit unresolved decisions are valid dispositions; missing decisions are not.
	return rc.Complete && (len(man.Candidates) > 0 || containsStr(rec.PhasesCompleted, "2")) &&
		endpointFails == 0 && deliverableValid(filepath.Join(spec.ResultsDir, "phase2b_output.md"))
}

// loadVerifiedFindings re-derives findings from the persisted candidate manifest +
// verification decisions (deterministic; used by finalize AND regeneration). Every
// candidate carries its reconciled disposition; FromConfirmed is supported-only.
func loadVerifiedFindings(resultsDir, repo string) ([]consolidate.Finding, bool) {
	b, err := os.ReadFile(filepath.Join(resultsDir, verification.CandidateManifestFile))
	if err != nil {
		return nil, false
	}
	var man verification.Manifest
	if json.Unmarshal(b, &man) != nil {
		return nil, true
	}
	var decs []verification.Decision
	if db, e := os.ReadFile(filepath.Join(resultsDir, verification.DecisionsFile)); e == nil {
		_ = json.Unmarshal(db, &decs)
	}
	rc := verification.Reconcile(&man, decs, repo)
	verification.EnrichReasons(rc, verification.LoadSessions(resultsDir))
	return verification.FinalFindings(&man, rc), true
}

// collectHuntCandidates reads the raw hunt output (results/*.md) into candidate
// findings — this is the ONLY place raw hunt output is read, and only to seed the
// manifest for verification; it is never published directly (FR-C1).
func collectHuntCandidates(resultsDir string) []consolidate.Finding {
	var all []consolidate.Finding
	planned := map[string]bool{}
	execution, hasPlan := loadHuntExecution(resultsDir)
	for _, name := range execution.Files {
		planned[filepath.Base(name)] = true
	}
	sub := filepath.Join(resultsDir, "results")
	entries, _ := os.ReadDir(sub)
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".md") || (hasPlan && !planned[e.Name()]) {
			continue
		}
		// Read only the MERGED per-unit files, never the per-sample `.sN.md` files —
		// otherwise the same candidate is extracted from the merge AND each sample,
		// producing duplicate candidates and "duplicate decisions" at reconciliation.
		if reSampleFile.MatchString(e.Name()) {
			continue
		}
		if b, err := os.ReadFile(filepath.Join(sub, e.Name())); err == nil {
			all = append(all, consolidate.ExtractFindings(string(b), "results/"+e.Name())...)
		}
	}
	for i := range all {
		consolidate.ApplyKnowledge(&all[i])
	}
	return all
}

// candidateFacts renders the canonical facts the session must work from (C-C5):
// the resolved handler span, the route identity separate from the display label,
// the file length and the required evidence span — only what the recognizer
// resolved, never a guess.
func candidateFacts(c verification.Candidate) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Display label (as the hunt wrote it): %s\n", orText(c.Finding.EntryPoint, "none"))
	if c.Citation == nil || c.Citation.Binding == nil {
		b.WriteString("Canonical facts: the harness could not resolve a handler for this citation; establish it with Read/Grep or submit unresolved.\n")
		return b.String()
	}
	bd := c.Citation.Binding
	if bd.Route != nil {
		fmt.Fprintf(&b, "Route identity (your entry_point must equal this EXACTLY): %s\n", bd.Route.String())
	} else {
		fmt.Fprintf(&b, "Route identity: unresolved (%s) — entry_point must name the real route guard you establish from source\n", orText(bd.Reason, "no route bound"))
	}
	if bd.Handler != nil {
		name := bd.Handler.Name
		if name == "" {
			name = "(unnamed span)"
		}
		fmt.Fprintf(&b, "Handler span: %s:%d-%d (%s)\n", bd.Handler.File, bd.Handler.Span[0], bd.Handler.Span[1], name)
		fmt.Fprintf(&b, "Required evidence span: lines %d-%d of %s (capture_evidence must cover the COMPLETE handler, decorators included)\n", bd.Handler.Span[0], bd.Handler.Span[1], bd.Handler.File)
	}
	fmt.Fprintf(&b, "File length: %d lines\n", bd.FileLength)
	fmt.Fprintf(&b, "Binding certainty: %s\n", bd.Certainty)
	return b.String()
}

// verifyCandidate runs one fresh verification session for a single candidate and
// returns the accepted decision (or nil), the agent result, and the candidate the
// decision belongs to (a different one after a superseding amendment).
func verifyCandidate(ctx context.Context, p client.Provider, sb *tools.Sandbox, spec ScanSpec, model, system string, vo verifyOptions,
	man *verification.Manifest, c *verification.Candidate) (d *verification.Decision, res agentResult, final verification.Candidate) {
	evidence := map[string]verification.Evidence{}
	failures := 0
	res.Model = model
	res.perClass = map[string]classInfo{}
	// Record the tool-failure count on every exit path (feature 007, T032/T037).
	defer func() { res.Failures = failures; final = *c }()

	initial := initialContext(spec.Repo, c.Finding.Location, evidence)
	sys := verifySystem(system, vo.sessionPrompt)
	toolset := verifyToolEnvelope()
	res.PromptHash = sha256Hex([]byte(sys))
	if tb, err := json.Marshal(toolset); err == nil {
		res.ToolSchemaHash = sha256Hex(tb)
	}
	msgs := []client.Message{
		{Role: "system", Content: sys},
		{Role: "user", Content: fmt.Sprintf(
			"Verify EXACTLY this one candidate. Capture evidence, then submit_verification.\n\n"+
				"Candidate: %s\nTitle: %s\nCWE: %s\nCited location: %s\nEntry point: %s\n\n%s\n"+
				"Primary context (already captured for you):\n%s\n\n"+
				"Acceptance includes an explicit 'unresolved'; it does not imply confirmation. "+
				"If the cited lines are not the sink, call amend_candidate ONCE with the correct path and lines before submitting.",
			c.ID, c.Finding.Title, c.Finding.CWE, c.Finding.Location, c.Finding.EntryPoint, candidateFacts(*c), initial)},
	}
	if vo.diagnosticCapture == DiagnosticFull {
		defer func() { res.ContextMessages = msgs }()
	}
	for turn := 0; turn < verifyTurnsPerCandidate; turn++ {
		if ctx.Err() != nil {
			res.StoppedReason = "cancelled"
			return nil, res, *c
		}
		res.Turns = turn + 1
		resp, err := p.Chat(ctx, client.ChatRequest{Model: model, Messages: msgs, Tools: toolset,
			NumCtx: spec.NumCtx, MaxOutputTokens: spec.MaxOutputTokens, ReasoningEffort: spec.ReasoningEffort})
		if err != nil && (ctx.Err() != nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)) {
			// Feature 014 (FR-015/018): cancellation is NOT an endpoint failure — record
			// it as such so the session outcome is flushed honestly by the caller.
			res.StoppedReason = "cancelled"
			return nil, res, *c
		}
		if err != nil {
			// A provider tool-call-parse rejection (the model mixed prose with the
			// tool-call JSON, or emitted invalid JSON) is recoverable — steer it and
			// retry within the session's bounded budget rather than failing the
			// candidate (parity with the feature-004 agent repair). A GENERIC transport
			// failure degrades this candidate to unresolved and is recorded.
			var te *client.TransportError
			if errors.As(err, &te) && te.Kind == client.KindToolParse {
				failures++
				res.classify(verification.FailToolEnvelope, "chat", "provider could not parse the tool call: "+te.Msg, "")
				res.logCall(c.ID, "chat", nil, "", "error", verification.FailToolEnvelope, "", te.Msg, "")
				if failures >= verifyMaxFailures {
					res.StoppedReason = "tool_repair"
					return nil, res, *c
				}
				msgs = append(msgs, client.Message{Role: "user", Content: "Your previous message could not be parsed as a tool call: do not mix prose with the tool call, and emit valid JSON arguments. Re-issue exactly ONE valid tool call (capture_evidence, amend_candidate or submit_verification)."})
				continue
			}
			res.classify(verification.FailTransport, "chat", err.Error(), "")
			res.logCall(c.ID, "chat", nil, "", "error", verification.FailTransport, "", err.Error(), "")
			res.StoppedReason = "endpoint_failure"
			res.Err = err
			return nil, res, *c
		}
		res.Prompt += resp.Usage.PromptTokens
		res.Completion += resp.Usage.CompletionTokens
		res.Provenance = resp.Provenance // feature 015 (C-C12): effective provider identity, every call
		if res.Provenance.Backend == "" {
			res.Provenance.Backend, res.Provenance.Endpoint = p.Backend(), p.Endpoint()
		}
		if resp.Model != "" && res.Provenance.ReturnedModel == "" {
			res.Provenance.ReturnedModel = resp.Model
		}
		if res.Provenance.RequestedModel == "" {
			res.Provenance.RequestedModel = model
		}
		msgs = append(msgs, resp.Message)
		if len(resp.Message.ToolCalls) == 0 {
			// Model stopped without submitting → one nudge, then give up (unresolved).
			if !res.nudged {
				res.nudged = true
				msgs = append(msgs, client.Message{Role: "user", Content: "You must call submit_verification with a verdict (supported/rejected/unresolved) before finishing."})
				continue
			}
			res.StoppedReason = "complete"
			return nil, res, *c
		}
		for _, tc := range resp.Message.ToolCalls {
			out, decided, dec, stop := handleVerifyTool(sb, spec.Repo, man, c, tc, evidence, &failures, &res)
			msgs = append(msgs, client.Message{Role: "tool", Name: tc.Name, ToolCallID: tc.ID, Content: out})
			if decided {
				res.StoppedReason = "complete"
				if dec.Verdict == "unresolved" {
					res.ExplicitUnresolved = true
				}
				return dec, res, *c
			}
			if stop != "" {
				res.StoppedReason = stop
				return nil, res, *c
			}
			if failures >= verifyMaxFailures {
				res.StoppedReason = "tool_repair"
				return nil, res, *c
			}
		}
	}
	// Turn exhaustion is how the session ENDED; it must not mask the last failed tool
	// operation, which is the actionable diagnosis (FR-018).
	if res.ByClass == nil {
		res.ByClass = map[string]int{}
	}
	res.ByClass[verification.FailTurnExhaustion]++
	res.perClass[verification.FailTurnExhaustion] = classInfo{op: "turn limit", msg: "no decision submitted within the turn budget"}
	res.logCall(c.ID, "turn limit", nil, "", "error", verification.FailTurnExhaustion, "", "no decision submitted within the turn budget", "")
	if res.LastOp == "" {
		res.LastOp, res.LastViolation = "turn limit", "no decision submitted within the turn budget"
	}
	res.StoppedReason = "max_turns"
	return nil, res, *c
}

// argError is a strict-decoding failure for one tool argument.
type argError struct {
	code, field, received, expected string
}

// strictArgs decodes tool arguments without coercion (C-C6): malformed JSON ⇒
// E_TOOL_ARGS_JSON; a present field of the wrong type ⇒ E_TOOL_ARGS_TYPE with the
// field. `types` maps field → "string" | "integer" | "boolean" | "string[]".
func strictArgs(raw string, types map[string]string) (map[string]any, *argError) {
	args := map[string]any{}
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return args, nil
	}
	if err := json.Unmarshal([]byte(trimmed), &args); err != nil {
		return nil, &argError{code: citation.EToolArgsJSON, received: clampStr(trimmed, 120), expected: "a JSON object of arguments: " + err.Error()}
	}
	for field, want := range types {
		v, ok := args[field]
		if !ok || v == nil {
			continue
		}
		bad := false
		switch want {
		case "string":
			_, isStr := v.(string)
			bad = !isStr
		case "integer":
			f, isNum := v.(float64)
			bad = !isNum || f != float64(int(f))
		case "boolean":
			_, isBool := v.(bool)
			bad = !isBool
		case "string[]":
			arr, isArr := v.([]any)
			bad = !isArr
			for _, x := range arr {
				if _, isStr := x.(string); !isStr {
					bad = true
				}
			}
		}
		if bad {
			rb, _ := json.Marshal(v)
			return nil, &argError{code: citation.EToolArgsType, field: field, received: clampStr(string(rb), 80), expected: want}
		}
	}
	return args, nil
}

var verifyArgTypes = map[string]map[string]string{
	"read":                {"file_path": "string", "path": "string", "offset": "integer", "limit": "integer"},
	"grep":                {"pattern": "string", "path": "string", "glob": "string", "ignore_case": "boolean", "files_with_matches": "boolean"},
	"capture_evidence":    {"path": "string", "start_line": "integer", "end_line": "integer"},
	"amend_candidate":     {"candidate_id": "string", "path": "string", "start_line": "integer", "end_line": "integer", "reason": "string"},
	"submit_verification": {"verdict": "string", "rationale": "string", "entry_point": "string", "attacker_control": "string", "preconditions": "string", "defenses_reviewed": "string", "security_impact": "string", "evidence_ids": "string[]", "unresolved_questions": "string[]"},
}

// handleVerifyTool dispatches one tool call inside a verification session. Every
// failure is classified on res (feature 014, FR-018) and logged as its own call
// record (feature 015, C-C10); rejected submissions return STRUCTURED feedback
// (code, field, received, expected, repairable, aids). Returns the tool output,
// whether a decision was accepted, the decision, and a session stop reason ("" to
// continue).
func handleVerifyTool(sb *tools.Sandbox, repo string, man *verification.Manifest, c *verification.Candidate, tc client.ToolCall,
	evidence map[string]verification.Evidence, failures *int, res *agentResult) (string, bool, *verification.Decision, string) {
	name := strings.ToLower(strings.TrimSpace(tc.Name))
	digest := sha256Hex([]byte(name + "|" + strings.TrimSpace(tc.Arguments)))
	args, aerr := strictArgs(tc.Arguments, verifyArgTypes[name])
	if aerr != nil {
		fb := verification.Feedback{Code: aerr.code, Field: aerr.field, Received: aerr.received, Expected: aerr.expected, Repairable: true,
			Message: "arguments were not decoded; nothing was coerced to a default"}
		res.classify(verification.FailInvalidToolArgs, tc.Name, aerr.code+": "+aerr.field+" "+aerr.expected, aerr.code)
		res.logCall(c.ID, tc.Name, nil, digest, "error", verification.FailInvalidToolArgs, aerr.code, aerr.expected, fb.JSON())
		return fb.JSON(), false, nil, ""
	}
	diag := diagnosticArgs(name, args)
	switch name {
	case "read":
		s, err := sb.ReadPaged(firstStrA(args, "file_path", "path"), firstIntA(args, "offset"), firstIntA(args, "limit"))
		if err != nil {
			res.classify(verification.FailInvalidToolArgs, "Read", err.Error(), "")
			res.logCall(c.ID, "Read", diag, digest, "error", verification.FailInvalidToolArgs, "", err.Error(), "")
			return "ERROR: " + err.Error(), false, nil, ""
		}
		res.logCall(c.ID, "Read", diag, digest, "ok", "", "", "", "")
		return s, false, nil, ""
	case "grep":
		out, err := sb.Grep(tools.GrepOpts{Pattern: firstStrA(args, "pattern"), Path: firstStrA(args, "path"),
			Glob: firstStrA(args, "glob"), IgnoreCase: firstBoolA(args, "ignore_case"), FilesWithMatches: firstBoolA(args, "files_with_matches")})
		if err != nil {
			res.classify(verification.FailInvalidToolArgs, "Grep", err.Error(), "")
			res.logCall(c.ID, "Grep", diag, digest, "error", verification.FailInvalidToolArgs, "", err.Error(), "")
			return "ERROR: " + err.Error(), false, nil, ""
		}
		res.logCall(c.ID, "Grep", diag, digest, "ok", "", "", "", "")
		return out, false, nil, ""
	case "capture_evidence":
		ev, err := captureEvidence(repo, firstStrA(args, "path"), firstIntA(args, "start_line"), firstIntA(args, "end_line"), evidence)
		if err != nil {
			res.classify(verification.FailInvalidToolArgs, "capture_evidence", err.Error(), "")
			res.logCall(c.ID, "capture_evidence", diag, digest, "error", verification.FailInvalidToolArgs, "", err.Error(), "")
			return "ERROR: " + err.Error(), false, nil, ""
		}
		res.sourceRefs = append(res.sourceRefs, verification.SourceRef{Path: ev.Path, Start: ev.StartLine, End: ev.EndLine})
		res.logCall(c.ID, "capture_evidence", diag, digest, "ok", "", "", "", "")
		b, _ := json.Marshal(ev)
		return string(b), false, nil, ""
	case "amend_candidate":
		return handleAmendment(repo, man, c, args, diag, digest, failures, res)
	case "submit_verification":
		// C-C6: an identical rejected submission repeated is a stop, not a loop.
		if digest == res.lastSubmitDigest {
			res.repeatCount++
			if res.repeatCount+1 >= verifyRepeatLimit {
				fb := verification.Feedback{Code: citation.ERepeatedSubmission, Field: "submission", Received: "the same rejected submission again",
					Expected: "a corrected submission or an explicit unresolved verdict", Repairable: false, Message: "session ended: identical rejected submission repeated"}
				res.classify(verification.FailRepeated, "submit_verification", fb.Message, citation.ERepeatedSubmission)
				res.logCall(c.ID, "submit_verification", diag, digest, "error", verification.FailRepeated, citation.ERepeatedSubmission, fb.Message, fb.JSON())
				res.StopCode = citation.ERepeatedSubmission
				return fb.JSON(), false, nil, "repeated_submission"
			}
		} else {
			res.lastSubmitDigest, res.repeatCount = digest, 0
		}
		dec, err := buildDecision(man, *c, args, evidence)
		if err != nil {
			*failures++
			fb := verification.ClassifySubmissionError(err.Error(), *c)
			res.classify(verification.FailInvalidSubmission, "submit_verification", err.Error(), fb.Code)
			res.logCall(c.ID, "submit_verification", diag, digest, "error", verification.FailInvalidSubmission, fb.Code, err.Error(), fb.JSON())
			res.failing = append(res.failing, verification.FailingSubmission{CallSeq: res.callSeq, Args: args, Feedback: fb, Code: fb.Code})
			return fb.JSON(), false, nil, ""
		}
		rc := verification.Reconcile(&verification.Manifest{SchemaVersion: man.SchemaVersion, Revision: man.Revision, Repo: man.Repo, Candidates: []verification.Candidate{*c}}, []verification.Decision{*dec}, repo)
		if !rc.Complete {
			*failures++
			why := strings.Join(rc.Errors, "; ")
			fb := verification.ClassifySubmissionError(why, *c)
			res.classify(verification.FailInvalidSubmission, "submit_verification", why, fb.Code)
			res.logCall(c.ID, "submit_verification", diag, digest, "error", verification.FailInvalidSubmission, fb.Code, why, fb.JSON())
			res.failing = append(res.failing, verification.FailingSubmission{CallSeq: res.callSeq, Args: args, Feedback: fb, Code: fb.Code})
			return fb.JSON(), false, nil, ""
		}
		res.logCall(c.ID, "submit_verification", diag, digest, "ok", "", "", "", "")
		return fmt.Sprintf(`{"accepted":true,"candidate_id":%q,"verdict":%q}`, c.ID, dec.Verdict), true, dec, ""
	default:
		fb := verification.Feedback{Code: verification.EUnknownTool, Field: "tool", Received: tc.Name, Expected: "one of Read, Grep, capture_evidence, amend_candidate, submit_verification", Repairable: true}
		res.classify(verification.FailInvalidToolArgs, tc.Name, "unknown tool", verification.EUnknownTool)
		res.logCall(c.ID, tc.Name, nil, digest, "error", verification.FailInvalidToolArgs, verification.EUnknownTool, "unknown tool", fb.JSON())
		return fb.JSON(), false, nil, ""
	}
}

// handleAmendment applies amend_candidate (C-C7): one accepted amendment per
// session, for THIS candidate only, must resolve and bind; identity kept or
// superseded per the shared anchor rule. The session continues with the returned
// candidate (the new one after supersession).
func handleAmendment(repo string, man *verification.Manifest, c *verification.Candidate, args, diag map[string]any, digest string, failures *int, res *agentResult) (string, bool, *verification.Decision, string) {
	reject := func(fb verification.Feedback) (string, bool, *verification.Decision, string) {
		*failures++
		res.classify(verification.FailInvalidSubmission, "amend_candidate", fb.Message+" "+fb.Expected, fb.Code)
		res.logCall(c.ID, "amend_candidate", diag, digest, "error", verification.FailInvalidSubmission, fb.Code, fb.Expected, fb.JSON())
		return fb.JSON(), false, nil, ""
	}
	if res.Amended {
		return reject(verification.Feedback{Code: verification.EAmendmentLimit, Field: "amend_candidate", Expected: "at most one accepted amendment per session; submit a verdict now", Repairable: false, Message: "amendment limit reached"})
	}
	if id := firstStrA(args, "candidate_id"); id != c.ID && id != c.Supersedes {
		return reject(verification.Feedback{Code: verification.EAmendmentCandidate, Field: "candidate_id", Received: id, Expected: c.ID, Repairable: true, Message: "an amendment may only move THIS candidate's citation"})
	}
	start, end := firstIntA(args, "start_line"), firstIntA(args, "end_line")
	if end == 0 {
		end = start
	}
	slot := c
	for i := range man.Candidates {
		if man.Candidates[i].ID == c.ID {
			slot = &man.Candidates[i] // the manifest entry, not the session's working copy
		}
	}
	next, am, fb := verification.ApplyAmendment(man, repo, slot, firstStrA(args, "path"), start, end, firstStrA(args, "reason"), "phase2b-model", 1)
	if fb != nil {
		man.Amendments = append(man.Amendments, am)
		return reject(*fb)
	}
	res.Amended, res.AmendIdentity = true, am.Identity
	res.logCall(c.ID, "amend_candidate", diag, digest, "ok", "", "", am.Identity, "")
	*c = *next
	out := map[string]any{"accepted": true, "candidate_id": c.ID, "location": c.Finding.Location, "identity": am.Identity}
	if c.Citation != nil && c.Citation.Binding != nil {
		out["facts"] = candidateFacts(*c)
	}
	b, _ := json.Marshal(out)
	return string(b), false, nil, ""
}

// diagnosticArgs keeps the argument subset worth recording per call (no source
// text is ever stored here; evidence quotes live in the decision record).
func diagnosticArgs(tool string, args map[string]any) map[string]any {
	if len(args) == 0 {
		return nil
	}
	out := map[string]any{}
	for k, v := range args {
		switch tool {
		case "submit_verification":
			if k == "evidence_ids" || k == "verdict" || k == "entry_point" || k == "unresolved_questions" {
				out[k] = v
			}
		default:
			out[k] = v
		}
	}
	return out
}

func captureEvidence(repo, path string, start, end int, evidence map[string]verification.Evidence) (verification.Evidence, error) {
	if path == "" || filepath.IsAbs(path) || strings.Contains(path, "..") {
		return verification.Evidence{}, fmt.Errorf("path must be repo-relative")
	}
	b, err := source.ReadFile(repo, path)
	if err != nil {
		return verification.Evidence{}, fmt.Errorf("cannot read %s", path)
	}
	lines := strings.Split(string(b), "\n")
	if start < 1 || end < start || end > len(lines) || end-start >= 2000 {
		return verification.Evidence{}, fmt.Errorf("invalid line range (1..%d, max 2000 lines)", len(lines))
	}
	quote := strings.Join(lines[start-1:end], "\n")
	ev := verification.Evidence{Path: path, StartLine: start, EndLine: end, Quote: quote}
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s:%d:%d:%s", path, start, end, quote)))
	ev.ID = "EV-" + fmt.Sprintf("%x", sum)[:24]
	evidence[ev.ID] = ev
	return ev, nil
}

func buildDecision(man *verification.Manifest, c verification.Candidate, args map[string]any, evidence map[string]verification.Evidence) (*verification.Decision, error) {
	verdict := firstStrA(args, "verdict")
	if verdict != "supported" && verdict != "rejected" && verdict != "unresolved" {
		return nil, fmt.Errorf("verdict must be supported, rejected, or unresolved")
	}
	if strings.TrimSpace(firstStrA(args, "rationale")) == "" {
		return nil, fmt.Errorf("rationale is required")
	}
	var evs []verification.Evidence
	for _, id := range toStrSlice(args["evidence_ids"]) {
		e, ok := evidence[id]
		if !ok {
			return nil, fmt.Errorf("evidence_ids must reference evidence captured this session: %s", id)
		}
		evs = append(evs, e)
	}
	return &verification.Decision{
		CandidateID: c.ID, Verdict: verdict, Rationale: firstStrA(args, "rationale"),
		EntryPoint: firstStrA(args, "entry_point"), AttackerControl: firstStrA(args, "attacker_control"),
		Preconditions: firstStrA(args, "preconditions"), DefensesReviewed: firstStrA(args, "defenses_reviewed"),
		SecurityImpact: firstStrA(args, "security_impact"), UnresolvedQuestions: toStrSlice(args["unresolved_questions"]),
		Evidence: evs, Reviewer: "phase2b-model", Revision: man.Revision,
	}, nil
}

func initialContext(repo, location string, evidence map[string]verification.Evidence) string {
	// Auto-capture a window around the cited line so the model starts grounded.
	i := strings.IndexByte(location, ':')
	if repo == "" || i < 0 {
		return "No resolvable primary citation; investigate with Read/Grep or submit unresolved."
	}
	file := location[:i]
	ln := 0
	for _, ch := range location[i+1:] {
		if ch < '0' || ch > '9' {
			break
		}
		ln = ln*10 + int(ch-'0')
	}
	if ln < 1 {
		return "No resolvable line; investigate or submit unresolved."
	}
	start, end := ln-15, ln+15
	if start < 1 {
		start = 1
	}
	ev, err := captureEvidence(repo, file, start, end, evidence)
	if err != nil {
		// clamp end to file length via a re-read
		if b, e := source.ReadFile(repo, file); e == nil {
			n := len(strings.Split(string(b), "\n"))
			if end > n {
				end = n
			}
			if ev, err = captureEvidence(repo, file, start, end, evidence); err != nil {
				return "Primary context unavailable: " + err.Error()
			}
		} else {
			return "Primary context unavailable."
		}
	}
	return fmt.Sprintf("[%s] %s:%d-%d\n%s", ev.ID, ev.Path, ev.StartLine, ev.EndLine, ev.Quote)
}

// verifySystem is the 2b system prompt: the methodology preamble, the session
// rules, and (feature 015, C-C5) the tested worked examples from
// skill/phases/phase2b_session.md when the skill provides them.
func verifySystem(base, sessionPrompt string) string {
	s := base + "\n\n## Phase 2b — adversarial verification\n" +
		"You are verifying ONE candidate finding. Investigate the cited handler and its defenses with Read/Grep. " +
		"Use capture_evidence to register the exact source lines you rely on (the harness copies them; do not paste source yourself). " +
		"Then call submit_verification with verdict supported/rejected/unresolved. Both supported and rejected decisions require entry_point, attacker_control, preconditions, defenses_reviewed, and security_impact explaining the conclusion. A 'supported' verdict requires captured evidence covering the cited location and a real sink at that location; if you cannot establish exploitability, submit 'unresolved' with your open questions. Never claim confirmation without evidence. " +
		"Every rejected tool call returns a structured error {code, field, received, expected, repairable, aids}: fix exactly that field; repeating an identical rejected submission ends the session. " +
		"If the cited lines are not the sink, call amend_candidate once with the correct path and lines (the harness re-resolves the handler); a different anchor creates a new candidate identity."
	if strings.TrimSpace(sessionPrompt) != "" {
		s += "\n\n" + sessionPrompt
	}
	return s
}

func verifyToolEnvelope() []client.Tool {
	str := map[string]any{"type": "string"}
	integer := map[string]any{"type": "integer"}
	boolean := map[string]any{"type": "boolean"}
	obj := func(props map[string]any, req ...string) map[string]any {
		return map[string]any{"type": "object", "properties": props, "required": req}
	}
	arr := map[string]any{"type": "array", "items": str}
	return []client.Tool{
		{Name: "Read", Description: "Read a file (line-numbered; offset/limit to page).", Parameters: obj(map[string]any{"file_path": str, "offset": integer, "limit": integer}, "file_path")},
		{Name: "Grep", Description: "Search the repository with a regex.", Parameters: obj(map[string]any{"pattern": str, "path": str, "glob": str, "ignore_case": boolean, "files_with_matches": boolean}, "pattern")},
		{Name: "capture_evidence", Description: "Read source lines and register immutable evidence; returns evidence_id + exact source.", Parameters: obj(map[string]any{"path": str, "start_line": integer, "end_line": integer}, "path", "start_line", "end_line")},
		{Name: "amend_candidate", Description: "Move THIS candidate's citation to the correct path and lines (once per session). The harness resolves and binds the new citation; the same sink keeps the identity, a different sink creates a new candidate.", Parameters: obj(map[string]any{"candidate_id": str, "path": str, "start_line": integer, "end_line": integer, "reason": str}, "candidate_id", "path", "start_line", "end_line", "reason")},
		{Name: "submit_verification", Description: "Submit the decision for this candidate. Do not write JSON files or paste source.", Parameters: obj(map[string]any{
			"verdict":   map[string]any{"type": "string", "enum": []string{"supported", "rejected", "unresolved"}},
			"rationale": str, "entry_point": str, "attacker_control": str, "preconditions": str,
			"defenses_reviewed": str, "security_impact": str, "evidence_ids": arr, "unresolved_questions": arr,
		}, "verdict", "rationale", "entry_point", "evidence_ids")},
	}
}

// classInfo is the last failure recorded for one class (operation/message/code).
type classInfo struct{ op, msg, code string }

// agentResult is the local accounting shape for a verification session (mapped to
// an AgentRecord via recordVerifyAgent below).
type agentResult struct {
	Turns              int
	StoppedReason      string
	Prompt, Completion int
	Failures           int // recoverable tool/validation failures counted toward the repair budget
	Err                error
	nudged             bool
	// Feature 014 (FR-018): per-operation failure diagnosis. ByClass counts EVERY
	// failure by class (including invalid tool arguments, which never counted toward
	// the repair budget and were previously invisible); LastOp / LastViolation name
	// the operation and the violated contract of the most recent failure.
	ByClass       map[string]int
	LastOp        string
	LastViolation string
	// Feature 015 (FR-026/027/029): per-class last failure, per-call records,
	// effective provenance, explicit unresolved, amendment, repeated-submission
	// tracking, failing submissions (diagnostics) and prompt/tool identity.
	perClass           map[string]classInfo
	Calls              []verification.CallRecord
	callSeq            int
	Provenance         client.Provenance
	Model              string
	ExplicitUnresolved bool
	Amended            bool
	AmendIdentity      string
	StopCode           string
	lastSubmitDigest   string
	repeatCount        int
	failing            []verification.FailingSubmission
	sourceRefs         []verification.SourceRef
	PromptHash         string
	ToolSchemaHash     string
	ContextMessages    []client.Message // explicit full diagnostics only; sanitized before persistence
}

// classify records one failure of the given class at the given operation.
func (r *agentResult) classify(class, op, msg, code string) {
	if r.ByClass == nil {
		r.ByClass = map[string]int{}
	}
	if r.perClass == nil {
		r.perClass = map[string]classInfo{}
	}
	r.ByClass[class]++
	r.LastOp = op
	r.LastViolation = clampStr(msg, 300)
	r.perClass[class] = classInfo{op: op, msg: clampStr(msg, 300), code: code}
}

// logCall appends one call record (feature 015, C-C10).
func (r *agentResult) logCall(candidateID, op string, args map[string]any, digest, outcome, class, code, msg, feedback string) {
	r.callSeq++
	r.Calls = append(r.Calls, verification.CallRecord{
		CandidateID: candidateID, SessionAttempt: 1, CallSeq: r.callSeq, TS: time.Now().UTC().Format(time.RFC3339Nano),
		Operation: op, Args: args, ArgsDigest: digest, Outcome: outcome, Class: class, Code: code,
		Message: clampStr(msg, 300), Feedback: clampStr(feedback, 2000), Model: r.Model,
	})
}

// recordVerifyAgent appends a verification session's engine-observed facts and
// accumulates run usage (turns count as calls).
func recordVerifyAgent(rec *RunRecord, phase, label, model, candidateID string, res agentResult) {
	rec.Agents = append(rec.Agents, AgentRecord{
		Label: label, Phase: phase, Model: model, Turns: res.Turns, StoppedReason: res.StoppedReason,
		PromptTokens: res.Prompt, CompletionTokens: res.Completion, CandidateID: candidateID,
	})
	pt, _ := rec.Usage["prompt_tokens"].(int)
	ct, _ := rec.Usage["completion_tokens"].(int)
	calls, _ := rec.Usage["calls"].(int)
	rec.Usage["prompt_tokens"] = pt + res.Prompt
	rec.Usage["completion_tokens"] = ct + res.Completion
	rec.Usage["calls"] = calls + res.Turns
}

func firstStrA(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if v, ok := m[k].(string); ok {
			return v
		}
	}
	return ""
}
func firstIntA(m map[string]any, keys ...string) int {
	for _, k := range keys {
		switch v := m[k].(type) {
		case float64:
			return int(v)
		case int:
			return v
		}
	}
	return 0
}
func firstBoolA(m map[string]any, keys ...string) bool {
	for _, k := range keys {
		if v, ok := m[k].(bool); ok {
			return v
		}
	}
	return false
}
func toStrSlice(v any) []string {
	arr, ok := v.([]any)
	if !ok {
		return nil
	}
	var out []string
	for _, x := range arr {
		if s, ok := x.(string); ok {
			out = append(out, s)
		}
	}
	return out
}
