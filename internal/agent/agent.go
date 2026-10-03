// Package agent runs one isolated agent: a bounded tool loop over a single
// Provider with the sandboxed file tools. It never has a shell/exec tool
// (constitution Principle III).
//
// Resilience against a degrading local model (research R14; feature 003):
//   - A recoverable tool problem (missing/renamed arg, unknown-but-aliasable
//     tool, tool error) returns a corrective tool result and the agent CONTINUES;
//     it never counts toward giving up.
//   - An unrecoverable problem (arguments not parseable as JSON) triggers a
//     bounded fresh-context repair on the SAME provider/endpoint; a success
//     continues the agent. The agent ends (`tool_repair`) only after the repair
//     budget of consecutive failures — a single malformed turn never kills it.
//   - Context is pruned each turn so long sessions stay within the window.
//   - A fan-out agent nearing its turn limit is nudged to write its deliverable.
package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"vhlocal/internal/client"
	"vhlocal/internal/tools"
)

// Stop reasons recorded per agent (surface in scan_meta agents[].stopped_reason).
const (
	StopComplete   = "complete"    // model ended with no tool call
	StopMaxTurns   = "max_turns"   // turn budget exhausted
	StopToolRepair = "tool_repair" // repair budget exhausted on unrecoverable tool calls
	// StopEndpointFailure is engine-set (not emitted by Run): an agent that failed
	// unrecoverably at the endpoint, degraded per-phase rather than aborting the run
	// (feature 004, FR-006). Kept here so the stopped_reason vocabulary is one place.
	StopEndpointFailure = "endpoint_failure"
)

// repairBudget is the number of consecutive unrecoverable-then-failed-repair
// tool calls tolerated before the agent ends gracefully. A successful repair
// resets the counter, so ordinary model noise never ends a productive agent.
const repairBudget = 2

// pruneSafetyFraction and bytesPerToken bound the working context. The prompt is
// kept under ~this fraction of the model's window (byte-estimated, no tokenizer).
const (
	pruneSafetyFraction = 0.6
	bytesPerToken       = 3
)

// dispatchKind classifies a tool call's outcome.
type dispatchKind int

const (
	kindOK            dispatchKind = iota // tool ran
	kindRecoverable                       // corrective tool result; agent continues, no give-up
	kindUnrecoverable                     // arguments unparseable as JSON; triggers repair
)

type dispatchResult struct {
	Kind    dispatchKind
	Content string // returned to the model as the tool result
	// Read is set for a successful Read tool call: the span actually read
	// (feature 014, FR-012/014 — factual evidence for review dispositions).
	Read *ReadSpan
}

// Result summarizes one agent run.
type Result struct {
	Turns           int
	StoppedReason   string
	FinalContent    string
	Usage           client.Usage
	Provenance      client.Provenance
	RepairAttempts  int  // fresh-context repairs attempted
	RepairSuccesses int  // repairs that yielded a well-formed tool call
	Produced        bool // a Write to DeliverablePath succeeded (when set)
	// Reads are the source spans the agent ACTUALLY read via successful Read tool
	// calls (feature 014, FR-012/014). They are factual tool evidence used to derive
	// evidence-backed review dispositions; Grep results and path mentions are not
	// span reads and are deliberately not recorded here.
	Reads []ReadSpan
}

// ReadSpan is one successful Read of a repo-relative file: lines [Start, End].
// End == 0 means "to end of file" (a whole-file read genuinely covers every span).
type ReadSpan struct {
	File  string
	Start int
	End   int
}

// Config parameters for one run.
type Config struct {
	Model           string
	NumCtx          int
	MaxTurns        int
	Temperature     *float64
	MaxOutputTokens int
	ReasoningEffort string
	// DeliverablePath, when set, enables the write-before-max_turns nudge: if the
	// agent nears its turn limit without a successful Write, it is prompted to
	// write to this path (FR-005).
	DeliverablePath string
}

// toolEnvelope is the fixed tool set advertised to the model (no shell/exec).
// Schemas mirror tools.py: Read pages via offset/limit and returns line-numbered
// content; Grep supports path/glob/ignore_case/files_with_matches (FR-004); Glob
// takes an optional path (FR-005).
func toolEnvelope() []client.Tool {
	obj := func(props map[string]any, required ...string) map[string]any {
		return map[string]any{"type": "object", "properties": props, "required": required}
	}
	str := map[string]any{"type": "string"}
	integer := map[string]any{"type": "integer"}
	boolean := map[string]any{"type": "boolean"}
	return []client.Tool{
		{Name: "Read", Description: "Read a file from the target repository. Returns line-numbered content. Use offset/limit to page through large files.",
			Parameters: obj(map[string]any{"file_path": str, "offset": integer, "limit": integer}, "file_path")},
		{Name: "Grep", Description: "Search the repository with a regular expression. Returns file:line:content matches — your primary instrument for tracing data flow to a sink.",
			Parameters: obj(map[string]any{"pattern": str, "path": str, "glob": str, "ignore_case": boolean, "files_with_matches": boolean}, "pattern")},
		{Name: "Glob", Description: "Find files by name pattern, e.g. '**/*.py' or 'routes*.js'.",
			Parameters: obj(map[string]any{"pattern": str, "path": str}, "pattern")},
		{Name: "Write", Description: "Write your output file. Only paths inside the results directory are permitted. Use the exact filename your instructions specify.",
			Parameters: obj(map[string]any{"file_path": str, "content": str}, "file_path", "content")},
	}
}

// ToolNames returns the advertised tool names (for scan_meta tool_envelope).
func ToolNames() []string { return []string{"Read", "Grep", "Glob", "Write"} }

// Run executes the loop: system + user prompt, then model↔tools until the model
// stops calling tools, MaxTurns is hit, or the repair budget is exhausted.
func Run(ctx context.Context, p client.Provider, sb *tools.Sandbox, cfg Config, system, task string) (Result, error) {
	msgs := []client.Message{
		{Role: "system", Content: system},
		{Role: "user", Content: task},
	}
	var res Result
	repairFailures := 0 // consecutive unrecoverable calls whose repair also failed
	nudged := false
	completionNudged := false // one-shot completion nudge (FR-010; C-N2)
	nudgeAt := cfg.MaxTurns * 8 / 10

	for turn := 0; turn < cfg.MaxTurns; turn++ {
		if err := ctx.Err(); err != nil {
			res.StoppedReason = "cancelled"
			return res, err
		}
		res.Turns = turn + 1

		// Write-before-max_turns nudge (FR-005): once, near the limit, if the
		// agent was told to write a deliverable but hasn't yet.
		if !nudged && cfg.DeliverablePath != "" && !res.Produced && turn >= nudgeAt {
			msgs = append(msgs, client.Message{Role: "user", Content: "You are nearing your turn limit. Write your findings now to this exact path using the Write tool: " + cfg.DeliverablePath})
			nudged = true
		}

		// Context pruning (FR-004): keep the prompt within a safe budget.
		msgs = pruneContext(msgs, cfg.NumCtx)

		resp, err := p.Chat(ctx, client.ChatRequest{
			Model: cfg.Model, Messages: msgs, Tools: toolEnvelope(),
			NumCtx: cfg.NumCtx, Temperature: cfg.Temperature,
			MaxOutputTokens: cfg.MaxOutputTokens, ReasoningEffort: cfg.ReasoningEffort,
		})
		if err != nil {
			// A provider tool-call-parse rejection (KindToolParse) is recoverable: the
			// model mixed prose with the tool-call JSON and the provider rejected the
			// whole blob, but the intended action is carried in the error. Route it
			// into the SAME bounded fresh-context repair used for a client-side
			// unparseable call (FR-002/003) — never a naive replay of the identical
			// request. A generic transport failure stays explicit (Principle V) and
			// propagates unchanged.
			var te *client.TransportError
			if errors.As(err, &te) && te.Kind == client.KindToolParse {
				repaired, out, ok := repairFromRaw(ctx, p, sb, cfg, te.Raw, &res)
				if ok {
					repairFailures = 0
					if isSuccessfulWrite(repaired, out, sb, cfg) {
						res.Produced = true
					}
					// Seed the transcript with the recovered call + its result so the
					// agent continues from the intended action (no identical replay).
					msgs = append(msgs,
						client.Message{Role: "assistant", ToolCalls: []client.ToolCall{repaired}},
						client.Message{Role: "tool", Name: repaired.Name, ToolCallID: repaired.ID, Content: out})
					continue
				}
				repairFailures++
				if repairFailures >= repairBudget {
					res.StoppedReason = StopToolRepair
					return res, nil // graceful degrade; the engine degrades this phase
				}
				// Not budget-exhausted: steer the model off prose+JSON before the next
				// turn. The added instruction changes the context, so this is not an
				// identical replay of the failing request.
				msgs = append(msgs, client.Message{Role: "user", Content: "Your previous message could not be parsed as a tool call. Do not mix prose with the tool call — emit exactly one valid tool call with JSON arguments."})
				continue
			}
			// Transport failure is explicit (Principle V): return it.
			return res, err
		}
		res.Usage.PromptTokens += resp.Usage.PromptTokens
		res.Usage.CompletionTokens += resp.Usage.CompletionTokens
		res.Provenance = resp.Provenance
		res.FinalContent = resp.Message.Content
		msgs = append(msgs, resp.Message)

		if len(resp.Message.ToolCalls) == 0 {
			// Deliverable-aware completion (FR-010/011; C-N1/N2): if the model stops
			// calling tools before writing its declared deliverable, nudge it once
			// more to write it before the phase is finalized. One-shot (completionNudged)
			// so it cannot loop; the phase still counts produced only if the file lands.
			if cfg.DeliverablePath != "" && !res.Produced && !completionNudged {
				completionNudged = true
				msgs = append(msgs, client.Message{Role: "user", Content: "Before finishing, write your deliverable now to this exact path using the Write tool: " + cfg.DeliverablePath})
				continue
			}
			res.StoppedReason = StopComplete
			return res, nil
		}

		for _, tc := range resp.Message.ToolCalls {
			dr := dispatch(sb, tc)
			if dr.Read != nil {
				res.Reads = append(res.Reads, *dr.Read) // feature 014: span actually read
			}
			if dr.Kind == kindUnrecoverable {
				// Bounded fresh-context repair on the SAME endpoint (C-A6).
				repaired, out, ok := repairToolCall(ctx, p, sb, cfg, tc, &res)
				if ok {
					repairFailures = 0
					if isSuccessfulWrite(repaired, out, sb, cfg) {
						res.Produced = true
					}
					msgs = append(msgs, client.Message{Role: "tool", Name: repaired.Name, ToolCallID: tc.ID, Content: out})
					continue
				}
				repairFailures++
				msgs = append(msgs, client.Message{Role: "tool", Name: tc.Name, ToolCallID: tc.ID, Content: out})
				if repairFailures >= repairBudget {
					res.StoppedReason = StopToolRepair
					return res, nil // graceful end, not a crash
				}
				continue
			}
			// ok or recoverable: continue; recoverable never counts toward give-up.
			if dr.Kind == kindOK {
				repairFailures = 0
				if isSuccessfulWrite(tc, dr.Content, sb, cfg) {
					res.Produced = true
				}
			}
			msgs = append(msgs, client.Message{Role: "tool", Name: tc.Name, ToolCallID: tc.ID, Content: dr.Content})
		}
	}
	res.StoppedReason = StopMaxTurns
	return res, nil
}

// isSuccessfulWrite reports whether a dispatched call actually produced the
// agent's DECLARED deliverable (used to set Result.Produced and gate the nudge).
//
// FR-C4: a write to an unrelated path or an empty file does NOT count as produced
// and MUST NOT suppress the deliverable nudge. "Produced" is true only when a Write
// was called AND cfg.DeliverablePath now exists and is non-empty — not merely
// because some Write returned "wrote ...".
func isSuccessfulWrite(tc client.ToolCall, out string, sb *tools.Sandbox, cfg Config) bool {
	if cfg.DeliverablePath == "" || canonicalTool(tc.Name) != "Write" {
		return false
	}
	return deliverableProduced(cfg.DeliverablePath)
}

// deliverableProduced reports whether the deliverable at path exists and is
// non-empty (a directory deliverable is produced if it holds any non-empty file).
func deliverableProduced(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	if info.IsDir() {
		entries, _ := os.ReadDir(path)
		for _, e := range entries {
			if fi, ferr := e.Info(); ferr == nil && !e.IsDir() && fi.Size() > 0 {
				return true
			}
		}
		return false
	}
	return info.Size() > 0
}

// repairToolCall recovers a CLIENT-SIDE unparseable tool call (the harness
// received a tool call whose arguments are not valid JSON) by re-asking the model
// in a MINIMAL fresh context (schema + parser error + the model's own malformed
// output + the writable-root grounding hint) on the SAME provider.
func repairToolCall(ctx context.Context, p client.Provider, sb *tools.Sandbox, cfg Config, bad client.ToolCall, res *Result) (client.ToolCall, string, bool) {
	schema, _ := json.Marshal(toolEnvelope())
	sys := "You emitted an invalid tool call. Re-emit exactly ONE valid tool call to accomplish the intended action. Tools (JSON schema): " + string(schema) +
		"\nThe only writable directory is: " + sb.WriteRoot() + "\nReturn a tool call with valid JSON arguments; do not explain."
	user := fmt.Sprintf("Intended tool: %q. Its arguments were not valid JSON and could not be parsed. Raw arguments were:\n%s", bad.Name, bad.Arguments)
	return repairChat(ctx, p, sb, cfg, sys, user, res)
}

// repairFromRaw recovers a PROVIDER-SIDE tool-call-parse failure (feature 004,
// FR-002): the provider rejected the model's message as unparseable and returned
// the model's raw intended output. Re-ask in a minimal fresh context seeded from
// that raw output, on the SAME provider/endpoint (Principle V; no naive replay, no
// provider switch). Shares the agent's repair budget/accounting via repairChat.
func repairFromRaw(ctx context.Context, p client.Provider, sb *tools.Sandbox, cfg Config, raw string, res *Result) (client.ToolCall, string, bool) {
	schema, _ := json.Marshal(toolEnvelope())
	sys := "Your previous tool call was rejected by the provider as unparseable — you mixed prose with the tool-call JSON. Re-emit exactly ONE valid tool call to accomplish the intended action, with valid JSON arguments and NO surrounding prose. Tools (JSON schema): " + string(schema) +
		"\nThe only writable directory is: " + sb.WriteRoot() + "\nReturn a tool call with valid JSON arguments; do not explain."
	user := "Your raw output that could not be parsed was:\n" + raw
	return repairChat(ctx, p, sb, cfg, sys, user, res)
}

// repairChat performs one bounded fresh-context repair on the SAME provider: a
// minimal (system, user) prompt advertising ONLY the sandbox tool envelope (no
// shell/exec — Principle III). Shared by both repair entry points; it counts the
// attempt, and on a well-formed, dispatchable recovered call counts the success.
// Returns the repaired call, its dispatched result, and whether repair succeeded.
func repairChat(ctx context.Context, p client.Provider, sb *tools.Sandbox, cfg Config, sys, user string, res *Result) (client.ToolCall, string, bool) {
	res.RepairAttempts++
	resp, err := p.Chat(ctx, client.ChatRequest{
		Model: cfg.Model,
		Messages: []client.Message{
			{Role: "system", Content: sys},
			{Role: "user", Content: user},
		},
		Tools:           toolEnvelope(),
		NumCtx:          cfg.NumCtx,
		Temperature:     cfg.Temperature,
		MaxOutputTokens: cfg.MaxOutputTokens,
		ReasoningEffort: cfg.ReasoningEffort,
	})
	if err != nil || len(resp.Message.ToolCalls) == 0 {
		return client.ToolCall{}, "ERROR: tool call could not be parsed and repair failed; skipping.", false
	}
	res.Usage.PromptTokens += resp.Usage.PromptTokens
	res.Usage.CompletionTokens += resp.Usage.CompletionTokens
	fixed := resp.Message.ToolCalls[0]
	dr := dispatch(sb, fixed)
	if dr.Read != nil {
		res.Reads = append(res.Reads, *dr.Read) // feature 014: repaired Read also counts
	}
	if dr.Kind == kindUnrecoverable {
		return client.ToolCall{}, dr.Content, false
	}
	res.RepairSuccesses++
	return fixed, dr.Content, true
}

// pruneContext keeps the message list within a byte budget derived from NumCtx by
// eliding the content of the oldest tool-result messages first. The system prompt
// (index 0), the original task (index 1), and the most recent messages are never
// pruned.
func pruneContext(msgs []client.Message, numCtx int) []client.Message {
	if numCtx <= 0 {
		return msgs
	}
	budget := int(float64(numCtx) * bytesPerToken * pruneSafetyFraction)
	if estimateSize(msgs) <= budget {
		return msgs
	}
	const keepRecent = 6
	// Elide the content of the oldest messages first — tool results and assistant
	// prose alike — so the prompt stays bounded regardless of where the bloat is.
	// The system prompt (0), the original task (1), and the most recent messages
	// are never pruned; assistant tool_calls are preserved for message validity.
	for _, role := range []string{"tool", "assistant"} {
		for i := 2; i < len(msgs)-keepRecent; i++ {
			if msgs[i].Role == role && msgs[i].Content != "[pruned]" && len(msgs[i].Content) > 0 {
				msgs[i].Content = "[pruned]"
				if estimateSize(msgs) <= budget {
					return msgs
				}
			}
		}
	}
	return msgs
}

func estimateSize(msgs []client.Message) int {
	n := 0
	for _, m := range msgs {
		n += len(m.Content)
		for _, tc := range m.ToolCalls {
			n += len(tc.Arguments) + len(tc.Name)
		}
	}
	return n
}

// dispatch normalizes a tool name (case-insensitive + aliases), parses arguments,
// runs the tool, and returns a tri-state result: ok, recoverable (corrective
// message, agent continues), or unrecoverable (unparseable JSON → repair).
func dispatch(sb *tools.Sandbox, tc client.ToolCall) dispatchResult {
	name := canonicalTool(tc.Name)
	args, ok := parseArgs(tc.Arguments)
	if !ok {
		return dispatchResult{Kind: kindUnrecoverable, Content: "ERROR: could not parse tool arguments as JSON."}
	}
	switch name {
	case "Read":
		path := firstStr(args, "path", "file_path", "file", "filename", "filepath")
		if path == "" {
			return dispatchResult{Kind: kindRecoverable, Content: "ERROR: Read requires a 'file_path'. Retry with {\"file_path\": \"...\"}."}
		}
		offset, limit := firstInt(args, "offset"), firstInt(args, "limit")
		s, err := sb.ReadPaged(path, offset, limit)
		if err != nil {
			return dispatchResult{Kind: kindRecoverable, Content: "ERROR: " + err.Error()}
		}
		// Feature 014: record the span actually read (1-based; End 0 = to EOF).
		start := offset
		if start < 1 {
			start = 1
		}
		end := 0
		if limit > 0 {
			end = start + limit - 1
		}
		return dispatchResult{Kind: kindOK, Content: s, Read: &ReadSpan{File: path, Start: start, End: end}}
	case "Grep":
		pat := firstStr(args, "pattern", "query", "q", "regex", "search")
		if pat == "" {
			return dispatchResult{Kind: kindRecoverable, Content: "ERROR: Grep requires a 'pattern'. Retry with {\"pattern\": \"...\"}."}
		}
		out, err := sb.Grep(tools.GrepOpts{
			Pattern:          pat,
			Path:             firstStr(args, "path", "dir", "directory"),
			Glob:             firstStr(args, "glob", "include"),
			IgnoreCase:       firstBool(args, "ignore_case", "i"),
			FilesWithMatches: firstBool(args, "files_with_matches", "files_only", "l"),
		})
		if err != nil {
			return dispatchResult{Kind: kindRecoverable, Content: "ERROR: " + err.Error()}
		}
		return dispatchResult{Kind: kindOK, Content: out}
	case "Glob":
		pat := firstStr(args, "pattern", "glob", "q", "query")
		if pat == "" {
			return dispatchResult{Kind: kindRecoverable, Content: "ERROR: Glob requires a 'pattern'. Retry with {\"pattern\": \"...\"}."}
		}
		files, err := sb.Glob(pat)
		if err != nil {
			return dispatchResult{Kind: kindRecoverable, Content: "ERROR: " + err.Error()}
		}
		if len(files) == 0 {
			return dispatchResult{Kind: kindOK, Content: "No files matched " + pat}
		}
		header := fmt.Sprintf("%d match(es):\n", len(files))
		return dispatchResult{Kind: kindOK, Content: header + strings.Join(files, "\n")}
	case "Write":
		path := firstStr(args, "path", "file_path", "file", "filename", "filepath")
		content := firstStr(args, "content", "text", "data", "body")
		if path == "" {
			return dispatchResult{Kind: kindRecoverable, Content: "ERROR: Write requires a 'path'. Retry with {\"path\": \"...\", \"content\": \"...\"}."}
		}
		if err := sb.Write(path, content); err != nil {
			return dispatchResult{Kind: kindRecoverable, Content: "ERROR: " + err.Error()}
		}
		return dispatchResult{Kind: kindOK, Content: "wrote " + path}
	default:
		return dispatchResult{Kind: kindRecoverable, Content: "ERROR: unknown tool " + tc.Name + ". Available: Read, Grep, Glob, Write."}
	}
}

// canonicalTool maps case-insensitive names and common model aliases to the
// canonical tool name (the model calls glob/read_file etc.).
func canonicalTool(name string) string {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "read", "read_file", "readfile", "cat", "open", "view":
		return "Read"
	case "grep", "search", "ripgrep", "rg", "search_files", "grep_search":
		return "Grep"
	case "glob", "list", "find", "ls", "list_files", "glob_files":
		return "Glob"
	case "write", "write_file", "writefile", "create_file", "save":
		return "Write"
	default:
		return name
	}
}

func parseArgs(s string) (map[string]any, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return map[string]any{}, true
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		return nil, false
	}
	return m, true
}

func firstStr(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if v, ok := m[k]; ok {
			if s, ok := v.(string); ok {
				return s
			}
		}
	}
	return ""
}

// firstInt reads an integer argument (JSON numbers arrive as float64; a numeric
// string is also accepted). Returns 0 when absent/invalid.
func firstInt(m map[string]any, keys ...string) int {
	for _, k := range keys {
		switch v := m[k].(type) {
		case float64:
			return int(v)
		case int:
			return v
		case string:
			n := 0
			for _, c := range strings.TrimSpace(v) {
				if c < '0' || c > '9' {
					return 0
				}
				n = n*10 + int(c-'0')
			}
			return n
		}
	}
	return 0
}

// firstBool reads a boolean argument (accepts a real bool or "true"/"1").
func firstBool(m map[string]any, keys ...string) bool {
	for _, k := range keys {
		switch v := m[k].(type) {
		case bool:
			return v
		case string:
			return v == "true" || v == "1" || v == "yes"
		}
	}
	return false
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
