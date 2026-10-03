package parity

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"vhlocal/internal/client"
	"vhlocal/tests/parity/transcript"
)

// transcriptProvider is the Go-only replay provider (feature 006, US2): it extracts
// the semantic situation (phase, partition, class, candidate) from each grounded
// request and returns the transcript's scripted response. An unmatched HUNT/RECON
// write still returns a valid (empty) deliverable; an unmatched VERIFY candidate
// errors loudly so the fixture cannot silently under-exercise a phase (C-D5).
type transcriptProvider struct {
	tr *transcript.Transcript
}

func (transcriptProvider) Backend() client.Backend { return "fake" }
func (transcriptProvider) Endpoint() string        { return "fake://transcript" }

var (
	reTPPath = regexp.MustCompile(`(\S+\.md)`)
	reTPLoc  = regexp.MustCompile(`[\w./+\-]+\.(?:py|go|js|ts|java|kt|cs|rb|php|rs|c|cc|cpp):\d+`)
	reTPEV   = regexp.MustCompile(`EV-[0-9a-f]{24}`)
)

func (tp transcriptProvider) Chat(_ context.Context, req client.ChatRequest) (*client.ChatResponse, error) {
	if hasTool(req, "submit_verification") {
		return tp.verify(req)
	}
	// Recon / hunt agent loop: after a Write tool result, the agent is done.
	if n := len(req.Messages); n > 0 && req.Messages[n-1].Role == "tool" {
		return textResp("done"), nil
	}
	task := lastUser(req)
	path := lastMatch(reTPPath, task)
	content := tp.reconOrHunt(path)
	return writeResp(path, content), nil
}

// reconOrHunt returns the content for a recon (phase1_output.md) or hunt
// (results/<slug>_<class>.md) write target.
func (tp transcriptProvider) reconOrHunt(path string) string {
	switch {
	case strings.Contains(path, "phase1_output.md"):
		if tp.tr.PartitionTable != "" {
			return tp.tr.PartitionTable
		}
		return "# output\n"
	case strings.Contains(path, "/results/"):
		part, class := unitFromPath(path)
		for _, r := range tp.tr.Hunt {
			if r.Partition == part && r.Class == class {
				return renderFindings(r.Findings)
			}
		}
		return "# output\n" // a valid, finding-less deliverable
	default:
		return "# output\n"
	}
}

// verify drives a per-candidate session: capture the complete containing function,
// then submit the scripted verdict. An unresolved verdict submits directly.
func (tp transcriptProvider) verify(req client.ChatRequest) (*client.ChatResponse, error) {
	joined := allContent(req)
	loc := ""
	for _, m := range reTPLoc.FindAllString(joined, -1) {
		if tp.tr.FindVerify(m) != nil {
			loc = m
			break
		}
	}
	rule := tp.tr.FindVerify(loc)
	if rule == nil {
		return nil, fmt.Errorf("transcript has no verify rule for candidate at %q — the fixture under-exercises verification", firstLoc(joined))
	}
	file := loc[:strings.IndexByte(loc, ':')]

	if rule.Verdict == "unresolved" {
		return submitResp(rule, nil), nil
	}
	// Has our capture_evidence already run this session? Its EV id is in a tool msg.
	captured := ""
	for _, m := range req.Messages {
		if m.Role == "tool" && strings.EqualFold(m.Name, "capture_evidence") {
			captured = reTPEV.FindString(m.Content)
		}
	}
	if captured == "" {
		return captureResp(file, rule.FuncStart, rule.FuncEnd), nil
	}
	return submitResp(rule, []string{captured}), nil
}

func renderFindings(fs []transcript.HuntFinding) string {
	var b strings.Builder
	b.WriteString("## Findings\n\n")
	for _, f := range fs {
		sev := f.Severity
		if sev == "" {
			sev = "High"
		}
		b.WriteString(fmt.Sprintf("### [%s] %s\n\n- **CWE**: %s\n- **Severity**: %s\n- **Location**: %s\n- **Entry point**: %s\n- **Data flow**: %s\n- **Fix**: parameterize\n\n",
			f.ID, f.Title, f.CWE, sev, f.Location, f.EntryPoint, f.DataFlow))
	}
	return b.String()
}

// --- request/response helpers ------------------------------------------------

func hasTool(req client.ChatRequest, name string) bool {
	for _, t := range req.Tools {
		if strings.EqualFold(t.Name, name) {
			return true
		}
	}
	return false
}

func lastUser(req client.ChatRequest) string {
	s := ""
	for _, m := range req.Messages {
		if m.Role == "user" {
			s = m.Content
		}
	}
	return s
}

func allContent(req client.ChatRequest) string {
	var b strings.Builder
	for _, m := range req.Messages {
		b.WriteString(m.Content)
		b.WriteByte('\n')
	}
	return b.String()
}

func lastMatch(re *regexp.Regexp, s string) string {
	all := re.FindAllString(s, -1)
	if len(all) == 0 {
		return ""
	}
	return all[len(all)-1]
}

func firstLoc(s string) string {
	if m := reTPLoc.FindString(s); m != "" {
		return m
	}
	return "(none found)"
}

// unitFromPath extracts (partition, class) from results/<slug>_<class>.md.
func unitFromPath(path string) (string, string) {
	base := path
	if i := strings.LastIndexByte(base, '/'); i >= 0 {
		base = base[i+1:]
	}
	base = strings.TrimSuffix(base, ".md")
	if i := strings.LastIndexByte(base, '_'); i > 0 {
		return base[:i], base[i+1:]
	}
	return base, ""
}

func textResp(s string) *client.ChatResponse {
	return &client.ChatResponse{Model: "transcript", Message: client.Message{Role: "assistant", Content: s},
		Usage: client.Usage{PromptTokens: 4, CompletionTokens: 2}}
}

func writeResp(path, content string) *client.ChatResponse {
	args, _ := json.Marshal(map[string]string{"path": path, "content": content})
	return &client.ChatResponse{Model: "transcript",
		Message: client.Message{Role: "assistant", ToolCalls: []client.ToolCall{{ID: "w1", Name: "Write", Arguments: string(args)}}},
		Usage:   client.Usage{PromptTokens: 8, CompletionTokens: 4}}
}

func captureResp(file string, start, end int) *client.ChatResponse {
	args, _ := json.Marshal(map[string]any{"path": file, "start_line": start, "end_line": end})
	return &client.ChatResponse{Model: "transcript",
		Message: client.Message{Role: "assistant", ToolCalls: []client.ToolCall{{ID: "c1", Name: "capture_evidence", Arguments: string(args)}}},
		Usage:   client.Usage{PromptTokens: 8, CompletionTokens: 4}}
}

func submitResp(rule *transcript.VerifyRule, evIDs []string) *client.ChatResponse {
	if evIDs == nil {
		evIDs = []string{}
	}
	rationale := rule.Rationale
	if rationale == "" {
		rationale = "scripted " + rule.Verdict + " decision"
	}
	args, _ := json.Marshal(map[string]any{
		"verdict": rule.Verdict, "rationale": rationale, "entry_point": rule.EntryPoint,
		"attacker_control": "request parameter", "preconditions": "none",
		"defenses_reviewed": "none observed", "security_impact": "impact assessed",
		"evidence_ids": evIDs, "unresolved_questions": []string{},
	})
	return &client.ChatResponse{Model: "transcript",
		Message: client.Message{Role: "assistant", ToolCalls: []client.ToolCall{{ID: "s1", Name: "submit_verification", Arguments: string(args)}}},
		Usage:   client.Usage{PromptTokens: 8, CompletionTokens: 4}}
}
