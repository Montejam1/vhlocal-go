package engine

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"vhlocal/internal/client"
	"vhlocal/internal/redact"
)

// Feature 014 (FR-005/007/009): prompt records captured AT THE MODEL-CALL BOUNDARY.
//
// A promptRecorder decorates a client.Provider; every Chat — main turns, the
// agent's fresh-context repair, the hunt canary, the repartition call, verification
// and reproduction — passes through it, so records are never reconstructed from
// templates after the fact. One decorator instance is created per unit/agent with a
// fixed meta (race-free under bounded concurrency); all instances append to one
// mutex-guarded JSONL sink.

// PromptCaptureVersion is written to scan_meta.json when records were captured;
// its absence on an older scan reads "not recorded by this version".
const PromptCaptureVersion = 1

// PromptsFile is the append-only JSONL record file in the results directory.
const PromptsFile = "prompts.jsonl"

// promptClampBytes bounds persisted system/task content (contracts "Bounds").
const promptClampBytes = 8 * 1024

// PromptRecord is one model call's actual sent content plus attribution.
type PromptRecord struct {
	Seq           int      `json:"seq"`
	TS            string   `json:"ts"`
	ScanTag       string   `json:"scan_tag"`
	Phase         string   `json:"phase"`
	Label         string   `json:"label"`
	Role          string   `json:"role"`
	Model         string   `json:"model"`
	Kind          string   `json:"kind"` // main | repair | canary | repartition
	System        string   `json:"system"`
	Task          string   `json:"task"`
	MessagesCount int      `json:"messages_count"`
	ToolCalls     []string `json:"tool_calls,omitempty"`
	ResponseStop  string   `json:"response_stop,omitempty"`
	Truncated     bool     `json:"truncated,omitempty"`
	Redactions    []string `json:"redactions,omitempty"`
	Error         string   `json:"error,omitempty"`
	// Feature 015 (FR-027/029): provenance of the exact instruction and tool contract
	// sent on this call, plus the candidate a 2b call verifies.
	CandidateID    string `json:"candidate_id,omitempty"`
	PromptHash     string `json:"prompt_hash,omitempty"`
	ToolSchemaHash string `json:"tool_schema_hash,omitempty"`
}

// promptSink is the shared, thread-safe append-only JSONL writer.
type promptSink struct {
	mu  sync.Mutex
	f   *os.File
	seq int
	// hashes/toolHashes remember the first prompt/tool-schema hash seen per phase
	// (feature 015); copied to scan_meta.json at the end of the run.
	hashes     map[string]string
	toolHashes map[string]string
}

func newPromptSink(resultsDir string) (*promptSink, error) {
	f, err := os.OpenFile(filepath.Join(resultsDir, PromptsFile), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, err
	}
	return &promptSink{f: f, hashes: map[string]string{}, toolHashes: map[string]string{}}, nil
}

// record assigns the next seq and appends one whole line (never interleaved).
func (s *promptSink) record(r PromptRecord) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.seq++
	r.Seq = s.seq
	if r.PromptHash != "" {
		if _, ok := s.hashes[r.Phase]; !ok {
			s.hashes[r.Phase] = r.PromptHash
		}
	}
	if r.ToolSchemaHash != "" {
		if _, ok := s.toolHashes[r.Phase]; !ok {
			s.toolHashes[r.Phase] = r.ToolSchemaHash
		}
	}
	b, err := json.Marshal(r)
	if err != nil {
		return
	}
	_, _ = s.f.Write(append(b, '\n'))
}

func (s *promptSink) Close() {
	if s == nil || s.f == nil {
		return
	}
	_ = s.f.Close()
}

// promptMeta is the fixed attribution for one decorator instance.
type promptMeta struct {
	scanTag, phase, label, role, model, kind string
}

type promptRecorder struct {
	inner client.Provider
	sink  *promptSink
	meta  promptMeta
}

// recordPrompts wraps p so every call is recorded with meta. A nil sink or
// provider returns p unchanged (recording is never a reason to fail a scan).
func recordPrompts(p client.Provider, sink *promptSink, meta promptMeta) client.Provider {
	if p == nil || sink == nil {
		return p
	}
	if meta.kind == "" {
		meta.kind = "main"
	}
	return &promptRecorder{inner: p, sink: sink, meta: meta}
}

func (r *promptRecorder) Backend() client.Backend { return r.inner.Backend() }
func (r *promptRecorder) Endpoint() string        { return r.inner.Endpoint() }

func (r *promptRecorder) Chat(ctx context.Context, req client.ChatRequest) (*client.ChatResponse, error) {
	rec := PromptRecord{
		TS: time.Now().UTC().Format(time.RFC3339Nano), ScanTag: r.meta.scanTag, Phase: r.meta.phase,
		Label: r.meta.label, Role: r.meta.role, Model: firstNonEmpty(req.Model, r.meta.model),
		Kind: r.meta.kind, MessagesCount: len(req.Messages),
	}
	var sys, task string
	for _, m := range req.Messages {
		if m.Role == "system" && sys == "" {
			sys = m.Content
		}
		if m.Role == "user" {
			task = m.Content // last user turn = the task/instruction actually sent
		}
	}
	// The agent's fresh-context repair is a 2-message call whose system prompt
	// names the invalid tool call; record it as its own kind (FR-005).
	if rec.Kind == "main" && len(req.Messages) == 2 && strings.Contains(sys, "invalid tool call") {
		rec.Kind = "repair"
	}
	// Feature 015: exact identity of what was sent — hash of the system text and of
	// the tool envelope; 2b calls name their candidate, and a call whose last user
	// turn is in-session validation feedback is a repair.
	if sys != "" {
		rec.PromptHash = sha256Hex([]byte(sys))
	}
	if len(req.Tools) > 0 {
		if tb, err := json.Marshal(req.Tools); err == nil {
			rec.ToolSchemaHash = sha256Hex(tb)
		}
	}
	if r.meta.phase == "2b" {
		for _, m := range req.Messages {
			if m.Role == "user" {
				if mm := reVerifyCandidate.FindStringSubmatch(m.Content); mm != nil {
					rec.CandidateID = mm[1]
					break
				}
			}
		}
		if rec.CandidateID != "" && rec.Label == "verify" {
			rec.Label = "verify:" + rec.CandidateID
		}
		if rec.Kind == "main" && len(req.Messages) > 2 {
			for _, mk := range verifyRepairMarkers {
				if strings.Contains(task, mk) {
					rec.Kind = "repair"
					break
				}
			}
		}
	}
	var reds []string
	rec.System, reds = sanitizePrompt(sys, reds)
	rec.Task, reds = sanitizePrompt(task, reds)
	if len(rec.System) > promptClampBytes {
		rec.System, rec.Truncated = rec.System[:promptClampBytes], true
	}
	if len(rec.Task) > promptClampBytes {
		rec.Task, rec.Truncated = rec.Task[:promptClampBytes], true
	}
	rec.Redactions = dedupStrings(reds)

	resp, err := r.inner.Chat(ctx, req)
	if err != nil {
		rec.Error = clampStr(err.Error(), 512)
	} else if resp != nil {
		for _, tc := range resp.Message.ToolCalls {
			rec.ToolCalls = append(rec.ToolCalls, tc.Name)
		}
		if len(resp.Message.ToolCalls) == 0 {
			rec.ResponseStop = "stop"
		} else {
			rec.ResponseStop = "tool_calls"
		}
	}
	r.sink.record(rec)
	return resp, err
}

// reCredURL strips userinfo (user:password@) from URLs embedded in content.
var reCredURL = regexp.MustCompile(`://[^/\s:@]+:[^/\s@]+@`)

// sanitizePrompt applies the existing redaction contract plus credentialed-URL
// stripping, returning the cleaned text and the labels of what was masked.
func sanitizePrompt(s string, reds []string) (string, []string) {
	if s == "" {
		return s, reds
	}
	if reCredURL.MatchString(s) {
		s = reCredURL.ReplaceAllString(s, "://[redacted]@")
		reds = append(reds, "url credentials")
	}
	masked, n := redact.Mask(s)
	if n > 0 {
		reds = append(reds, "secrets/PII")
	}
	return masked, reds
}

func clampStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…[truncated]"
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// roleFor maps a phase key to the provider role used for attribution.
func roleFor(key string) string {
	switch key {
	case "1", "1t":
		return "recon"
	case "2b":
		return "verify"
	case "3", "3d", "4":
		return "reproduce"
	}
	return "hunt"
}

// logTag returns the tag used for this run's scan log lines (FR-006).
func logTag(spec ScanSpec) string {
	if spec.LogTag != "" {
		return spec.LogTag
	}
	return spec.ScanTag
}

// Hashes returns the first prompt-text and tool-schema hash recorded per phase
// (feature 015, FR-027/029) — the exact instruction/contract identity a run used.
func (s *promptSink) Hashes() (prompts, tools map[string]string) {
	prompts, tools = map[string]string{}, map[string]string{}
	if s == nil {
		return prompts, tools
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, v := range s.hashes {
		prompts[k] = v
	}
	for k, v := range s.toolHashes {
		tools[k] = v
	}
	return prompts, tools
}

// sha256Hex is the record-level content hash used for prompt/tool-schema identity.
func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// reVerifyCandidate extracts the candidate a 2b task verifies (the task text is
// the sent content, so this is not reconstruction).
var reVerifyCandidate = regexp.MustCompile(`(?m)^Candidate: (CAND-[0-9a-f]+)`)

// verifyRepairMarkers are the phase-2b in-session repair feedbacks; a call whose
// last user turn carries one is a repair, not a main call (feature 015).
var verifyRepairMarkers = []string{
	"could not be parsed as a tool call",
	"You must call submit_verification",
	"Contract violated",
	"Correct the submission",
	"E_",
}
