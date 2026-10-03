package engine

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"vhlocal/internal/redact"
	"vhlocal/internal/verification"
)

// Feature 015 (FR-029, C-C11): diagnostic capture for verification sessions with
// failing submissions. `diagnostics/<candidate>.json` holds the COMPLETE failing
// submissions and the exact feedback, the prompt/tool-schema hashes and the source
// references a session captured — enough to replay the contract failure offline
// through verification.Reconcile without any model. Previews elsewhere are
// declared in `truncated_fields[]`; decisive fields are never truncated. Secrets are
// masked; hidden reasoning is never available to this process and never stored.

const (
	DiagnosticsDir      = "diagnostics"
	DiagnosticsKeep     = 200             // newest N per scan
	DiagnosticsMaxBytes = 5 * 1024 * 1024 // per file, previews trimmed first
	DiagnosticBounded   = "bounded"
	DiagnosticFull      = "full"
)

// DiagnosticRecord is diagnostics/<candidate>.json.
type DiagnosticRecord struct {
	CandidateID        string                           `json:"candidate_id"`
	Revision           string                           `json:"revision"`
	Model              string                           `json:"model,omitempty"`
	StopReason         string                           `json:"stop_reason"`
	StopCode           string                           `json:"stop_code,omitempty"`
	PromptHash         string                           `json:"prompt_hash"`
	ToolSchemaHash     string                           `json:"tool_schema_hash"`
	Location           string                           `json:"location"`
	FailingSubmissions []verification.FailingSubmission `json:"failing_submissions"`
	SourceRefs         []verification.SourceRef         `json:"source_refs"`
	Calls              []verification.CallRecord        `json:"calls,omitempty"`
	Context            string                           `json:"context"` // bounded | full
	ContextRef         string                           `json:"context_ref,omitempty"`
	TruncatedFields    []string                         `json:"truncated_fields"`
	SizeBytes          int                              `json:"size_bytes"`
	Note               string                           `json:"note"`
}

// writeDiagnostic persists the record for one session (best effort; never fails a
// scan). `mode` is bounded (default) or full; in full mode the sanitized call log is
// stored once per prompt hash under diagnostics/context/.
func writeDiagnostic(resultsDir, mode string, c verification.Candidate, res agentResult, revision string) {
	if mode == "" {
		mode = DiagnosticBounded
	}
	dir := filepath.Join(resultsDir, DiagnosticsDir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return
	}
	rec := DiagnosticRecord{
		CandidateID: c.ID, Revision: revision, Model: res.Model, StopReason: res.StoppedReason, StopCode: res.StopCode,
		PromptHash: res.PromptHash, ToolSchemaHash: res.ToolSchemaHash, Location: c.Finding.Location,
		FailingSubmissions: sanitizeSubmissions(res.failing), SourceRefs: res.sourceRefs, Context: mode,
		TruncatedFields: []string{"calls[].message (300-byte clamp)", "calls[].feedback (2000-byte clamp)"},
		Note:            "telemetry previews (calls[].message/feedback) are stored clamps, not model-context truncation; failing_submissions and feedback are complete",
	}
	if rec.SourceRefs == nil {
		rec.SourceRefs = []verification.SourceRef{}
	}
	if mode == DiagnosticFull {
		// Content-address the context: candidates share a system prompt, but their
		// conversations differ. A prompt hash alone would silently reuse the first.
		ctxDir := filepath.Join(dir, "context")
		if err := os.MkdirAll(ctxDir, 0o755); err == nil && res.PromptHash != "" {
			b, _ := json.MarshalIndent(sanitizeDiagnosticValue(map[string]any{"prompt_hash": res.PromptHash, "tool_schema_hash": res.ToolSchemaHash, "messages": res.ContextMessages, "calls": res.Calls}), "", "  ")
			if len(b) > DiagnosticsMaxBytes {
				rec.TruncatedFields = append(rec.TruncatedFields, "context.messages (omitted: over 5 MB; failing submissions retained)")
				b, _ = json.Marshal(map[string]any{"prompt_hash": res.PromptHash, "omitted": "context over 5 MB; complete failing submissions in candidate record"})
			}
			ref := filepath.Join(DiagnosticsDir, "context", sha256Hex(b)+".json")
			full := filepath.Join(resultsDir, ref)
			if _, err := os.Stat(full); err != nil {
				_ = os.WriteFile(full, b, 0o600)
			}
			rec.ContextRef = ref
		}
	} else {
		// Bounded: the call log without previews of tool output (they are clamps).
		for _, cl := range res.Calls {
			if cl.Outcome == "error" {
				cl.Message, _ = redact.Mask(cl.Message)
				cl.Feedback, _ = redact.Mask(cl.Feedback)
				rec.Calls = append(rec.Calls, cl)
			}
		}
		if len(rec.Calls) > 0 {
			rec.TruncatedFields = append(rec.TruncatedFields, "calls[].message (300-byte clamp)", "calls[].feedback (2000-byte clamp)")
		}
	}
	b, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return
	}
	if len(b) > DiagnosticsMaxBytes {
		// Trim non-decisive fields first: the call log; failing submissions stay whole.
		rec.Calls = nil
		rec.TruncatedFields = append(rec.TruncatedFields, "calls (dropped: file over 5 MB)")
		b, _ = json.MarshalIndent(rec, "", "  ")
	}
	rec.SizeBytes = len(b)
	b, _ = json.MarshalIndent(rec, "", "  ")
	_ = os.WriteFile(filepath.Join(dir, safeName(c.ID)+".json"), b, 0o600)
	pruneDiagnostics(dir)
}

// sanitizeSubmissions masks secrets inside the complete failing submissions
// without shortening them (decisive fields are never truncated).
func sanitizeSubmissions(in []verification.FailingSubmission) []verification.FailingSubmission {
	out := []verification.FailingSubmission{}
	b, _ := json.Marshal(sanitizeDiagnosticValue(in))
	_ = json.Unmarshal(b, &out)
	return out
}

// Round-trip through JSON to cover structs, nested arrays, and raw tool JSON.
// Never mutate the verifier's in-memory evidence while sanitizing telemetry.
func sanitizeDiagnosticValue(value any) any {
	b, _ := json.Marshal(value)
	var v any
	_ = json.Unmarshal(b, &v)
	var walk func(any) any
	walk = func(v any) any {
		switch x := v.(type) {
		case map[string]any:
			for k, val := range x {
				switch strings.ToLower(k) {
				case "password", "passwd", "secret", "api_key", "apikey", "api-key", "api_token", "token", "access_token", "client_secret", "authorization":
					x[k] = "[REDACTED]"
				case "reasoning", "reasoning_content", "thinking":
					delete(x, k)
				default:
					x[k] = walk(val)
				}
			}
		case []any:
			for i := range x {
				x[i] = walk(x[i])
			}
		case string:
			var inner any
			if (strings.HasPrefix(strings.TrimSpace(x), "{") || strings.HasPrefix(strings.TrimSpace(x), "[")) && json.Unmarshal([]byte(x), &inner) == nil {
				raw, _ := json.Marshal(walk(inner))
				return string(raw)
			}
			masked, _ := redact.Mask(x)
			return masked
		}
		return v
	}
	return walk(v)
}

// pruneDiagnostics keeps the newest DiagnosticsKeep records (by modification time).
func pruneDiagnostics(dir string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	type f struct {
		name string
		mod  int64
	}
	var files []f
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		files = append(files, f{e.Name(), info.ModTime().UnixNano()})
	}
	sort.Slice(files, func(i, j int) bool { return files[i].mod > files[j].mod })
	for _, old := range files[min(len(files), DiagnosticsKeep):] {
		_ = os.Remove(filepath.Join(dir, old.name))
	}
	// Context blobs have the same retention as the records which reference them.
	used := map[string]bool{}
	for _, kept := range files[:min(len(files), DiagnosticsKeep)] {
		b, e := os.ReadFile(filepath.Join(dir, kept.name))
		if e != nil {
			continue
		}
		var d DiagnosticRecord
		if json.Unmarshal(b, &d) == nil && d.ContextRef != "" {
			used[filepath.Base(d.ContextRef)] = true
		}
	}
	contexts, _ := os.ReadDir(filepath.Join(dir, "context"))
	for _, c := range contexts {
		if !c.IsDir() && !used[c.Name()] {
			_ = os.Remove(filepath.Join(dir, "context", c.Name()))
		}
	}
}

func safeName(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r == '-' || r == '_' || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9'):
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	return b.String()
}

// orText returns s, or alt when s is blank.
func orText(s, alt string) string {
	if strings.TrimSpace(s) == "" {
		return alt
	}
	return s
}
