// Package client also defines the inference-provider abstraction shared by the
// three backends (ollama, openai-compatible, openrouter). Provenance is captured
// at call time (constitution Principle IV); failures are explicit and never
// trigger a silent provider/model fallback (Principle V). Secrets (API keys)
// travel in headers and are never written into provenance, logs, or artifacts.
package client

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
)

// Backend identifies an inference backend.
type Backend string

const (
	BackendOllama     Backend = "ollama"
	BackendOpenAI     Backend = "openai"
	BackendOpenRouter Backend = "openrouter"
)

// Tool is a function tool advertised to the model. Parameters is a JSON Schema.
type Tool struct {
	Name        string
	Description string
	Parameters  map[string]any
}

// ToolCall is a model request to invoke a tool. Arguments is the raw JSON object
// string the model supplied (may be malformed — the agent loop repairs it).
type ToolCall struct {
	ID        string
	Name      string
	Arguments string
}

// Message is one chat message.
type Message struct {
	Role       string // system | user | assistant | tool
	Content    string
	ToolCalls  []ToolCall // assistant tool-call requests
	ToolCallID string     // for role=tool: which call this answers
	Name       string     // for role=tool: the tool name
}

// ChatRequest is a backend-agnostic chat completion request.
type ChatRequest struct {
	Model           string
	Messages        []Message
	Tools           []Tool
	NumCtx          int      // ollama options.num_ctx (ignored by openai wire)
	Temperature     *float64 // nil = provider default
	MaxOutputTokens int      // 0 = uncapped
	ReasoningEffort string   // "", low, medium, high (providers that support it)
}

// Usage is engine-observed token accounting for one call.
type Usage struct {
	PromptTokens     int
	CompletionTokens int
}

// Provenance is captured for every call (Principle IV). No secrets.
type Provenance struct {
	Backend         Backend  `json:"backend"`
	Endpoint        string   `json:"endpoint"` // credential-redacted
	RequestedModel  string   `json:"requested_model"`
	ReturnedModel   string   `json:"returned_model"` // what the provider reported, if any
	NumCtx          int      `json:"num_ctx,omitempty"`
	Temperature     *float64 `json:"temperature,omitempty"`
	MaxOutputTokens int      `json:"max_output_tokens,omitempty"`
	ReasoningEffort string   `json:"reasoning_effort,omitempty"`
}

// ChatResponse is a backend-agnostic response.
type ChatResponse struct {
	Message    Message
	Model      string // model id the provider actually returned
	Usage      Usage
	Provenance Provenance
}

// Provider is one configured backend+endpoint+role.
type Provider interface {
	Chat(ctx context.Context, req ChatRequest) (*ChatResponse, error)
	Backend() Backend
	Endpoint() string // credential-redacted, safe to log
}

// ErrorKind classifies a TransportError (feature 004). The zero value
// (KindGeneric) is a real transport/outage failure — unreachable, auth, timeout,
// malformed response. KindToolParse means the provider rejected the model's tool
// call as unparseable (e.g. Ollama HTTP 500 "error parsing tool call"): the model
// interleaved prose with the tool-call JSON. That is recoverable by a bounded
// fresh-context repair (the intended action is carried in Raw), NOT by replaying
// the identical request, which reproduces it (FR-001/003).
type ErrorKind string

const (
	KindGeneric   ErrorKind = ""           // default: real outage / transport failure
	KindToolParse ErrorKind = "tool_parse" // provider could not parse the model's tool call
)

// TransportError is an explicit backend failure (Principle V: surfaced, recorded,
// never silently swallowed or routed to a different provider). Retryable marks
// transient conditions the caller MAY retry against the SAME endpoint. Kind/Raw
// are in-memory only (this error is never serialized) — no artifact/schema change.
type TransportError struct {
	Backend   Backend
	Endpoint  string
	Status    int // HTTP status, 0 for network-level
	Msg       string
	Retryable bool
	Kind      ErrorKind // Generic (default) or ToolParse (feature 004)
	Raw       string    // model's intended output carried in a ToolParse error ("" if none)
}

func (e *TransportError) Error() string {
	if e.Status != 0 {
		return fmt.Sprintf("%s backend at %s: HTTP %d: %s", e.Backend, e.Endpoint, e.Status, e.Msg)
	}
	return fmt.Sprintf("%s backend at %s: %s", e.Backend, e.Endpoint, e.Msg)
}

// classifyTransport inspects a freshly built TransportError and, when its message
// is a provider tool-call-parse rejection, reclassifies it as KindToolParse:
// extracts the model's raw intended output and marks it NOT replay-retryable
// (replaying the same context reproduces it — FR-001/003). Genuine outages are
// left KindGeneric. Idempotent and safe to call at every error-construction site.
func classifyTransport(te *TransportError) {
	if te == nil {
		return
	}
	msg := te.Msg
	// Providers may wrap the error in a JSON body {"error":"..."}; unwrap so the
	// signature match and raw extraction see the un-escaped message.
	var wrap struct {
		Error string `json:"error"`
	}
	if json.Unmarshal([]byte(msg), &wrap) == nil && wrap.Error != "" {
		msg = wrap.Error
	}
	if !isToolParseSignature(msg) {
		return
	}
	te.Kind = KindToolParse
	te.Retryable = false
	te.Raw = extractRawToolCall(msg)
}

// isToolParseSignature reports whether an error message is a provider's tool-call
// parse rejection. The Ollama form is exact; the OpenAI-compatible form is
// best-effort (a parse failure that clearly concerns a tool/function call — C-P4).
func isToolParseSignature(msg string) bool {
	low := strings.ToLower(msg)
	if strings.Contains(low, "error parsing tool call") {
		return true
	}
	tool := strings.Contains(low, "tool call") || strings.Contains(low, "tool_call") ||
		strings.Contains(low, "function call") || strings.Contains(low, "function_call")
	parse := strings.Contains(low, "parse") || strings.Contains(low, "parsing") ||
		strings.Contains(low, "unparseable") || strings.Contains(low, "unparsable")
	return tool && parse
}

// extractRawToolCall pulls the model's intended output out of a provider error of
// the form: ... raw='<payload>', err=<...>. Returns "" when no raw payload present.
func extractRawToolCall(msg string) string {
	const marker = "raw='"
	i := strings.Index(msg, marker)
	if i < 0 {
		return ""
	}
	rest := msg[i+len(marker):]
	if j := strings.Index(rest, "', err="); j >= 0 {
		return rest[:j]
	}
	if j := strings.LastIndex(rest, "'"); j >= 0 {
		return rest[:j]
	}
	return rest
}

// redactEndpoint strips any user:password@ credentials from a URL so it is safe
// to store in provenance/logs.
func redactEndpoint(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	if u.User != nil {
		u.User = url.User("redacted")
	}
	return u.String()
}
