package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// OllamaClient talks to Ollama's native /api/chat. num_ctx is always set
// explicitly (Ollama's default context is far smaller than gpt-oss's and an
// over-long prompt is silently truncated).
type OllamaClient struct {
	host string
	http *http.Client
}

// NewOllama returns an Ollama provider for the given host (base URL).
func NewOllama(host string) *OllamaClient {
	return &OllamaClient{host: strings.TrimRight(host, "/"), http: &http.Client{Timeout: 0}}
}

func (c *OllamaClient) Backend() Backend { return BackendOllama }
func (c *OllamaClient) Endpoint() string { return redactEndpoint(c.host) }

// wire types
type ollamaReq struct {
	Model    string          `json:"model"`
	Messages []ollamaMessage `json:"messages"`
	Tools    []ollamaTool    `json:"tools,omitempty"`
	Stream   bool            `json:"stream"`
	Options  map[string]any  `json:"options,omitempty"`
}

type ollamaMessage struct {
	Role      string           `json:"role"`
	Content   string           `json:"content"`
	ToolCalls []ollamaToolCall `json:"tool_calls,omitempty"`
	ToolName  string           `json:"tool_name,omitempty"`
}

type ollamaTool struct {
	Type     string         `json:"type"`
	Function ollamaFunction `json:"function"`
}
type ollamaFunction struct {
	Name        string         `json:"name"`
	Description string         `json:"description,omitempty"`
	Parameters  map[string]any `json:"parameters,omitempty"`
}
type ollamaToolCall struct {
	Function ollamaCallFn `json:"function"`
}
type ollamaCallFn struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments"`
}

type ollamaResp struct {
	Model      string        `json:"model"`
	Message    ollamaMessage `json:"message"`
	Done       bool          `json:"done"`
	PromptEval int           `json:"prompt_eval_count"`
	Eval       int           `json:"eval_count"`
	Error      string        `json:"error"`
}

// Chat implements Provider.
func (c *OllamaClient) Chat(ctx context.Context, req ChatRequest) (*ChatResponse, error) {
	body := ollamaReq{Model: req.Model, Stream: false, Options: map[string]any{}}
	if req.NumCtx > 0 {
		body.Options["num_ctx"] = req.NumCtx
	}
	if req.Temperature != nil {
		body.Options["temperature"] = *req.Temperature
	}
	for _, m := range req.Messages {
		om := ollamaMessage{Role: m.Role, Content: m.Content, ToolName: m.Name}
		for _, tc := range m.ToolCalls {
			om.ToolCalls = append(om.ToolCalls, ollamaToolCall{
				Function: ollamaCallFn{Name: tc.Name, Arguments: json.RawMessage(orEmptyObj(tc.Arguments))},
			})
		}
		body.Messages = append(body.Messages, om)
	}
	for _, t := range req.Tools {
		body.Tools = append(body.Tools, ollamaTool{Type: "function", Function: ollamaFunction{
			Name: t.Name, Description: t.Description, Parameters: t.Parameters,
		}})
	}

	prov := Provenance{
		Backend: BackendOllama, Endpoint: c.Endpoint(), RequestedModel: req.Model,
		NumCtx: req.NumCtx, Temperature: req.Temperature, MaxOutputTokens: req.MaxOutputTokens,
		ReasoningEffort: req.ReasoningEffort,
	}

	var resp ollamaResp
	if err := postJSON(ctx, c.http, c.host+"/api/chat", BackendOllama, c.Endpoint(), body, &resp); err != nil {
		return nil, err
	}
	if resp.Error != "" {
		te := &TransportError{Backend: BackendOllama, Endpoint: c.Endpoint(), Msg: resp.Error}
		classifyTransport(te) // FR-001: a 200-with-error tool-call-parse rejection → ToolParse
		return nil, te
	}
	out := &ChatResponse{
		Model:      resp.Model,
		Usage:      Usage{PromptTokens: resp.PromptEval, CompletionTokens: resp.Eval},
		Provenance: prov,
	}
	out.Provenance.ReturnedModel = resp.Model
	out.Message = Message{Role: "assistant", Content: resp.Message.Content}
	for i, tc := range resp.Message.ToolCalls {
		out.Message.ToolCalls = append(out.Message.ToolCalls, ToolCall{
			ID:        fmt.Sprintf("call_%d", i),
			Name:      tc.Function.Name,
			Arguments: string(tc.Function.Arguments),
		})
	}
	return out, nil
}

// Models lists models the Ollama host advertises (GET /api/tags).
func (c *OllamaClient) Models(ctx context.Context) ([]ModelInfo, error) {
	var raw struct {
		Models []struct {
			Name    string `json:"name"`
			Size    int64  `json:"size"`
			Details struct {
				Family string `json:"family"`
			} `json:"details"`
		} `json:"models"`
	}
	if err := getJSON(ctx, c.http, c.host+"/api/tags", BackendOllama, c.Endpoint(), &raw); err != nil {
		return nil, err
	}
	var out []ModelInfo
	for _, m := range raw.Models {
		sz := m.Size
		out = append(out, ModelInfo{Name: m.Name, Size: &sz, Family: m.Details.Family})
	}
	return out, nil
}

// ModelInfo is a model list entry (shared shape for GET /api/models).
type ModelInfo struct {
	Name   string `json:"name"`
	Size   *int64 `json:"size"`
	Family string `json:"family,omitempty"`
}

func orEmptyObj(s string) string {
	if strings.TrimSpace(s) == "" {
		return "{}"
	}
	return s
}

// --- shared HTTP helpers with one bounded retry on transient failures ---

func postJSON(ctx context.Context, hc *http.Client, urlStr string, be Backend, endpoint string, body, out any) error {
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}
	return doWithRetry(ctx, hc, http.MethodPost, urlStr, be, endpoint, b, nil, out)
}

func getJSON(ctx context.Context, hc *http.Client, urlStr string, be Backend, endpoint string, out any) error {
	return doWithRetry(ctx, hc, http.MethodGet, urlStr, be, endpoint, nil, nil, out)
}

func doWithRetry(ctx context.Context, hc *http.Client, method, urlStr string, be Backend, endpoint string, body []byte, headers map[string]string, out any) error {
	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(500 * time.Millisecond):
			}
		}
		var rdr io.Reader
		if body != nil {
			rdr = bytes.NewReader(body)
		}
		httpReq, err := http.NewRequestWithContext(ctx, method, urlStr, rdr)
		if err != nil {
			return err
		}
		httpReq.Header.Set("Content-Type", "application/json")
		for k, v := range headers {
			httpReq.Header.Set(k, v)
		}
		resp, err := hc.Do(httpReq)
		if err != nil {
			lastErr = &TransportError{Backend: be, Endpoint: endpoint, Msg: err.Error(), Retryable: true}
			continue
		}
		data, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode >= 400 {
			te := &TransportError{Backend: be, Endpoint: endpoint, Status: resp.StatusCode,
				Msg: strings.TrimSpace(string(data)), Retryable: resp.StatusCode == 429 || resp.StatusCode >= 500}
			// FR-001/003: a tool-call-parse 500 becomes ToolParse + non-retryable, so
			// it is routed to fresh-context repair instead of being blindly replayed;
			// generic 5xx/429 keep their bounded same-endpoint retry.
			classifyTransport(te)
			if te.Retryable {
				lastErr = te
				continue
			}
			return te
		}
		if err := json.Unmarshal(data, out); err != nil {
			return &TransportError{Backend: be, Endpoint: endpoint, Msg: "malformed response: " + err.Error()}
		}
		return nil
	}
	return lastErr
}
