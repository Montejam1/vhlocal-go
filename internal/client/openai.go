package client

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"vhlocal/internal/config"
)

// OpenAIClient talks to any OpenAI-compatible /v1/chat/completions server. It
// backs both the "openai" backend (mlx_lm.server / vLLM / LM Studio) and the
// "openrouter" backend (fixed host + bearer key). The key travels in the
// Authorization header and is never recorded in provenance (FR-009a).
type OpenAIClient struct {
	backend Backend
	host    string
	apiKey  string
	http    *http.Client
}

// NewOpenAI returns an OpenAI-compatible provider. For BackendOpenRouter the host
// is forced to the fixed OpenRouter host.
func NewOpenAI(backend Backend, host, apiKey string) *OpenAIClient {
	if backend == BackendOpenRouter {
		host = config.OpenRouterHost
	}
	return &OpenAIClient{backend: backend, host: strings.TrimRight(host, "/"), apiKey: apiKey, http: &http.Client{}}
}

// mustJSON marshals v, panicking only on a programming error (unencodable type).
func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

func (c *OpenAIClient) Backend() Backend { return c.backend }
func (c *OpenAIClient) Endpoint() string { return redactEndpoint(c.host) }

// wire types (OpenAI chat completions)
type oaiReq struct {
	Model       string       `json:"model"`
	Messages    []oaiMessage `json:"messages"`
	Tools       []oaiTool    `json:"tools,omitempty"`
	Temperature *float64     `json:"temperature,omitempty"`
	MaxTokens   int          `json:"max_tokens,omitempty"`
}
type oaiMessage struct {
	Role       string        `json:"role"`
	Content    string        `json:"content"`
	ToolCalls  []oaiToolCall `json:"tool_calls,omitempty"`
	ToolCallID string        `json:"tool_call_id,omitempty"`
	Name       string        `json:"name,omitempty"`
}
type oaiTool struct {
	Type     string      `json:"type"`
	Function oaiFunction `json:"function"`
}
type oaiFunction struct {
	Name        string         `json:"name"`
	Description string         `json:"description,omitempty"`
	Parameters  map[string]any `json:"parameters,omitempty"`
}
type oaiToolCall struct {
	ID       string    `json:"id"`
	Type     string    `json:"type"`
	Function oaiCallFn `json:"function"`
}
type oaiCallFn struct {
	Name      string `json:"name"`
	Arguments string `json:"arguments"`
}
type oaiResp struct {
	Model   string `json:"model"`
	Choices []struct {
		Message oaiMessage `json:"message"`
	} `json:"choices"`
	Usage struct {
		PromptTokens     int `json:"prompt_tokens"`
		CompletionTokens int `json:"completion_tokens"`
	} `json:"usage"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error"`
}

// Chat implements Provider.
func (c *OpenAIClient) Chat(ctx context.Context, req ChatRequest) (*ChatResponse, error) {
	body := oaiReq{Model: req.Model, Temperature: req.Temperature}
	if req.MaxOutputTokens > 0 {
		body.MaxTokens = req.MaxOutputTokens
	}
	for _, m := range req.Messages {
		om := oaiMessage{Role: m.Role, Content: m.Content, ToolCallID: m.ToolCallID, Name: m.Name}
		for _, tc := range m.ToolCalls {
			om.ToolCalls = append(om.ToolCalls, oaiToolCall{
				ID: tc.ID, Type: "function",
				Function: oaiCallFn{Name: tc.Name, Arguments: orEmptyObj(tc.Arguments)},
			})
		}
		body.Messages = append(body.Messages, om)
	}
	for _, t := range req.Tools {
		body.Tools = append(body.Tools, oaiTool{Type: "function", Function: oaiFunction{
			Name: t.Name, Description: t.Description, Parameters: t.Parameters,
		}})
	}

	headers := map[string]string{}
	if c.apiKey != "" {
		headers["Authorization"] = "Bearer " + c.apiKey
	}

	prov := Provenance{
		Backend: c.backend, Endpoint: c.Endpoint(), RequestedModel: req.Model,
		Temperature: req.Temperature, MaxOutputTokens: req.MaxOutputTokens,
		ReasoningEffort: req.ReasoningEffort,
	}

	var resp oaiResp
	if err := doWithRetry(ctx, c.http, "POST", c.host+"/v1/chat/completions", c.backend, c.Endpoint(),
		mustJSON(body), headers, &resp); err != nil {
		return nil, err
	}
	if resp.Error != nil {
		te := &TransportError{Backend: c.backend, Endpoint: c.Endpoint(), Msg: resp.Error.Message}
		classifyTransport(te) // FR-001/C-P4: OpenAI-compatible tool/function-call parse error → ToolParse
		return nil, te
	}
	if len(resp.Choices) == 0 {
		return nil, &TransportError{Backend: c.backend, Endpoint: c.Endpoint(), Msg: "no choices in response"}
	}
	msg := resp.Choices[0].Message
	out := &ChatResponse{
		Model:      resp.Model,
		Usage:      Usage{PromptTokens: resp.Usage.PromptTokens, CompletionTokens: resp.Usage.CompletionTokens},
		Provenance: prov,
	}
	out.Provenance.ReturnedModel = resp.Model
	out.Message = Message{Role: "assistant", Content: msg.Content}
	for _, tc := range msg.ToolCalls {
		out.Message.ToolCalls = append(out.Message.ToolCalls, ToolCall{
			ID: tc.ID, Name: tc.Function.Name, Arguments: tc.Function.Arguments,
		})
	}
	return out, nil
}
