package client

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestOllamaChatParsesResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/chat" {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{
			"model":"gpt-oss:120b",
			"message":{"role":"assistant","content":"hi","tool_calls":[
				{"function":{"name":"Read","arguments":{"path":"app.py"}}}
			]},
			"done":true,"prompt_eval_count":42,"eval_count":7
		}`))
	}))
	defer srv.Close()

	c := NewOllama(srv.URL)
	resp, err := c.Chat(context.Background(), ChatRequest{Model: "gpt-oss:120b", NumCtx: 131072})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Model != "gpt-oss:120b" || resp.Usage.PromptTokens != 42 || resp.Usage.CompletionTokens != 7 {
		t.Fatalf("bad parse: %+v", resp)
	}
	if len(resp.Message.ToolCalls) != 1 || resp.Message.ToolCalls[0].Name != "Read" {
		t.Fatalf("tool call not parsed: %+v", resp.Message.ToolCalls)
	}
	// Provenance captured at call time (Principle IV), num_ctx recorded.
	if resp.Provenance.Backend != BackendOllama || resp.Provenance.NumCtx != 131072 {
		t.Fatalf("provenance: %+v", resp.Provenance)
	}
	if resp.Provenance.ReturnedModel != "gpt-oss:120b" {
		t.Errorf("returned model not recorded: %q", resp.Provenance.ReturnedModel)
	}
}

func TestOpenAIChatParsesResponseAndSendsKey(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.Write([]byte(`{
			"model":"m","choices":[{"message":{"role":"assistant","content":"ok",
				"tool_calls":[{"id":"c1","type":"function","function":{"name":"Grep","arguments":"{\"q\":\"x\"}"}}]}}],
			"usage":{"prompt_tokens":10,"completion_tokens":3}
		}`))
	}))
	defer srv.Close()

	c := NewOpenAI(BackendOpenAI, srv.URL, "sekret")
	resp, err := c.Chat(context.Background(), ChatRequest{Model: "m"})
	if err != nil {
		t.Fatal(err)
	}
	if gotAuth != "Bearer sekret" {
		t.Errorf("key not sent in header: %q", gotAuth)
	}
	// The key must NOT appear in provenance (FR-009a).
	if resp.Provenance.Endpoint == "" || contains(resp.Provenance.Endpoint, "sekret") {
		t.Errorf("provenance leaked or missing endpoint: %q", resp.Provenance.Endpoint)
	}
	if len(resp.Message.ToolCalls) != 1 || resp.Message.ToolCalls[0].ID != "c1" {
		t.Fatalf("tool call: %+v", resp.Message.ToolCalls)
	}
}

func TestTransportErrorIsExplicitNonRetryable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "bad request", http.StatusBadRequest) // 400, non-retryable
	}))
	defer srv.Close()
	c := NewOllama(srv.URL)
	_, err := c.Chat(context.Background(), ChatRequest{Model: "x"})
	var te *TransportError
	if !errors.As(err, &te) {
		t.Fatalf("expected *TransportError, got %v", err)
	}
	if te.Status != 400 || te.Retryable {
		t.Fatalf("400 should be explicit non-retryable, got %+v", te)
	}
}

// C-P1: an Ollama HTTP 500 "error parsing tool call" is classified ToolParse with
// the model's intended action extracted from raw='…'.
func TestOllamaToolParse500Classified(t *testing.T) {
	body := `{"error":"error parsing tool call: raw='We need to locate the file.{\"pattern\":\"/home/x/**\"}', err=invalid character 'W' looking for beginning of value"}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(body))
	}))
	defer srv.Close()
	c := NewOllama(srv.URL)
	_, err := c.Chat(context.Background(), ChatRequest{Model: "gpt-oss:120b"})
	var te *TransportError
	if !errors.As(err, &te) {
		t.Fatalf("expected *TransportError, got %v", err)
	}
	if te.Kind != KindToolParse {
		t.Fatalf("kind=%q want tool_parse", te.Kind)
	}
	if te.Retryable { // C-P2: a tool-parse error is NOT replay-retryable
		t.Error("a tool-parse error must be non-retryable")
	}
	if !contains(te.Raw, `{"pattern":"/home/x/**"}`) {
		t.Errorf("raw intended action not extracted: %q", te.Raw)
	}
}

// C-P2: a generic 500 (no tool-parse signature) stays Generic and retryable.
func TestGeneric500StaysRetryable(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error":"internal server error"}`))
	}))
	defer srv.Close()
	c := NewOllama(srv.URL)
	_, err := c.Chat(context.Background(), ChatRequest{Model: "x"})
	var te *TransportError
	if !errors.As(err, &te) {
		t.Fatalf("expected *TransportError, got %v", err)
	}
	if te.Kind != KindGeneric {
		t.Errorf("a plain 500 must stay generic, got kind=%q", te.Kind)
	}
	if !te.Retryable {
		t.Error("a generic 500 must remain retryable")
	}
	if hits < 2 {
		t.Errorf("a retryable 500 should be retried on the same endpoint; hits=%d", hits)
	}
}

// C-P3: a genuine transport failure (401) is Generic, not misclassified.
func TestAuthErrorNotToolParse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error":"unauthorized"}`))
	}))
	defer srv.Close()
	c := NewOllama(srv.URL)
	_, err := c.Chat(context.Background(), ChatRequest{Model: "x"})
	var te *TransportError
	if !errors.As(err, &te) {
		t.Fatalf("expected *TransportError, got %v", err)
	}
	if te.Kind == KindToolParse {
		t.Error("a 401 must not be misclassified as a tool-parse error")
	}
	if te.Status != 401 || te.Retryable {
		t.Errorf("401 should be explicit non-retryable generic, got %+v", te)
	}
}

// C-P4: the OpenAI-compatible backend classifies its equivalent tool/function-call
// parse error as ToolParse too.
func TestOpenAIToolParseClassified(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// HTTP 200 with an error field indicating a tool-call parse failure.
		w.Write([]byte(`{"error":{"message":"failed to parse tool call arguments from model output"}}`))
	}))
	defer srv.Close()
	c := NewOpenAI(BackendOpenAI, srv.URL, "")
	_, err := c.Chat(context.Background(), ChatRequest{Model: "m"})
	var te *TransportError
	if !errors.As(err, &te) {
		t.Fatalf("expected *TransportError, got %v", err)
	}
	if te.Kind != KindToolParse {
		t.Errorf("OpenAI-compatible tool-call parse error must classify as tool_parse, got %q", te.Kind)
	}
}

func TestRedactEndpointStripsCredentials(t *testing.T) {
	got := redactEndpoint("http://user:pass@gpu:11434")
	if contains(got, "pass") {
		t.Fatalf("credentials not redacted: %q", got)
	}
}

func contains(s, sub string) bool {
	return len(sub) > 0 && len(s) >= len(sub) && (indexOf(s, sub) >= 0)
}
func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
