// Package testsupport provides offline fakes for the inference layer so the
// engine and agent loop can be tested without a live model or network
// (constitution Principle VII; FR-029).
package testsupport

import (
	"context"
	"sync"

	"vhlocal/internal/client"
)

// FakeProvider returns scripted responses in order, then errors if over-called.
// Each call records the request it received for assertions. It is safe for
// concurrent use (feature 013, US3 bounded-concurrency tests).
type FakeProvider struct {
	Backend_  client.Backend
	Endpoint_ string
	Script    []client.ChatResponse
	Err       error // if set, Chat always returns this error
	mu        sync.Mutex
	Calls     []client.ChatRequest
	idx       int
}

// Chat implements client.Provider.
func (f *FakeProvider) Chat(_ context.Context, req client.ChatRequest) (*client.ChatResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Calls = append(f.Calls, req)
	if f.Err != nil {
		return nil, f.Err
	}
	if f.idx >= len(f.Script) {
		// Default terminal response: assistant with no tool calls.
		return &client.ChatResponse{Message: client.Message{Role: "assistant", Content: "done"}}, nil
	}
	r := f.Script[f.idx]
	f.idx++
	return &r, nil
}

// CallCount returns the number of Chat calls recorded (thread-safe).
func (f *FakeProvider) CallCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.Calls)
}

func (f *FakeProvider) Backend() client.Backend {
	if f.Backend_ == "" {
		return "fake"
	}
	return f.Backend_
}

func (f *FakeProvider) Endpoint() string {
	if f.Endpoint_ == "" {
		return "fake://local"
	}
	return f.Endpoint_
}

// AssistantText builds a scripted plain-text assistant response.
func AssistantText(content string) client.ChatResponse {
	return client.ChatResponse{Message: client.Message{Role: "assistant", Content: content}}
}

// AssistantToolCall builds a scripted assistant response requesting one tool call.
func AssistantToolCall(id, name, argsJSON string) client.ChatResponse {
	return client.ChatResponse{Message: client.Message{
		Role:      "assistant",
		ToolCalls: []client.ToolCall{{ID: id, Name: name, Arguments: argsJSON}},
	}}
}
