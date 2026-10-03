package assist

import (
	"context"
	"errors"
	"testing"

	"vhlocal/internal/client"
	"vhlocal/internal/client/testsupport"
)

func finding() map[string]any {
	return map[string]any{
		"title": "SQLi in login", "severity": "High", "location": "auth.go:42",
		"entry_point": "POST /login", "verification_status": "supported",
		"verification_record": map[string]any{"attacker_control": "username"},
	}
}

// T035 (FR-039/040): each of the five actions runs, captures provenance, and is
// labeled as generated analysis distinct from scan evidence. Draft actions are
// marked as non-executed drafts.
func TestAllFiveActions(t *testing.T) {
	t.Setenv("VHLOCAL_ASSIST_DIR", t.TempDir())
	actions := []Action{ExplainFlow, FindMitigations, Challenge, DraftTest, ProposeFix}
	for _, a := range actions {
		fp := &testsupport.FakeProvider{Backend_: "fake", Endpoint_: "fake://local",
			Script: []client.ChatResponse{testsupport.AssistantText("analysis for " + string(a))}}
		res := Run(context.Background(), fp, Request{
			StableID: "source-v1:s1", ScanID: "scan1", Revision: "rev1",
			Action: a, RequestID: "r-" + string(a), Model: "m1", Finding: finding(),
		})
		if res.Status != StatusSucceeded {
			t.Fatalf("%s status=%s err=%s", a, res.Status, res.Error)
		}
		if res.Label != GeneratedLabel {
			t.Fatalf("%s missing generated label", a)
		}
		if res.Provenance.Backend != "fake" || res.Provenance.Endpoint != "fake://local" {
			t.Fatalf("%s provenance not captured: %+v", a, res.Provenance)
		}
		wantKind := "analysis"
		if a == DraftTest || a == ProposeFix {
			wantKind = "draft"
		}
		if res.Kind != wantKind {
			t.Fatalf("%s kind=%s want %s", a, res.Kind, wantKind)
		}
		// The prompt carries the finding as untrusted data and forbids execution claims.
		sys := fp.Calls[0].Messages[0].Content
		if !contains(sys, "untrusted") || !contains(sys, "never claim you executed") {
			t.Fatalf("%s system prompt missing untrusted-data / no-execution guardrails", a)
		}
		if len(fp.Calls[0].Tools) != 0 {
			t.Fatalf("%s must run with NO tools (static-only), got %d", a, len(fp.Calls[0].Tools))
		}
	}
}

// T035 (FR-041/Principle V): a provider transport error is an explicit failure —
// never a silent fallback to another provider.
func TestFailureIsExplicit(t *testing.T) {
	t.Setenv("VHLOCAL_ASSIST_DIR", t.TempDir())
	fp := &testsupport.FakeProvider{Err: &client.TransportError{Backend: "fake", Endpoint: "fake://local", Msg: "unreachable"}}
	res := Run(context.Background(), fp, Request{StableID: "source-v1:s1", Action: Challenge, Finding: finding()})
	if res.Status != StatusFailed || res.Error == "" {
		t.Fatalf("expected explicit failure, got %+v", res)
	}
}

// T035 (FR-042): a cancelled context yields a cancelled result.
func TestCancellation(t *testing.T) {
	t.Setenv("VHLOCAL_ASSIST_DIR", t.TempDir())
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	fp := &testsupport.FakeProvider{Err: errors.New("context canceled")}
	res := Run(ctx, fp, Request{StableID: "source-v1:s1", Action: ExplainFlow, Finding: finding()})
	if res.Status != StatusCancelled {
		t.Fatalf("cancelled ctx should yield cancelled, got %s", res.Status)
	}
}

// FR-041: a nil provider fails explicitly (no fallback).
func TestNilProviderExplicitFailure(t *testing.T) {
	t.Setenv("VHLOCAL_ASSIST_DIR", t.TempDir())
	res := Run(context.Background(), nil, Request{StableID: "source-v1:s1", Action: ExplainFlow, Finding: finding()})
	if res.Status != StatusFailed || res.Error == "" {
		t.Fatalf("nil provider must fail explicitly: %+v", res)
	}
}

// FR-042: results persist and are retrievable; a repeat is served from the store.
func TestPersistAndRetrieve(t *testing.T) {
	t.Setenv("VHLOCAL_ASSIST_DIR", t.TempDir())
	fp := &testsupport.FakeProvider{Script: []client.ChatResponse{testsupport.AssistantText("hello")}}
	Run(context.Background(), fp, Request{StableID: "source-v1:s1", ScanID: "scan1", Revision: "rev1", Action: ProposeFix, RequestID: "r1", Finding: finding()})
	got, ok := Get("source-v1:s1", ProposeFix, "rev1")
	if !ok || got.Output != "hello" || got.RequestID != "r1" {
		t.Fatalf("retrieve failed: ok=%v res=%+v", ok, got)
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
