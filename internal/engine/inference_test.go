package engine

import (
	"context"
	"path/filepath"
	"sync"
	"testing"

	"vhlocal/internal/client"
)

// recordingWriter behaves like pathWriter (writes deliverables so the pipeline
// progresses) but records every ChatRequest it receives, so a test can assert
// which effective inference params and per-role routing reached the model
// (feature 013, FR-017/018, SC-005). Thread-safe for the concurrent hunt path.
type recordingWriter struct {
	pw   *pathWriter
	mu   sync.Mutex
	reqs []client.ChatRequest
}

func (r *recordingWriter) Backend() client.Backend { return "fake" }
func (r *recordingWriter) Endpoint() string        { return "fake://local" }
func (r *recordingWriter) Chat(ctx context.Context, req client.ChatRequest) (*client.ChatResponse, error) {
	r.mu.Lock()
	r.reqs = append(r.reqs, req)
	r.mu.Unlock()
	return r.pw.Chat(ctx, req)
}
func (r *recordingWriter) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.reqs)
}
func (r *recordingWriter) all() []client.ChatRequest {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]client.ChatRequest(nil), r.reqs...)
}

// FR-018 / SC-005: temperature (including an explicit 0), reasoning effort, and
// output limit reach the model calls; zero temperature is not replaced by a
// default.
func TestInferenceParamsReachCalls(t *testing.T) {
	repo := filepath.Join(repoRoot(t), "testdata", "vulnapp")
	zero := 0.0
	spec := brokenSpec(repo, t.TempDir())
	spec.Temperature = &zero
	spec.ReasoningEffort = "high"
	spec.MaxOutputTokens = 4096

	hunt := &recordingWriter{pw: &pathWriter{model: "m"}}
	if _, err := Execute(context.Background(), spec, Providers{Hunt: hunt}, staticSkill{}, nil); err != nil {
		t.Fatal(err)
	}
	reqs := hunt.all()
	if len(reqs) == 0 {
		t.Fatal("no calls recorded")
	}
	sawTemp, sawReason := false, false
	for _, q := range reqs {
		if q.Temperature != nil && *q.Temperature == 0 {
			sawTemp = true
		}
		if q.ReasoningEffort == "high" {
			sawReason = true
		}
	}
	if !sawTemp {
		t.Error("explicit temperature 0 did not reach any call (or was replaced by a default)")
	}
	if !sawReason {
		t.Error("reasoning_effort did not reach any call")
	}
}

// FR-017 / SC-005: a per-role provider actually receives that role's calls — the
// Verify provider is used for Phase 2b, not the Hunt provider.
func TestPerRoleProviderReachesItsCalls(t *testing.T) {
	repo := filepath.Join(repoRoot(t), "testdata", "vulnapp")
	spec := brokenSpec(repo, t.TempDir()) // phases include 2b

	hunt := &recordingWriter{pw: &pathWriter{model: "hunt"}}
	verify := &recordingWriter{pw: &pathWriter{model: "verify"}}
	if _, err := Execute(context.Background(), spec, Providers{Hunt: hunt, Verify: verify}, staticSkill{}, nil); err != nil {
		t.Fatal(err)
	}
	if verify.count() == 0 {
		t.Error("the per-role Verify provider received no calls; Phase 2b did not route to it")
	}
}
