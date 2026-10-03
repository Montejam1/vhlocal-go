package parity

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"vhlocal/internal/client"
	"vhlocal/internal/engine"
	"vhlocal/internal/inventory"
)

// goDoneProvider is a trivial offline provider: every agent turn returns "done"
// with no tool calls, so no findings are written. This exercises the real engine
// pipeline (discovery → partitions → hunt → finalize → coverage) for a Go target
// without a scripted transcript, proving that discovered Go entry points reach the
// live coverage denominator and that, absent analysis, they remain not_reviewed.
type goDoneProvider struct{}

func (goDoneProvider) Backend() client.Backend { return "fake" }
func (goDoneProvider) Endpoint() string        { return "fake://goapp" }
func (goDoneProvider) Chat(_ context.Context, _ client.ChatRequest) (*client.ChatResponse, error) {
	return &client.ChatResponse{Message: client.Message{Role: "assistant", Content: "done"}}, nil
}

// T047/T052 (integration checkpoint, fixture #1 + #4): discovered Go entry points
// reach hunt partitioning and the coverage ledger via the real engine.Execute path;
// with no analysis produced, every Go route is honestly not_reviewed (never
// silently "clean/covered"). Offline: no live model, no network, no Go toolchain.
func TestGoAppReachesCoverage(t *testing.T) {
	repo := filepath.Join(moduleRoot(t), "testdata", "goapp")
	out := t.TempDir()
	p := goDoneProvider{}
	spec := engine.ScanSpec{
		Repo: repo, ResultsDir: out, Model: "fixture", Backend: "ollama", Host: "fake",
		NumCtx: 8192, MaxPartitions: 8, Phases: []string{"1", "2", "4"}, QualityStrictness: "balanced",
	}
	rec, err := engine.Execute(context.Background(), spec, engine.Providers{Hunt: p, Verify: p, Reproduce: p}, staticSkill{}, nil)
	if err != nil {
		t.Fatalf("engine.Execute: %v", err)
	}

	// Coverage ledger must exist and enumerate the Go routes (fixture #1).
	b, err := os.ReadFile(filepath.Join(out, "coverage_ledger.json"))
	if err != nil {
		t.Fatalf("coverage_ledger.json: %v", err)
	}
	var cl inventory.CoverageLedger
	if err := json.Unmarshal(b, &cl); err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{"GET /users/{id}": false, "POST /login": false, "GET /health": false}
	for _, e := range cl.Entries {
		key := e.Method + " " + e.Path
		if _, ok := want[key]; ok {
			want[key] = true
			if e.Language != "go" {
				t.Errorf("%s: language=%q, want go", key, e.Language)
			}
			// #4: with no analysis, a discovered route is not_reviewed, never reviewed.
			if e.Disposition != inventory.DispNotReviewed {
				t.Errorf("%s: disposition=%q, want not_reviewed (no analysis was produced)", key, e.Disposition)
			}
		}
	}
	for key, seen := range want {
		if !seen {
			t.Errorf("Go route %q not present in coverage ledger — discovery did not reach coverage", key)
		}
	}

	// The fake route in a comment must NOT be enumerated.
	for _, e := range cl.Entries {
		if e.Path == "/commented" {
			t.Error("a route in a comment must not be enumerated")
		}
	}

	// Coverage must NOT be reported complete when routes are unreviewed (honest).
	if cl.Complete {
		t.Error("coverage marked complete while Go routes are unreviewed")
	}

	// Discovery reached partitioning: partitions derived from the Go subsystem.
	if len(rec.Partitions) == 0 {
		t.Error("no partitions derived from discovered Go entry points")
	}
}

// T047 (fixture #1, inventory level): the live EnumerateRoutes path recognizes the
// Go entry points (not only the recognizer's own unit tests).
func TestEnumerateRoutesIncludesGo(t *testing.T) {
	repo := filepath.Join(moduleRoot(t), "testdata", "goapp")
	routes, err := inventory.EnumerateRoutes(repo)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, r := range routes {
		got[r.Method+" "+r.Path] = r.Language
	}
	for _, key := range []string{"GET /users/{id}", "POST /login", "GET /health"} {
		if got[key] != "go" {
			t.Errorf("EnumerateRoutes missing Go route %q (lang=%q)", key, got[key])
		}
	}
}
