package engine

import (
	"context"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"vhlocal/internal/client"
)

// barrierWriter wraps pathWriter and records the maximum number of Chat calls
// in flight at once, so a test can prove bounded overlap (feature 013, US3,
// SC-004). A short delay while "in flight" forces genuine overlap under
// concurrency>1; under serial execution the max stays 1.
type barrierWriter struct {
	pw        *pathWriter
	mu        sync.Mutex
	active    int
	maxActive int
}

func (b *barrierWriter) Backend() client.Backend { return "fake" }
func (b *barrierWriter) Endpoint() string        { return "fake://local" }

func (b *barrierWriter) enter() {
	b.mu.Lock()
	b.active++
	if b.active > b.maxActive {
		b.maxActive = b.active
	}
	b.mu.Unlock()
}
func (b *barrierWriter) leave() {
	b.mu.Lock()
	b.active--
	b.mu.Unlock()
}
func (b *barrierWriter) MaxActive() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.maxActive
}

func (b *barrierWriter) Chat(ctx context.Context, req client.ChatRequest) (*client.ChatResponse, error) {
	b.enter()
	time.Sleep(10 * time.Millisecond) // widen the overlap window
	defer b.leave()
	return b.pw.Chat(ctx, req)
}

func concurrencySpec(repo, results string, n int) ScanSpec {
	sc := brokenSpec(repo, results)
	sc.Concurrency = n
	return sc
}

// SC-004 / FR-013/014: concurrency>1 produces real bounded overlap that never
// exceeds the limit; concurrency 1 stays strictly serial. Run under -race to
// catch data races in the shared record/vote/budget state.
func TestHuntBoundedConcurrency(t *testing.T) {
	repo := filepath.Join(repoRoot(t), "testdata", "vulnapp")

	t.Run("parallel bounded", func(t *testing.T) {
		bw := &barrierWriter{pw: &pathWriter{model: "m"}}
		rec, err := Execute(context.Background(), concurrencySpec(repo, t.TempDir(), 2),
			Providers{Hunt: bw}, staticSkill{}, nil)
		if err != nil {
			t.Fatal(err)
		}
		if rec == nil {
			t.Fatal("nil record")
		}
		max := bw.MaxActive()
		if max <= 1 {
			t.Errorf("concurrency=2 produced no overlap (maxActive=%d); parallelism not working", max)
		}
		if max > 2 {
			t.Errorf("concurrency=2 exceeded the limit (maxActive=%d)", max)
		}
	})

	t.Run("serial", func(t *testing.T) {
		bw := &barrierWriter{pw: &pathWriter{model: "m"}}
		_, err := Execute(context.Background(), concurrencySpec(repo, t.TempDir(), 1),
			Providers{Hunt: bw}, staticSkill{}, nil)
		if err != nil {
			t.Fatal(err)
		}
		if max := bw.MaxActive(); max != 1 {
			t.Errorf("concurrency=1 must be strictly serial, maxActive=%d", max)
		}
	})
}

// FR-015: cancellation stops scheduling new work and preserves completed
// artifacts; the run is marked cancelled and not reported complete.
func TestHuntConcurrencyCancellation(t *testing.T) {
	repo := filepath.Join(repoRoot(t), "testdata", "vulnapp")
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel before hunt fan-out
	rec, err := Execute(ctx, concurrencySpec(repo, t.TempDir(), 3),
		Providers{Hunt: &pathWriter{model: "m"}}, staticSkill{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !rec.Cancelled {
		t.Error("a cancelled scan must be marked cancelled")
	}
}

// FR-014: parallel aggregation is deterministic — the same inputs yield the same
// set of hunt agent labels regardless of scheduling.
func TestHuntConcurrencyDeterministicAgents(t *testing.T) {
	repo := filepath.Join(repoRoot(t), "testdata", "vulnapp")
	labelSet := func(rec *RunRecord) map[string]bool {
		m := map[string]bool{}
		for _, a := range rec.Agents {
			m[a.Label] = true
		}
		return m
	}
	r1, err := Execute(context.Background(), concurrencySpec(repo, t.TempDir(), 3),
		Providers{Hunt: &pathWriter{model: "m"}}, staticSkill{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	r2, err := Execute(context.Background(), concurrencySpec(repo, t.TempDir(), 3),
		Providers{Hunt: &pathWriter{model: "m"}}, staticSkill{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	s1, s2 := labelSet(r1), labelSet(r2)
	if len(s1) != len(s2) {
		t.Fatalf("nondeterministic agent set: %d vs %d", len(s1), len(s2))
	}
	for k := range s1 {
		if !s2[k] {
			t.Errorf("label %q present in run1 but not run2", k)
		}
	}
}
