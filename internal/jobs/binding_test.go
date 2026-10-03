package jobs

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// waitDone blocks until the job leaves the active states, so a blocked worker's
// final persist lands BEFORE t.TempDir cleanup (avoids a cleanup race).
func waitDone(t *testing.T, s *Store, id string) {
	t.Helper()
	waitFor(t, 3*time.Second, func() bool {
		st, _ := s.Status(id)
		return st != StatusRunning && st != StatusQueued
	})
}

// waitFor polls until cond is true or the deadline passes.
func waitFor(t *testing.T, d time.Duration, cond func() bool) bool {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return cond()
}

// Feature 014 (FR-001, T013): on the engine's scan_start event the job binds its
// results directory and PERSISTS it — before the run function returns — so live
// evidence endpoints can resolve the directory while the scan is still running.
func TestScanStartBindsAndPersistsResultsDir(t *testing.T) {
	root := t.TempDir()
	resultsDir := filepath.Join(root, "run-1")
	os.MkdirAll(resultsDir, 0o755)
	release := make(chan struct{})
	store, err := NewStore(filepath.Join(root, "jobs.json"), func(ctx context.Context, spec map[string]any, emit func(map[string]any)) (string, error) {
		emit(map[string]any{"type": "scan_start", "results_dir": resultsDir})
		<-release // stay "running" until the test has inspected the binding
		return resultsDir, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	store.SetBindFilter(func(dir string) bool { return strings.HasPrefix(dir, root) })
	id := store.Submit(map[string]any{"repo": root})

	bound := waitFor(t, 3*time.Second, func() bool {
		st, dir, _ := store.EvidenceState(id)
		return dir == resultsDir && (st == EvidenceRunningNoFiles || st == EvidenceReady)
	})
	if !bound {
		st, dir, reason := store.EvidenceState(id)
		t.Fatalf("results dir not bound while running: state=%s dir=%q reason=%q", st, dir, reason)
	}
	// Persisted before the run returned.
	b, _ := os.ReadFile(filepath.Join(root, "jobs.json"))
	var persisted []map[string]any
	_ = json.Unmarshal(b, &persisted)
	found := false
	for _, j := range persisted {
		if j["id"] == id && j["results_dir"] == resultsDir && j["started"] == true {
			found = true
		}
	}
	if !found {
		t.Errorf("binding not persisted to jobs.json before the run finished: %s", b)
	}
	close(release)
	waitDone(t, store, id)
}

// FR-001 (confinement): a results directory outside the allowed roots is refused
// at binding time and the job stays not_started (never a silent bind).
func TestScanStartBindingConfined(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir() // a different temp tree = outside the allow root
	release := make(chan struct{})
	store, _ := NewStore(filepath.Join(root, "jobs.json"), func(ctx context.Context, spec map[string]any, emit func(map[string]any)) (string, error) {
		emit(map[string]any{"type": "scan_start", "results_dir": outside})
		<-release
		return "", nil
	})
	store.SetBindFilter(func(dir string) bool { return strings.HasPrefix(dir, root) })
	id := store.Submit(map[string]any{"repo": root})
	// Give the worker time to emit; the binding must be refused.
	time.Sleep(150 * time.Millisecond)
	if st, dir, _ := store.EvidenceState(id); st != EvidenceNotStarted || dir != "" {
		t.Errorf("out-of-root results dir must be refused: state=%s dir=%q", st, dir)
	}
	close(release)
	waitDone(t, store, id)
}

// Feature 014 (FR-008, T018): a server restart mid-run marks the job interrupted
// and RETAINS the bound results dir (persisted at scan_start), so recorded
// evidence stays reachable.
func TestRestartPreservesBindingAndMarksInterrupted(t *testing.T) {
	root := t.TempDir()
	resultsDir := filepath.Join(root, "run-x")
	os.MkdirAll(resultsDir, 0o755)
	block := make(chan struct{})
	path := filepath.Join(root, "jobs.json")
	s1, _ := NewStore(path, func(ctx context.Context, spec map[string]any, emit func(map[string]any)) (string, error) {
		emit(map[string]any{"type": "scan_start", "results_dir": resultsDir})
		<-block // "crash" happens while running
		return resultsDir, nil
	})
	id := s1.Submit(map[string]any{"repo": root})
	if !waitFor(t, 3*time.Second, func() bool { _, d, _ := s1.EvidenceState(id); return d == resultsDir }) {
		t.Fatal("binding never happened")
	}
	// Simulate restart: a fresh store loads the same file (worker 1 is left blocked).
	s2, _ := NewStore(path, func(context.Context, map[string]any, func(map[string]any)) (string, error) { return "", nil })
	st, _ := s2.Status(id)
	if st != StatusInterrupted {
		t.Errorf("after restart status = %q, want interrupted", st)
	}
	if es, dir, _ := s2.EvidenceState(id); dir != resultsDir || es == EvidenceNotStarted || es == EvidenceUnknown {
		t.Errorf("after restart binding lost: state=%s dir=%q", es, dir)
	}
	close(block)
	waitDone(t, s1, id) // let the "crashed" worker finish before TempDir cleanup
}
