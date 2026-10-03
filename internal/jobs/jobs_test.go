package jobs

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func noopRun(ctx context.Context, spec map[string]any, emit func(map[string]any)) (string, error) {
	return "", nil
}

// T008: an event carrying cumulative token/agent counters updates the live tiles
// (previously always 0). Tolerates int and float64 (JSON) values.
func TestOnEventUpdatesProgressTiles(t *testing.T) {
	s := &Store{jobs: map[string]*Job{}, queue: make(chan string, 1), path: filepath.Join(t.TempDir(), "jobs.json")}
	s.jobs["j1"] = &Job{ID: "j1", Status: StatusRunning}
	s.onEvent("j1", map[string]any{"type": "agent_done", "prompt_tokens": 1200, "completion_tokens": 300})
	s.onEvent("j1", map[string]any{"type": "agent_start", "agent_index": float64(2), "agent_total": float64(6)})
	j := s.jobs["j1"].Public()
	if j["prompt_tokens"] != 1200 || j["completion_tokens"] != 300 {
		t.Errorf("token tiles not updated: %v / %v", j["prompt_tokens"], j["completion_tokens"])
	}
	if j["agent_index"] != 2 || j["agent_total"] != 6 {
		t.Errorf("agent progress not updated: %v / %v", j["agent_index"], j["agent_total"])
	}
}

// CB-7 (US1, FR-002/004): the store loads a mixed/legacy persisted history without
// crashing, forces a dead in-flight job to interrupted, preserves order, and the
// history survives a restart. Legacy/unknown fields degrade rather than panic.
func TestLoadMixedStatesLegacyAndRestart(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "jobs.json")
	// Mixed states incl. a running job (must become interrupted on load) and a
	// legacy-shaped record with an unknown extra field and missing fields.
	seed := `[
	  {"id":"j1","status":"done","created_at":5,"spec":{"repo":"/a"}},
	  {"id":"j2","status":"running","created_at":4,"spec":{"repo":"/b"}},
	  {"id":"j3","status":"failed","created_at":3,"error":"boom","spec":{"repo":"/c"}},
	  {"id":"j4","status":"cancelled","created_at":2,"spec":{"repo":"/d"}},
	  {"id":"j5","status":"done","created_at":1,"legacy_extra_field":true}
	]`
	if err := os.WriteFile(path, []byte(seed), 0o644); err != nil {
		t.Fatal(err)
	}

	s, err := NewStore(path, noopRun)
	if err != nil {
		t.Fatal(err)
	}
	list, _ := s.List()
	if len(list) != 5 {
		t.Fatalf("expected 5 jobs, got %d", len(list))
	}
	byID := map[string]map[string]any{}
	for _, j := range list {
		byID[j["id"].(string)] = j
	}
	if byID["j2"]["status"] != StatusInterrupted {
		t.Errorf("a running job must load as interrupted, got %v", byID["j2"]["status"])
	}
	if byID["j5"]["status"] != StatusDone {
		t.Errorf("legacy-shaped job must load without crashing, got %v", byID["j5"]["status"])
	}
	// Newest-first ordering by created_at.
	if list[0]["id"] != "j1" {
		t.Errorf("expected newest (j1) first, got %v", list[0]["id"])
	}

	// Restart: a fresh store from the same path preserves the history.
	s2, err := NewStore(path, noopRun)
	if err != nil {
		t.Fatal(err)
	}
	list2, _ := s2.List()
	if len(list2) != 5 {
		t.Errorf("history must survive restart, got %d jobs", len(list2))
	}
}
