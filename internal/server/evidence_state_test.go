package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"vhlocal/internal/jobs"
)

// evidenceServer builds a Server whose runner emits scan_start for a given dir
// and then blocks until released, so each evidence state can be staged.
func evidenceServer(t *testing.T, root string, run jobs.RunFunc) *Server {
	t.Helper()
	store, err := jobs.NewStore(filepath.Join(root, "jobs.json"), run)
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{cfg: Config{AllowRoots: []string{root}, ReportsDir: root}, store: store}
	store.SetBindFilter(s.allowRootOK)
	return s
}

func get(s *Server, path string) (int, map[string]any, string) {
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
	var m map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &m)
	return w.Code, m, w.Body.String()
}

func waitState(t *testing.T, s *Server, id, want string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if st, _, _ := s.store.EvidenceState(id); st == want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	st, dir, reason := s.store.EvidenceState(id)
	t.Fatalf("state never became %s (got %s dir=%q reason=%q)", want, st, dir, reason)
}

// Feature 014 (FR-002, T014): every evidence endpoint distinguishes unknown /
// not_started / running_no_files / ready / empty / unavailable with distinct
// status+body — no two states share a response.
func TestEvidenceStatesAreDistinguishable(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "r1")
	os.MkdirAll(dir, 0o755)
	release := make(chan struct{})
	s := evidenceServer(t, root, func(ctx context.Context, spec map[string]any, emit func(map[string]any)) (string, error) {
		emit(map[string]any{"type": "scan_start", "results_dir": dir})
		<-release
		return dir, nil
	})
	seen := map[string]string{} // state -> "code|state-field" signature per endpoint

	record := func(state, ep string, code int, m map[string]any) {
		sig := ep + ":" + http.StatusText(code) + "|" + str(m["state"])
		if prev, ok := seen[ep+"/"+state]; ok && prev != sig {
			t.Errorf("state %s on %s changed signature: %s vs %s", state, ep, prev, sig)
		}
		seen[ep+"/"+state] = sig
	}
	endpoints := []string{"artifacts", "prompts", "log", "file?path=x.txt"}

	// unknown
	for _, ep := range endpoints {
		code, m, _ := get(s, "/api/scans/nope/"+ep)
		if code != 404 {
			t.Errorf("unknown id on %s → %d, want 404", ep, code)
		}
		record("unknown", ep, code, m)
	}

	// running_no_files (bound, empty dir, job running)
	id := s.store.Submit(map[string]any{"repo": root})
	waitState(t, s, id, jobs.EvidenceRunningNoFiles)
	for _, ep := range endpoints {
		code, m, body := get(s, "/api/scans/"+id+"/"+ep)
		if str(m["state"]) != jobs.EvidenceRunningNoFiles && !strings.HasPrefix(ep, "file") {
			t.Errorf("running_no_files on %s → %d %s", ep, code, body)
		}
		record("running_no_files", ep, code, m)
	}

	// not_started (a second job is queued behind the running one)
	id2 := s.store.Submit(map[string]any{"repo": root})
	for _, ep := range endpoints {
		code, m, body := get(s, "/api/scans/"+id2+"/"+ep)
		if str(m["state"]) != jobs.EvidenceNotStarted || code == 200 || code == 404 {
			t.Errorf("not_started on %s → %d %s (must be neither 200 nor 404)", ep, code, body)
		}
		record("not_started", ep, code, m)
	}

	// ready (a file appears while running)
	os.WriteFile(filepath.Join(dir, "phase1_output.md"), []byte("# recon"), 0o644)
	waitState(t, s, id, jobs.EvidenceReady)
	code, m, body := get(s, "/api/scans/"+id+"/artifacts")
	if code != 200 || str(m["state"]) != jobs.EvidenceReady {
		t.Errorf("ready → %d %s", code, body)
	}
	files, _ := m["files"].([]any)
	if len(files) != 1 {
		t.Errorf("ready must list the file while RUNNING, got %v", m["files"])
	}
	record("ready", "artifacts", code, m)

	// unavailable (directory vanishes)
	os.RemoveAll(dir)
	code, m, body = get(s, "/api/scans/"+id+"/artifacts")
	if code != 503 || str(m["state"]) != jobs.EvidenceUnavailable {
		t.Errorf("unavailable → %d %s, want 503 unavailable", code, body)
	}
	record("unavailable", "artifacts", code, m)

	// empty (terminal, dir exists, no files)
	os.MkdirAll(dir, 0o755)
	close(release)
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if st, _ := s.store.Status(id); st == jobs.StatusDone {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	code, m, body = get(s, "/api/scans/"+id+"/artifacts")
	if code != 200 || str(m["state"]) != jobs.EvidenceEmpty {
		t.Errorf("empty → %d %s, want 200 empty", code, body)
	}
	record("empty", "artifacts", code, m)

	// No two states share a signature on the same endpoint.
	bySig := map[string]string{}
	for k, sig := range seen {
		ep := k[:strings.Index(k, "/")]
		key := ep + "=" + sig
		if other, ok := bySig[key]; ok && other != k {
			t.Errorf("states %s and %s are indistinguishable on %s (%s)", other, k, ep, sig)
		}
		bySig[key] = k
	}
}

// Feature 014 (FR-009, T019): a scan recorded before prompt capture existed reads
// not_recorded — never an indefinite "not captured yet".
func TestPromptsNotRecordedForLegacyScan(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "legacy")
	os.MkdirAll(dir, 0o755)
	// A terminal scan with scan_meta.json lacking prompt_capture_version and no prompts.jsonl.
	os.WriteFile(filepath.Join(dir, "scan_meta.json"), []byte(`{"repo":"x","engine_version":"0.9"}`), 0o644)
	s := evidenceServer(t, root, func(ctx context.Context, spec map[string]any, emit func(map[string]any)) (string, error) {
		emit(map[string]any{"type": "scan_start", "results_dir": dir})
		return dir, nil
	})
	id := s.store.Submit(map[string]any{"repo": root})
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if st, _ := s.store.Status(id); st == jobs.StatusDone {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	code, m, body := get(s, "/api/scans/"+id+"/prompts")
	if code != 200 || str(m["state"]) != "not_recorded" {
		t.Errorf("legacy scan prompts → %d %s, want 200 state=not_recorded", code, body)
	}
}
