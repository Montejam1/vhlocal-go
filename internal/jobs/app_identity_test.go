package jobs

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestRestartRetainsPartialApplicationIdentity(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "results")
	os.Mkdir(dir, 0700)
	meta := map[string]any{"schema": "partial", "repo": "/fixture/shop", "app_slug": "shop-stable", "status": "running"}
	b, _ := json.Marshal(meta)
	os.WriteFile(filepath.Join(dir, "scan_meta.json"), b, 0600)
	jobs := []Job{{ID: "job", Status: StatusRunning, ResultsDir: &dir, Spec: map[string]any{"repo": "/fixture/shop", "app_slug": "shop-stable"}}}
	b, _ = json.Marshal(jobs)
	path := filepath.Join(root, "jobs.json")
	os.WriteFile(path, b, 0600)
	store, err := NewStore(path, noopRun)
	if err != nil {
		t.Fatal(err)
	}
	if status, _ := store.Status("job"); status != StatusInterrupted {
		t.Fatal(status)
	}
	b, _ = os.ReadFile(filepath.Join(dir, "scan_meta.json"))
	json.Unmarshal(b, &meta)
	if meta["app_slug"] != "shop-stable" || meta["status"] != "interrupted" || meta["schema"] != "partial" {
		t.Fatal(meta)
	}
	meta["schema"] = "final"
	meta["status"] = "done"
	b, _ = json.Marshal(meta)
	os.WriteFile(filepath.Join(dir, "scan_meta.json"), b, 0600)
	markPartialRecord(&jobs[0])
	after, _ := os.ReadFile(filepath.Join(dir, "scan_meta.json"))
	if string(after) != string(b) {
		t.Fatal("recovery rewrote final report")
	}
}
