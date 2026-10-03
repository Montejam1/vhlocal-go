package cli

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"vhlocal/internal/apps"
)

func TestRunPersistsCanonicalApplicationIdentity(t *testing.T) {
	var calls atomic.Int32
	endpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); w.WriteHeader(500) }))
	defer endpoint.Close()
	repo, out := t.TempDir(), t.TempDir()
	// Report-only phase: no source execution and no inference call is permitted.
	if code := runCmd([]string{"--repo", repo, "--out", out, "--phases", "4", "--model", "offline", "--backend", "ollama", "--host", endpoint.URL, "--app-name", "Shop", "--ledger=false"}); code != ExitOK {
		t.Fatal(code)
	}
	if calls.Load() != 0 {
		t.Fatal("report-only run contacted provider")
	}
	b, e := os.ReadFile(filepath.Join(out, "scan_meta.json"))
	if e != nil {
		t.Fatal(e)
	}
	var m map[string]any
	json.Unmarshal(b, &m)
	if m["app_slug"] != apps.SlugFor(repo) || m["app_name"] != "Shop" || m["schema"] != "final" {
		t.Fatalf("CLI identity: %v", m)
	}
}
