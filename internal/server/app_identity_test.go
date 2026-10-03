package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"vhlocal/internal/apps"
	"vhlocal/internal/engine"
	"vhlocal/internal/jobs"
)

type identitySkill struct{}

func (identitySkill) Preamble() string              { return "offline test" }
func (identitySkill) Prompt(string) (string, error) { return "offline test", nil }

func TestApplicationIdentityDuringScanLifecycle(t *testing.T) {
	for _, cancel := range []bool{false, true} {
		t.Run(map[bool]string{false: "complete", true: "cancel"}[cancel], func(t *testing.T) {
			root := t.TempDir()
			repo := filepath.Join(root, "shop")
			reportsDir := filepath.Join(root, "reports")
			dir := filepath.Join(reportsDir, "scan")
			os.MkdirAll(repo, 0700)
			os.MkdirAll(reportsDir, 0700)
			t.Setenv("VHLOCAL_LEDGER_DIR", filepath.Join(root, "ledgers"))
			started := make(chan struct{})
			release := make(chan struct{})
			store, e := jobs.NewStore(filepath.Join(root, "jobs.json"), func(ctx context.Context, spec map[string]any, emit func(map[string]any)) (string, error) {
				_, err := engine.Execute(ctx, engine.ScanSpec{Repo: spec["repo"].(string), ResultsDir: dir, AppName: spec["app_name"].(string), Model: "offline", Backend: "fake", Phases: []string{"4"}}, engine.Providers{}, identitySkill{}, func(kind string, p map[string]any) {
					p["type"] = kind
					emit(p)
					if kind == "scan_start" {
						close(started)
						select {
						case <-release:
						case <-ctx.Done():
						}
					}
				})
				return dir, err
			})
			if e != nil {
				t.Fatal(e)
			}
			defer func() { close(release); waitJobsIdle(t, store) }()
			s := &Server{cfg: Config{ReportsDir: reportsDir, AllowRoots: []string{root}}, store: store}
			body, _ := json.Marshal(map[string]any{"repo": repo, "app_name": "Store", "model": "offline", "phases": "4"})
			w := httptest.NewRecorder()
			s.Handler().ServeHTTP(w, httptest.NewRequest("POST", "/api/scans", bytes.NewReader(body)))
			if w.Code != 201 {
				t.Fatalf("create: %s", w.Body.String())
			}
			select {
			case <-started:
			case <-time.After(5 * time.Second):
				t.Fatal("scan did not start")
			}
			list, _ := store.List()
			if len(list) != 1 || list[0]["app_slug"] != apps.SlugFor(repo) || list[0]["app_name"] != "Store" {
				t.Fatalf("job identity: %+v", list)
			}
			assertHistory := func(want string) {
				t.Helper()
				w := httptest.NewRecorder()
				s.Handler().ServeHTTP(w, httptest.NewRequest("GET", "/api/applications/"+apps.SlugFor(repo), nil))
				var d apps.AppDetail
				if json.Unmarshal(w.Body.Bytes(), &d) != nil || w.Code != 200 || len(d.ScanHistory) != 1 || d.ScanHistory[0].Status != want {
					t.Fatalf("%s history: %d %s", want, w.Code, w.Body.String())
				}
				if got := apps.ListSummaries(reportsDir); len(got) != 1 {
					t.Fatalf("duplicate application: %+v", got)
				}
			}
			assertHistory("running")
			if cancel {
				store.Cancel(list[0]["id"].(string))
			} else {
				release <- struct{}{}
			}
			waitJobsIdle(t, store)
			assertHistory(map[bool]string{false: "done", true: "cancelled"}[cancel])
		})
	}
}
