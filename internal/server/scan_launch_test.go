package server

import (
	"bytes"
	"context"
	"encoding/json"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	vhlocal "vhlocal"
	"vhlocal/internal/jobs"
)

// Cached pre-fix forms must still enqueue a scan when their legacy controls
// request exactly the behavior the engine implements. Never call a live model.
func TestScanLaunchLegacyDefaults(t *testing.T) {
	root := t.TempDir()
	ran := make(chan map[string]any, 1)
	store, err := jobs.NewStore(filepath.Join(root, "jobs.json"), func(_ context.Context, spec map[string]any, _ func(map[string]any)) (string, error) {
		ran <- spec
		return "", nil
	})
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{cfg: Config{AllowRoots: []string{root}}, store: store}
	payload := map[string]any{
		"repo": root, "model": "offline", "backend": "ollama", "phases": "all",
		"max_partitions": 8, "seed_routes": false, "seed_prior": false,
		"enforce_coverage": true, "concurrency": 1, "ledger": false,
	}
	b, _ := json.Marshal(payload)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/api/scans", bytes.NewReader(b)))
	if w.Code != http.StatusCreated {
		t.Fatalf("default form rejected: %d %s", w.Code, w.Body.String())
	}
	select {
	case spec := <-ran:
		if spec["repo"] != root || spec["model"] != "offline" {
			t.Fatalf("wrong queued scan: %v", spec)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("accepted scan never reached the runner")
	}
}

// Genuinely invalid values (and options whose behavior is not yet implemented)
// MUST still be rejected before queuing, with an actionable field-specific error.
// Feature 013: concurrency>1 and enforce_coverage=false are NO LONGER here — their
// behavior is implemented and they are accepted (see TestScanLaunchAcceptsImplementedOptions).
// Feature 013 (FR-024, SC-008): launching with the full set of now-functional
// options queues the scan and PERSISTS those options in the job config (verified
// via the runner's spec, not a copied payload) — for the shape all forms submit.
func TestPerFormLaunchPersistsOptions(t *testing.T) {
	root := t.TempDir()
	ran := make(chan map[string]any, 1)
	store, err := jobs.NewStore(filepath.Join(root, "jobs.json"), func(_ context.Context, spec map[string]any, _ func(map[string]any)) (string, error) {
		ran <- spec
		return "", nil
	})
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{cfg: Config{AllowRoots: []string{root}}, store: store}
	payload := map[string]any{
		"repo": root, "model": "offline", "backend": "ollama", "phases": "all",
		"max_partitions": 8,
		// The feature-013 controls every form now submits:
		"concurrency": 3, "enforce_coverage": false, "seed_routes": true, "seed_prior": true,
	}
	b, _ := json.Marshal(payload)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/api/scans", bytes.NewReader(b)))
	if w.Code != http.StatusCreated {
		t.Fatalf("launch rejected: %d %s", w.Code, w.Body.String())
	}
	select {
	case spec := <-ran:
		if spec["concurrency"] != float64(3) {
			t.Errorf("concurrency not persisted in job config: %v", spec["concurrency"])
		}
		if spec["enforce_coverage"] != false {
			t.Errorf("enforce_coverage=false not persisted: %v", spec["enforce_coverage"])
		}
		if spec["seed_routes"] != true || spec["seed_prior"] != true {
			t.Errorf("seed_* not persisted: %v / %v", spec["seed_routes"], spec["seed_prior"])
		}
	case <-time.After(3 * time.Second):
		t.Fatal("accepted scan never reached the runner")
	}
	waitJobsIdle(t, store) // worker's final persist must land before TempDir cleanup
}

// waitJobsIdle waits until no job is queued/running (avoids a TempDir cleanup race
// with the store worker's final persist).
func waitJobsIdle(t *testing.T, store *jobs.Store) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if _, busy := store.List(); !busy {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestScanLaunchRejectsUnimplementedBehavior(t *testing.T) {
	for key, values := range map[string][]any{
		// seed_routes / seed_prior are implemented (accept booleans); non-booleans reject.
		"seed_routes": {"false", nil, []any{false}},
		"seed_prior":  {"false", nil, []any{true}},
		// enforce_coverage accepts booleans; a non-boolean is rejected field-specifically.
		"enforce_coverage": {"true", nil, 1.0},
		// concurrency accepts a whole number in [1,8]; these are all invalid.
		"concurrency": {0, 9, 1.5, "1", nil},
	} {
		for _, value := range values {
			b, _ := json.Marshal(map[string]any{"repo": "/unused", key: value})
			w := httptest.NewRecorder()
			// Rejection must happen before queue submission or source access.
			(&Server{}).Handler().ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/api/scans", bytes.NewReader(b)))
			if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), key) {
				t.Errorf("%s=%v: expected actionable rejection, got %d %s", key, value, w.Code, w.Body.String())
			}
		}
	}
}

// Feature 013 (FR-013/FR-012, SC-008): options whose behavior is implemented are
// accepted by the validator (they must fail later ONLY on the unrelated repo
// check, never with an option-specific rejection). concurrency=2 is the reported
// regression that passes only now that bounded parallelism is real.
func TestScanLaunchAcceptsImplementedOptions(t *testing.T) {
	for _, tc := range []struct {
		key   string
		value any
	}{
		{"concurrency", 2.0},
		{"concurrency", 8.0},
		{"enforce_coverage", false},
		{"enforce_coverage", true},
		{"seed_routes", true},
		{"seed_routes", false},
		{"seed_prior", true},
		{"seed_prior", false},
	} {
		b, _ := json.Marshal(map[string]any{"repo": "/unused", tc.key: tc.value})
		w := httptest.NewRecorder()
		(&Server{}).Handler().ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/api/scans", bytes.NewReader(b)))
		// Validation must pass; the request then fails on the repo check, NOT on the option.
		if strings.Contains(w.Body.String(), tc.key) {
			t.Errorf("%s=%v: implemented option was rejected: %d %s", tc.key, tc.value, w.Code, w.Body.String())
		}
	}
}

// Check the actual embedded forms, not a copied list of expected payload keys.
// This catches another UI control being added without a matching API option.
func TestShippedScanFormOptionContract(t *testing.T) {
	web, err := fs.Sub(vhlocal.WebFS, "vhlocal/web")
	if err != nil {
		t.Fatal(err)
	}
	payloadRE := regexp.MustCompile(`(?s)const payload = \{(.*?)\n  \};`)
	keyRE := regexp.MustCompile(`(?m)(?:^|,)\s*([a-z_]+)\s*:`)
	for _, name := range []string{"index.html", "index.classic.html", "index.legacy.html"} {
		t.Run(name, func(t *testing.T) {
			b, err := fs.ReadFile(web, name)
			if err != nil {
				t.Fatal(err)
			}
			form := payloadRE.FindSubmatch(b)
			if len(form) != 2 {
				t.Fatal("cannot locate scan payload; update the contract test for the form structure")
			}
			keys := keyRE.FindAllSubmatch(form[1], -1)
			if len(keys) < 5 {
				t.Fatal("scan payload keys were not extracted")
			}
			for _, match := range keys {
				if key := string(match[1]); !supportedScanOptions[key] {
					t.Errorf("form submits unsupported/fixed option %q", key)
				}
			}
			// Feature 013 (FR-023): these controls are IMPLEMENTED, so they must be
			// re-enabled (never disabled) and their keys submitted in the payload.
			for _, id := range []string{"seedRoutes", "enforceCoverage", "concurrency"} {
				input := regexp.MustCompile(`<input\b[^>]*\bid="` + id + `"[^>]*>`).Find(b)
				if input == nil {
					t.Errorf("control %s is missing from the form", id)
					continue
				}
				if regexp.MustCompile(`\sdisabled(?:\s|>|=)`).Match(input) {
					t.Errorf("implemented control %s must be re-enabled, not disabled", id)
				}
			}
			// The functional keys must be submitted (all forms).
			for _, key := range []string{"concurrency", "enforce_coverage", "seed_routes"} {
				if !regexp.MustCompile(`(?m)(?:^|,)\s*` + key + `\s*:`).Match(form[1]) {
					t.Errorf("form does not submit the %s option", key)
				}
			}
		})
	}
}
