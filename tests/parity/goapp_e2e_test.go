package parity

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"vhlocal/internal/engine"
	"vhlocal/tests/parity/transcript"
)

// TestGoAppEndToEndVerificationIntoReport is the Go integration checkpoint (feature
// 012, #2/#3): discovered Go entry points reach hunt assignments, and supported /
// rejected / unresolved candidates flow through verification into the published
// report and findings.json. Fully offline (scripted transcript + fake providers;
// no live model, no network, no Go toolchain). Reproduction (phase 3) is out of
// scope for this checkpoint and is not run.
func TestGoAppEndToEndVerificationIntoReport(t *testing.T) {
	repo := filepath.Join(moduleRoot(t), "testdata", "goapp")
	tr, err := transcript.Load(filepath.Join(moduleRoot(t), "tests", "parity", "transcript", "goapp.json"))
	if err != nil {
		t.Fatal(err)
	}
	out := t.TempDir()
	p := transcriptProvider{tr: tr}
	spec := engine.ScanSpec{
		Repo: repo, ResultsDir: out, Model: "fixture", Backend: "ollama", Host: "fake",
		NumCtx: 8192, MaxPartitions: 8, Phases: []string{"1", "2", "2b", "4"}, QualityStrictness: "balanced",
	}
	if _, err := engine.Execute(context.Background(), spec, engine.Providers{Hunt: p, Verify: p, Reproduce: p}, staticSkill{}, nil); err != nil {
		t.Fatalf("engine.Execute: %v", err)
	}

	// (#2) findings.json carries the Go candidates with their verification outcomes.
	b, err := os.ReadFile(filepath.Join(out, "findings.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Findings []map[string]any `json:"findings"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	byStatus := map[string]int{}
	goFindings := 0
	for _, f := range doc.Findings {
		loc, _ := f["location"].(string)
		if !strings.HasPrefix(loc, "api/routes.go:") {
			continue
		}
		goFindings++
		vs, _ := f["verification_status"].(string)
		byStatus[vs]++
	}
	if goFindings == 0 {
		t.Fatal("no Go candidates reached findings.json — discovery did not flow into hunt/verification")
	}
	for _, want := range []string{"supported", "rejected", "unresolved"} {
		if byStatus[want] == 0 {
			t.Errorf("expected at least one %q Go candidate in findings.json; got statuses %v", want, byStatus)
		}
	}

	// (#2) The published report exists and references the supported finding's route.
	rep, err := os.ReadFile(filepath.Join(out, "SCAN_REPORT.md"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(rep), "/users/{id}") {
		t.Error("published report does not reference the supported Go finding's route")
	}

	// (#3 / #4) A sibling route with no supported finding must not be falsely marked
	// reviewed; coverage must not be reported complete.
	cb, err := os.ReadFile(filepath.Join(out, "coverage_ledger.json"))
	if err != nil {
		t.Fatal(err)
	}
	var cl struct {
		Complete bool `json:"complete"`
		Entries  []struct {
			Path        string `json:"path"`
			Disposition string `json:"disposition"`
			Language    string `json:"language"`
		} `json:"entries"`
	}
	if err := json.Unmarshal(cb, &cl); err != nil {
		t.Fatal(err)
	}
	if cl.Complete {
		t.Error("coverage marked complete while Go routes remain unreviewed (honesty)")
	}
	var sawHealth, anyGo bool
	for _, e := range cl.Entries {
		if e.Language == "go" {
			anyGo = true
		}
		if e.Path == "/health" {
			sawHealth = true
			if e.Disposition == "finding_emitted" || e.Disposition == "reviewed_no_issue" {
				t.Errorf("/health falsely marked %q with no supported finding in its handler", e.Disposition)
			}
		}
	}
	if !anyGo {
		t.Error("coverage ledger contains no Go routes")
	}
	if !sawHealth {
		t.Error("coverage ledger missing the /health route")
	}
}
