package parity

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"vhlocal/internal/benchmark"
	"vhlocal/internal/engine"
	"vhlocal/tests/parity/transcript"
)

// This scripted provider knows the fixture answers; it measures plumbing, not
// discovery. Ground-truth identities must never be present in a model request.
func TestBenchmarkTranscriptIsolationAndBaseline(t *testing.T) {
	root := moduleRoot(t)
	truth, err := benchmark.LoadTruth(filepath.Join(root, "testdata/benchmark/truth/ground_truth.json"))
	if err != nil {
		t.Fatal(err)
	}
	repo := filepath.Join(root, truth.Target)
	out := t.TempDir()
	tr := &transcript.Transcript{PartitionTable: "## Subgraph Partitions\n\n| ID | Scope |\n|---|---|\n| SG-1 | pysvc/app.py gosvc/main.go web/server.js web/api.ts |\n"}
	hunt := transcript.HuntRule{Partition: "sg-1", Class: "all"}
	for i, e := range truth.Entries {
		loc := fmt.Sprintf("%s:%d", e.Anchor.File, e.Anchor.Lines[0])
		route := "non-HTTP source"
		for _, m := range e.AcceptableMatches {
			if m.Route != "" {
				route = m.Route
				break
			}
		}
		hunt.Findings = append(hunt.Findings, transcript.HuntFinding{ID: fmt.Sprintf("VULN-%03d", i+1), Title: "Fixture " + e.Family, CWE: e.CWE, Location: loc, EntryPoint: route, DataFlow: e.RootCause})
		verdict := "unresolved"
		if e.Language == "python" && e.Expected == "vulnerable" {
			verdict = "supported"
		}
		if e.Expected == "safe_control" {
			verdict = "rejected"
		}
		tr.Verify = append(tr.Verify, transcript.VerifyRule{Location: loc, Verdict: verdict, FuncStart: e.Anchor.Lines[0], FuncEnd: e.Anchor.Lines[1], EntryPoint: route, Rationale: "Scripted fixture decision; no live model inference"})
	}
	tr.Hunt = []transcript.HuntRule{hunt}
	enforce := false
	spec := engine.ScanSpec{Repo: repo, ResultsDir: out, Model: "transcript", Backend: "fake", Host: "fake://transcript", EngineVersion: "015-offline-fixture", NumCtx: 8192, MaxPartitions: 1, HuntSamples: 1, Phase2Mode: "combined", EnforceCoverage: &enforce, Phases: []string{"1", "2", "2b", "4"}}
	spec.EffectiveConfig = engine.BuildEffectiveConfig(map[string]any{}, spec)
	_, err = engine.Execute(context.Background(), spec, engine.Providers{Hunt: transcriptProvider{tr: tr}}, staticSkill{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	prompts, err := os.ReadFile(filepath.Join(out, "prompts.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range truth.Entries {
		if strings.Contains(string(prompts), e.ID) {
			t.Fatalf("truth id leaked: %s", e.ID)
		}
	}
	if strings.Contains(string(prompts), "ground_truth") {
		t.Fatal("ground truth path leaked")
	}
	scored, err := benchmark.Score(out, truth)
	if err != nil {
		t.Fatal(err)
	}
	if scored.Live || scored.Provider != "transcript" || scored.Supported.TP == 0 || len(scored.SafeControlFP) != 0 {
		t.Fatalf("bad offline score: %+v", scored)
	}
	// Stable identity fields: temporary paths and git state of the developer's
	// checkout are not claims about a released build or a live-model experiment.
	scored.ResultsDir = "offline-transcript-fixture"
	scored.Config.TargetRevision, err = engine.SourceFingerprint(repo)
	if err != nil {
		t.Fatal(err)
	}
	scored.Cost.Seconds = 0
	base := benchmark.NewBaseline("2026-09-29", benchmark.Policy{Version: "1"}, benchmark.Run{ResultsDir: scored.ResultsDir, Results: scored})
	file := filepath.Join(root, "testdata/benchmark/baseline/2026-09-29-offline.json")
	if os.Getenv("VHLOCAL_UPDATE_BENCH_BASELINE") == "1" {
		os.MkdirAll(filepath.Dir(file), 0755)
		b, _ := json.MarshalIndent(base, "", "  ")
		if err = os.WriteFile(file, append(b, '\n'), 0644); err != nil {
			t.Fatal(err)
		}
	}
	frozen, err := benchmark.LoadBaseline(file)
	if err != nil {
		t.Fatal(err)
	}
	if ds := benchmark.Compare(scored, frozen, benchmark.Policy{Version: "1"}); len(ds) != 0 {
		t.Fatalf("offline regression: %+v", ds)
	}
	if len(benchmark.ConfigDiff(scored.Config, frozen.Config)) != 0 {
		t.Fatal("baseline config changed; regenerate and review explicitly")
	}
	actual, _ := json.Marshal(scored)
	want, _ := json.Marshal(frozen.Results)
	if string(actual) != string(want) {
		t.Fatal("offline scored result differs from frozen golden; review any baseline update explicitly")
	}
	if frozen.Live || frozen.Provider != "transcript" {
		t.Fatal("offline baseline mislabeled")
	}
}
