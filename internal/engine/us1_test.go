package engine

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"

	"vhlocal/internal/phases"
)

// C-1d: the built phase task grounds the agent — absolute repo path, writable
// results dir, assigned scope, the phase prompt, and the exact deliverable.
func TestBuildTaskGrounding(t *testing.T) {
	spec := phases.PhasesByKey["1"]
	task := buildTask("PROMPT-BODY-MARKER", spec, "/tmp/results", "/tmp/repo")
	for _, want := range []string{
		"/tmp/repo",
		"/tmp/results",
		"Assigned scope",
		"PROMPT-BODY-MARKER",
		filepath.Join("/tmp/results", spec.OutputFile),
	} {
		if !contains2(task, want) {
			t.Errorf("grounded task missing %q; task=\n%s", want, task)
		}
	}
}

type missingPromptSkill struct{}

func (missingPromptSkill) Preamble() string { return "" }
func (missingPromptSkill) Prompt(f string) (string, error) {
	return "", fmt.Errorf("no such prompt file: %s", f)
}

// C-1f: a missing/unreadable required prompt is an explicit configuration failure —
// the phase is skipped (no placeholder agent runs) and it surfaces as a degraded
// reason, rather than burning budget on a "(prompt unavailable)" placeholder.
func TestMissingPromptIsConfigFailureNotPlaceholder(t *testing.T) {
	repo := filepath.Join(repoRoot(t), "testdata", "vulnapp")
	results := t.TempDir()
	rec, err := Execute(context.Background(), brokenSpec(repo, results), Providers{Hunt: &pathWriter{model: "m"}}, missingPromptSkill{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range rec.Agents {
		if a.Model != "deterministic" {
			t.Errorf("model agent ran on a missing prompt: %+v", a)
		}
	}
	rs := runStatus(t, results)
	if !contains2(degradedReasons(rs), "configuration error") {
		t.Errorf("a missing prompt must surface a configuration error; reasons=%q", degradedReasons(rs))
	}
}

// C-5d (feature 005, FR-033): a fully-resumed run counts its valid resumed work as
// effective completion — it is not reported incomplete.
func TestResumeCountsValidWorkAsComplete(t *testing.T) {
	repo := filepath.Join(repoRoot(t), "testdata", "vulnapp")
	results := t.TempDir()
	prov := Providers{Hunt: &pathWriter{model: "m"}, Verify: verifyingProvider{verdict: "supported"}}
	spec := brokenSpec(repo, results)
	if _, err := Execute(context.Background(), spec, prov, staticSkill{}, nil); err != nil {
		t.Fatal(err)
	}
	spec.Resume = true
	rec, err := Execute(context.Background(), spec, prov, staticSkill{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(rec.PhasesSkipped) == 0 {
		t.Error("resume should skip completed phases")
	}
	rs := runStatus(t, results)
	if rs["execution_status"] == "incomplete" {
		t.Errorf("a fully-resumed run must not be incomplete; got %v (completed=%v)", rs["execution_status"], rec.PhasesCompleted)
	}
}
