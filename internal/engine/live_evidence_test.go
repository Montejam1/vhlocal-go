package engine

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"vhlocal/internal/config"
	"vhlocal/internal/logsetup"
)

// Feature 014 (SC-001, T015): while the scan is still RUNNING, a real artifact, a
// prompt record, and a scan-tagged log line already exist on disk (the API/UI read
// exactly these files), each within 5 s of being produced.
func TestLiveEvidenceExistsWhileRunning(t *testing.T) {
	repo := filepath.Join(repoRoot(t), "testdata", "vulnapp")
	results := t.TempDir()
	spec := brokenSpec(repo, results)
	spec.Phases = []string{"1"} // one phase is enough to observe the window
	spec.LogTag = "job-live-1"
	dw := newDelayedWriter()

	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = Execute(context.Background(), spec, Providers{Hunt: dw}, staticSkill{}, nil)
	}()
	select {
	case <-dw.wrote:
	case <-time.After(5 * time.Second):
		t.Fatal("agent never issued its Write")
	}

	// Within 5 s of the write, all three evidence kinds must exist — job still running.
	deadline := time.Now().Add(5 * time.Second)
	var haveArtifact, havePrompt, haveLog bool
	for time.Now().Before(deadline) && !(haveArtifact && havePrompt && haveLog) {
		if fi, err := os.Stat(filepath.Join(results, "phase1_output.md")); err == nil && fi.Size() > 0 {
			haveArtifact = true
		}
		if b, err := os.ReadFile(filepath.Join(results, "prompts.jsonl")); err == nil && strings.Contains(string(b), `"phase":"1"`) {
			havePrompt = true
		}
		if txt, _ := logsetup.ReadLog(config.LogFile(), 0, "job-live-1", logsetup.DEBUG); strings.Contains(txt, "phase_start") {
			haveLog = true
		}
		time.Sleep(20 * time.Millisecond)
	}
	select {
	case <-done:
		t.Fatal("scan finished before evidence was checked — the window was not live")
	default:
	}
	if !haveArtifact {
		t.Error("artifact not on disk while running")
	}
	if !havePrompt {
		t.Error("prompt record not on disk while running (prompts.jsonl with phase 1)")
	}
	if !haveLog {
		t.Error("scan-tagged log line not written while running")
	}
	dw.Release()
	<-done
}
