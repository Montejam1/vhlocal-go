package engine

import (
	"context"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"vhlocal/internal/config"
	"vhlocal/internal/logsetup"
)

var reLogLine = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T[^ ]+ (DEBUG|INFO|WARNING|ERROR|CRITICAL) \[[^\]]+\] `)

// Feature 014 (FR-006/007, T017): a run writes scan-tagged operational lines —
// phase/agent transitions, stop reasons, output writes, terminal outcome — readable
// by tag; every line is well formed even with concurrent hunt units (-race); the
// planted credential never appears.
func TestScanLogWrittenTaggedAndWellFormed(t *testing.T) {
	repo := filepath.Join(repoRoot(t), "testdata", "vulnapp")
	spec := brokenSpec(repo, t.TempDir())
	spec.LogTag = "job-log-77"
	spec.Host = "http://svc:SECRETPW-77@h"
	spec.Concurrency = 3
	if _, err := Execute(context.Background(), spec, Providers{Hunt: &pathWriter{model: "m"}}, staticSkill{}, nil); err != nil {
		t.Fatal(err)
	}
	txt, err := logsetup.ReadLog(config.LogFile(), 0, "job-log-77", logsetup.DEBUG)
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(txt) == "" {
		t.Fatal("no scan-tagged log lines written")
	}
	lines := strings.Split(txt, "\n")
	for _, ln := range lines {
		if !reLogLine.MatchString(ln) {
			t.Errorf("malformed/interleaved log line: %q", ln)
		}
	}
	for _, want := range []string{"phase_start", "agent_stop", "output_written", "terminal"} {
		if !strings.Contains(txt, want) {
			t.Errorf("log lacks %q event", want)
		}
	}
	if strings.Contains(txt, "SECRETPW") {
		t.Error("planted credential leaked into the scan log")
	}
	// Another tag must not see these lines.
	other, _ := logsetup.ReadLog(config.LogFile(), 0, "job-other", logsetup.DEBUG)
	if strings.Contains(other, "phase_start") {
		t.Error("lines leaked across scan tags")
	}
}
