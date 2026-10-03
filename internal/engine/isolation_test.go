package engine

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// statSig is a cheap change signature for a file (size + mtime), or "" if absent.
func statSig(p string) string {
	fi, err := os.Stat(p)
	if err != nil {
		return ""
	}
	return fi.ModTime().UTC().Format(time.RFC3339Nano) + "|" + itoa(fi.Size())
}

func itoa(n int64) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	if neg {
		b = append([]byte{'-'}, b...)
	}
	return string(b)
}

// Feature 014 (FR-027, SC-011): running the engine on a temp repo must write
// NOTHING to the operator's real stores. This is the regression that would have
// caught the ~100 KB of /tmp/Test…/001 entries the engine tests had been leaking
// into the real ~/.vhlocal/applications.json. It also proves registration still
// happens — just into the isolated root.
func TestExecuteNeverWritesToRealOperatorStores(t *testing.T) {
	if origHome == "" || isolatedHome == "" {
		t.Fatal("TestMain isolation did not run")
	}
	realRegistry := filepath.Join(origHome, ".vhlocal", "applications.json")
	realJobs := filepath.Join(origHome, ".vhlocal", "jobs.json")
	realLog := filepath.Join(origHome, ".vhlocal", "vhlocal.log")
	before := map[string]string{
		realRegistry: statSig(realRegistry), realJobs: statSig(realJobs), realLog: statSig(realLog),
	}

	repo := filepath.Join(repoRoot(t), "testdata", "vulnapp")
	if _, err := Execute(context.Background(), brokenSpec(repo, t.TempDir()),
		Providers{Hunt: &pathWriter{model: "m"}}, staticSkill{}, nil); err != nil {
		t.Fatal(err)
	}

	for p, sig := range before {
		if got := statSig(p); got != sig {
			t.Errorf("engine test leaked into the REAL operator store %s (before=%q after=%q)", p, sig, got)
		}
	}
	// Registration was redirected, not suppressed: the isolated registry exists.
	isolated := filepath.Join(isolatedHome, ".vhlocal", "applications.json")
	if statSig(isolated) == "" {
		t.Errorf("expected registration to land in the isolated root %s", isolated)
	}
}
