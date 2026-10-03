package logsetup

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestTaggedLinesAndSlice(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vhlocal.log")
	a, err := New(path, "scan-A", false, DEBUG)
	if err != nil {
		t.Fatal(err)
	}
	a.Info("hello from A")
	a.Warning("A warned")
	a.Close()

	b, _ := New(path, "scan-B", false, DEBUG)
	b.Info("hello from B")
	b.Close()

	// Slice to scan-A only.
	out, err := ReadLog(path, 0, "scan-A", DEBUG)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "[scan-A]") || strings.Contains(out, "[scan-B]") {
		t.Fatalf("scan-A slice leaked other tags:\n%s", out)
	}
	if strings.Count(out, "\n")+1 != 2 {
		t.Fatalf("expected 2 lines for scan-A, got:\n%s", out)
	}
}

func TestMinLevelFilterOnRead(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vhlocal.log")
	l, _ := New(path, "s", false, DEBUG)
	l.Debug("dbg")
	l.Info("inf")
	l.Error("err")
	l.Close()

	out, _ := ReadLog(path, 0, "", WARNING)
	if strings.Contains(out, "dbg") || strings.Contains(out, "inf") {
		t.Fatalf("WARNING+ filter leaked lower levels:\n%s", out)
	}
	if !strings.Contains(out, "err") {
		t.Fatalf("expected error line, got:\n%s", out)
	}
}

func TestReadMissingLogIsEmpty(t *testing.T) {
	out, err := ReadLog(filepath.Join(t.TempDir(), "nope.log"), 0, "", DEBUG)
	if err != nil || out != "" {
		t.Fatalf("missing log should be empty/no-error, got %q err=%v", out, err)
	}
}
