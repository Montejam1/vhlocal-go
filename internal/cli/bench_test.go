package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"vhlocal/internal/benchmark"
)

func TestEfficacyCLIRejectsMissingInputs(t *testing.T) {
	if got := benchDispatch([]string{"efficacy", "--json"}); got != ExitUsage {
		t.Fatalf("exit = %d", got)
	}
}

func TestEfficacyCLIComparisonAndRegression(t *testing.T) {
	root := t.TempDir()
	repo := filepath.Join(root, "target")
	os.Mkdir(repo, 0700)
	os.WriteFile(filepath.Join(repo, "app.py"), []byte("eval(input())\n"), 0600)
	write := func(name string, v any) {
		t.Helper()
		b, _ := json.Marshal(v)
		if e := os.WriteFile(filepath.Join(root, name), b, 0600); e != nil {
			t.Fatal(e)
		}
	}
	truth := benchmark.Truth{Version: 2, Entries: []benchmark.Entry{{ID: "v1", Language: "python", CWE: "CWE-95", Family: "code-injection", Expected: "vulnerable", Anchor: benchmark.Anchor{File: "app.py", Lines: [2]int{1, 1}}}}}
	write("truth.json", truth)
	write("scan_meta.json", map[string]any{"repo": repo, "backend": "fake", "model": "fixture"})
	write("findings.json", map[string]any{"findings": []any{map[string]any{"id": "V1", "location": "app.py:1", "cwe": "CWE-95", "verification_status": "supported"}}})
	scored, e := benchmark.Score(root, truth)
	if e != nil {
		t.Fatal(e)
	}
	write("baseline.json", benchmark.NewBaseline("fixture", benchmark.Policy{Version: "1"}, benchmark.Run{Results: scored}))
	for _, regression := range []bool{false, true} {
		if regression {
			write("findings.json", map[string]any{"findings": []any{}})
		}
		f, e := os.CreateTemp(t.TempDir(), "stdout")
		if e != nil {
			t.Fatal(e)
		}
		old := os.Stdout
		os.Stdout = f
		code := benchDispatch([]string{"efficacy", "--results", root, "--truth", filepath.Join(root, "truth.json"), "--baseline", filepath.Join(root, "baseline.json"), "--json"})
		os.Stdout = old
		f.Close()
		b, _ := os.ReadFile(f.Name())
		if (code == 1) != regression || code == ExitUsage {
			t.Fatalf("regression %t exit %d output %s", regression, code, b)
		}
		if !strings.HasPrefix(strings.TrimSpace(string(b)), "{\n  \"config_diff\"") {
			t.Fatal("configuration differences must print first")
		}
	}
}
