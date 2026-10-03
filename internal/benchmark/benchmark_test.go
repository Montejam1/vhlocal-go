package benchmark

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func writeFixture(t *testing.T, dir, name string, value any) {
	t.Helper()
	b, e := json.Marshal(value)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(dir, name), b, 0600); e != nil {
		t.Fatal(e)
	}
}

func TestSupportedScoringAndNegativeControls(t *testing.T) {
	dir := t.TempDir()
	repo := t.TempDir()
	os.WriteFile(filepath.Join(repo, "app.py"), []byte("def bad():\n return eval(input())\ndef safe():\n return 1\ndef missed():\n return eval(input())\n"), 0600)
	truth := Truth{Version: 2, Target: repo, Entries: []Entry{
		{ID: "v1", Language: "python", Family: "code-injection", CWE: "CWE-95", Expected: "vulnerable", Anchor: Anchor{File: "app.py", Lines: [2]int{1, 2}}},
		{ID: "v2", Language: "python", Family: "code-injection", CWE: "CWE-95", Expected: "vulnerable", Anchor: Anchor{File: "app.py", Lines: [2]int{5, 6}}},
		{ID: "safe", Language: "python", Family: "code-injection", CWE: "CWE-95", Expected: "safe_control", Anchor: Anchor{File: "app.py", Lines: [2]int{3, 4}}},
	}}
	mk := func(id, loc, status string) map[string]any {
		return map[string]any{"id": id, "location": loc, "cwe": "CWE-95", "normalized_cwe": "CWE-95", "cwe_family": "code-injection", "verification_status": status}
	}
	dup := mk("dup", "app.py:6", "supported")
	dup["duplicate_of"] = "a"
	rows := []map[string]any{mk("a", "app.py:2", "supported"), mk("repeat", "app.py:2", "supported"), mk("safe-hit", "app.py:4", "supported"), mk("unresolved", "app.py:6", "unresolved"), mk("rejected", "app.py:6", "rejected"), dup}
	writeFixture(t, dir, "scan_meta.json", map[string]any{"repo": repo, "backend": "ollama", "model": "m"})
	writeFixture(t, dir, "findings.json", map[string]any{"findings": rows})
	writeFixture(t, dir, "candidate_manifest.json", map[string]any{"candidates": []any{map[string]any{"id": "candidate", "finding": map[string]any{"location": "app.py:6", "cwe": "CWE-95"}}}})
	r, err := Score(dir, truth)
	if err != nil {
		t.Fatal(err)
	}
	if r.Supported.TP != 1 || r.Supported.FP != 1 || r.Supported.FN != 1 || r.Supported.Precision != .5 || r.Supported.Recall != .5 || len(r.SafeControlFP) != 1 {
		t.Fatalf("incorrect scoring: %+v", r)
	}
	if r.Cost.USD != float64(0) || r.PerLanguage["python"].Denominator != 2 {
		t.Fatalf("bad cost/denominator: %+v", r)
	}
	if r.CandidateRecall.Matched != 1 || r.CandidateRecall.Total != 2 || r.PerFamily["code-injection"].FP != 1 {
		t.Fatalf("candidate recall/family: %+v", r)
	}
	writeFixture(t, dir, "scan_meta.json", map[string]any{"repo": repo, "backend": "unpriced", "model": "m"})
	r, _ = Score(dir, truth)
	if r.Cost.USD != "unknown" {
		t.Fatal("fabricated cost")
	}
	base := NewBaseline("fixture", Policy{Version: "1"}, Run{Results: r})
	r.Supported.Recall = 0
	if len(Compare(r, base, Policy{Version: "1"})) == 0 {
		t.Fatal("missed recall regression")
	}
}

func TestWrongWeaknessAtSameLineIsNotDetection(t *testing.T) {
	dir, repo := t.TempDir(), t.TempDir()
	os.WriteFile(filepath.Join(repo, "a.py"), []byte("eval(input())\n"), 0600)
	writeFixture(t, dir, "scan_meta.json", map[string]any{"repo": repo})
	writeFixture(t, dir, "findings.json", map[string]any{"findings": []any{map[string]any{"id": "wrong", "location": "a.py:1", "verification_status": "supported", "normalized_cwe": "CWE-22", "cwe_family": "path-traversal"}}})
	r, e := Score(dir, Truth{Version: 2, Entries: []Entry{{ID: "code", CWE: "CWE-95", Family: "code-injection", Expected: "vulnerable", Anchor: Anchor{File: "a.py", Lines: [2]int{1, 1}}}}})
	if e != nil {
		t.Fatal(e)
	}
	if r.Supported.TP != 0 || r.Supported.FP != 1 {
		t.Fatalf("wrong weakness credited: %+v", r.Supported)
	}
}
