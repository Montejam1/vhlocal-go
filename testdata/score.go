//go:build ignore

// score.go — recall + negative-control scorer for the bundled vulnapp fixture.
// Usage: go run ./testdata/score.go <results-dir>
//
// It reads <results-dir>/findings.json and checks, against the five planted bugs
// and the one decoy in testdata/ground_truth/vulnapp.json, which vulnerability
// classes were found and whether the negative control was wrongly reported.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type finding struct {
	CWEFamily   string `json:"cwe_family"`
	NormCWE     string `json:"normalized_cwe"`
	Location    string `json:"location"`
	EntryPoint  string `json:"entry_point"`
	DataFlow    string `json:"data_flow"`
	Title       string `json:"title"`
	DuplicateOf any    `json:"duplicate_of"`
}

type doc struct {
	Findings []finding `json:"findings"`
}

// planted class -> (family key, a location/keyword hint).
var planted = []struct {
	name, family, hint string
}{
	{"SQL injection (q, status → execute)", "sql-injection", "db.py"},
	{"Path traversal (name → open)", "path-traversal", "files.py"},
	{"Command injection (src → os.system)", "command-injection", "files.py"},
	{"Broken access control (orders/<id>)", "access-control", "main.py"},
}

func main() {
	fmt.Fprintln(os.Stderr, "DEPRECATED: this legacy candidate-recall scorer is not an efficacy measure. Use vhlocal bench efficacy --results <dir> --truth <v2-truth.json> for supported-only precision/recall and safe controls.")
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: go run ./testdata/score.go <results-dir>")
		os.Exit(2)
	}
	b, err := os.ReadFile(filepath.Join(os.Args[1], "findings.json"))
	if err != nil {
		fmt.Fprintln(os.Stderr, "cannot read findings.json:", err)
		os.Exit(2)
	}
	var d doc
	if err := json.Unmarshal(b, &d); err != nil {
		fmt.Fprintln(os.Stderr, "invalid findings.json:", err)
		os.Exit(2)
	}

	var live []finding
	for _, f := range d.Findings {
		if f.DuplicateOf == nil {
			live = append(live, f)
		}
	}

	found := 0
	fmt.Println("Recall against planted bugs:")
	for _, p := range planted {
		hit := false
		for _, f := range live {
			blob := strings.ToLower(f.CWEFamily + " " + f.NormCWE + " " + f.Location + " " + f.DataFlow + " " + f.Title)
			if (f.CWEFamily == p.family || strings.Contains(blob, strings.ReplaceAll(p.family, "-", " "))) &&
				strings.Contains(blob, p.hint) {
				hit = true
				break
			}
		}
		mark := "MISS"
		if hit {
			mark = "found"
			found++
		}
		fmt.Printf("  [%-5s] %s\n", mark, p.name)
	}

	// Negative control: anything on the /api/users → find_user_safe path is a FP.
	decoyReported := false
	for _, f := range live {
		blob := strings.ToLower(f.Location + " " + f.EntryPoint + " " + f.DataFlow + " " + f.Title)
		if strings.Contains(blob, "find_user_safe") || strings.Contains(blob, "/api/users") {
			decoyReported = true
			fmt.Printf("  [DECOY] FALSE POSITIVE reported: %s @ %s\n", f.Title, f.Location)
		}
	}

	fmt.Printf("\nClass recall: %d/%d\n", found, len(planted))
	if decoyReported {
		fmt.Println("Negative control: FAILED (decoy reported)")
		os.Exit(1)
	}
	fmt.Println("Negative control: PASS (decoy not reported)")
}
