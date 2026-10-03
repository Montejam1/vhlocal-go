// Command projctl prints the canonical semantic projection of a results directory
// as JSON — a helper for authoring and reviewing the parity golden (feature 006,
// US2, T005). Offline; reads only the on-disk artifacts.
//
// Usage: projctl <results-dir>
package main

import (
	"encoding/json"
	"fmt"
	"os"

	"vhlocal/tests/parity"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: projctl <results-dir>")
		os.Exit(2)
	}
	p, err := parity.Project(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, "project:", err)
		os.Exit(1)
	}
	b, _ := json.MarshalIndent(p, "", "  ")
	fmt.Println(string(b))
}
