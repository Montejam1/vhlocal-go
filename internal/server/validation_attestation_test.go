package server

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// This checks documentation/source labels, not browser behavior.
func TestValidationDistinguishesSourceChecksFromBrowserEvidence(t *testing.T) {
	root := filepath.Join("..", "..")
	for _, name := range []string{"report_form_test.go", "diagram_form_test.go"} {
		b, e := os.ReadFile(name)
		if e != nil {
			t.Fatal(e)
		}
		if !strings.Contains(string(b), "not browser verification") {
			t.Fatalf("%s overstates source checks", name)
		}
	}
	b, e := os.ReadFile(filepath.Join(root, "specs/015-analyst-reports-efficacy/quickstart.md"))
	if e != nil {
		t.Fatal(e)
	}
	for _, label := range []string{"attested", "machine_executed", "not run", "browser / version"} {
		if !strings.Contains(string(b), label) {
			t.Fatalf("validation report lacks %q", label)
		}
	}
}
