package report

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"vhlocal/internal/consolidate"
)

func sampleInput() Input {
	f := consolidate.NewFinding("VULN-001")
	f.CWE, f.Severity, f.Title, f.Location = "CWE-89", "High", "SQLi in <search>", "app/db.py:42"
	f.Classification = consolidate.ClassStaticallySupported
	findings := consolidate.Prepare([]consolidate.Finding{f})
	doc := consolidate.Build(findings, consolidate.Options{
		EngineVersion: "0.1.0", HuntModel: "gpt-oss:120b",
		Status: consolidate.ComputeRunStatus(consolidate.StatusInput{
			PhasesRequested: []string{"1", "2"}, PhasesCompleted: []string{"1", "2"},
			CoverageKnown: true, CoverageComplete: false, NotReviewed: 3,
		}),
	})
	return Input{
		Target: "vulnapp", Model: "gpt-oss:120b", Host: "http://localhost:11434",
		StartedAt: "2026-09-14 10:00", FinishedAt: "2026-09-14 10:30", Duration: "30m",
		Doc: doc, CodeExecuted: false, VerifyModelUsed: false,
	}
}

func TestRenderMarkdownHasSectionsAndHonesty(t *testing.T) {
	md := RenderMarkdown(sampleInput())
	// Feature 016 (T036): the section names changed with the redesign — scanner facts
	// moved into "Scan details" and the findings list became "Issues to fix". Every
	// honesty assertion is kept; only the heading and label text follows the new document.
	for _, want := range []string{
		"## Scan summary", "## Run status (three independent axes)", "**Execution**:",
		"**Coverage**:", "**Assessment method**:", "## Issues to fix", "VULN-001",
		"never executed", "same model",
	} {
		if !strings.Contains(md, want) {
			t.Errorf("markdown missing %q", want)
		}
	}
}

func TestRenderHTMLSelfContained(t *testing.T) {
	h := RenderHTML(sampleInput())
	// No external resource references (offline guarantee, FR-008).
	for _, bad := range []string{"src=\"http", "href=\"http", "//cdn", "googleapis", "http-equiv=\"refresh"} {
		if strings.Contains(h, bad) {
			t.Errorf("HTML has external/dynamic reference %q", bad)
		}
	}
	// Interactive controls + filtered banner logic present.
	for _, want := range []string{"Save as PDF", "applyFilter", "Filtered view — showing", "beforeprint"} {
		if !strings.Contains(h, want) {
			t.Errorf("HTML missing %q", want)
		}
	}
	// Finding title is HTML-escaped (served artifact must be inert, FR-025).
	if strings.Contains(h, "SQLi in <search>") {
		t.Error("finding title not escaped")
	}
	if !strings.Contains(h, "SQLi in &lt;search&gt;") {
		t.Error("expected escaped title")
	}
	// Three axes rendered.
	// Feature 016 (T036): the validation axis is labelled "Assessment method" for readers;
	// the recorded value is still shown beside it. All three axes must still be present.
	if !strings.Contains(h, "Execution:") || !strings.Contains(h, "Coverage:") || !strings.Contains(h, "Assessment method:") {
		t.Error("three status axes not all rendered")
	}
}

func TestWriteBothFiles(t *testing.T) {
	dir := t.TempDir()
	md, htmlP, err := Write(sampleInput(), dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{md, htmlP} {
		if _, err := os.Stat(p); err != nil {
			t.Errorf("missing %s: %v", p, err)
		}
	}
	if filepath.Base(md) != "SCAN_REPORT.md" || filepath.Base(htmlP) != "SCAN_REPORT.html" {
		t.Errorf("names: %s %s", md, htmlP)
	}
}
