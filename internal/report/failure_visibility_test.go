package report

import (
	"regexp"
	"strings"
	"testing"

	"vhlocal/internal/consolidate"
)

// T071 (FR-020, C-C6): a failed scan is never presented as complete, and failures read as
// specific facts about unfinished work rather than as repeated qualifications hung on every
// supported vulnerability.
func TestFailuresReadAsUnfinishedWorkNotAsDoubtOnEveryIssue(t *testing.T) {
	in := fixture016Input(t)
	in.Doc.RunStatus.ExecutionStatus = consolidate.ExecAborted
	m := BuildModel(in)

	if m.Presentation.Scope.Execution == "Complete" {
		t.Fatal("an aborted run reads as complete")
	}
	md := renderMarkdownModel(in, m)
	h := renderHTMLModel(in, m)

	for name, body := range map[string]string{"markdown": md, "standalone html": h} {
		low := strings.ToLower(body)
		for _, bad := range []string{"scan completed successfully", "assessment complete", "run completed"} {
			if strings.Contains(low, bad) {
				t.Errorf("%s presents a failed run as complete: %q", name, bad)
			}
		}
		if !strings.Contains(body, "Stopped by an error") {
			t.Errorf("%s does not state that the run stopped on an error", name)
		}
	}

	// The qualification is stated once, in the scope note, not repeated per issue.
	if n := strings.Count(md, "This assessment is not exhaustive"); n != 1 {
		t.Errorf("the incompleteness note appears %d times, want once", n)
	}
	details := sectionOf(t, md, hdrDetails)
	hedges := []*regexp.Regexp{
		regexp.MustCompile(`(?i)because the scan did not complete`),
		regexp.MustCompile(`(?i)this may be unreliable because`),
		regexp.MustCompile(`(?i)treat this as a partial scan`),
	}
	for _, re := range hedges {
		if loc := re.FindString(details); loc != "" {
			t.Errorf("an issue detail repeats the run-level qualification: %q", loc)
		}
	}

	// The failure itself is a specific fact in the operator section, with its own numbers.
	diag := sectionOf(t, md, hdrScanDetail)
	if !strings.Contains(diag, "Needs review") && !strings.Contains(diag, "where review did not finish") {
		t.Error("Scan details does not quantify the unfinished work")
	}
	// Established issues keep their standing: an aborted run does not downgrade them.
	clean := fixture016Input(t)
	cm := BuildModel(clean)
	if len(m.Presentation.Issues) != len(cm.Presentation.Issues) {
		t.Errorf("an aborted execution changed the issue count from %d to %d",
			len(cm.Presentation.Issues), len(m.Presentation.Issues))
	}
	for i := range m.Presentation.Issues {
		if m.Presentation.Issues[i].Severity != cm.Presentation.Issues[i].Severity {
			t.Errorf("issue %s severity changed with the execution axis", m.Presentation.Issues[i].Ref)
		}
	}
}
