package report

import (
	"regexp"
	"strings"
	"testing"

	"vhlocal/internal/consolidate"
)

// T023 (SC-006, FR-005, FR-020, C-P10, C-C6): every recorded status combination renders
// honestly. The corpus covers complete, incomplete, zero-finding with review complete,
// zero-finding with review partial, cancelled, interrupted, unknown coverage,
// unresolved-only, and a historical run whose status the record never captured.
//
// Each case asserts the counts it should show and that the report fabricates no scan
// success, security assurance, severity score, or executed test.
func TestStatusCorpusRendersHonestly(t *testing.T) {
	cases := []struct {
		name string
		// mutate shapes the records for this case.
		mutate func(t *testing.T, in *Input)
		// wantIssues is -1 when the case keeps the fixture's own count.
		wantIssues int
		wantScope  string
		// wantPhrase is a reader-facing fact the case must state.
		wantPhrase string
	}{
		{
			name:       "complete run with findings",
			mutate:     func(t *testing.T, in *Input) { in.Doc.RunStatus.ExecutionStatus = consolidate.ExecComplete },
			wantIssues: -1, wantScope: "Complete",
		},
		{
			name:       "incomplete run with findings",
			mutate:     func(t *testing.T, in *Input) { in.Doc.RunStatus.ExecutionStatus = consolidate.ExecPartial },
			wantIssues: -1, wantScope: "Incomplete", wantPhrase: "not completed",
		},
		{
			name: "zero findings, review complete",
			mutate: func(t *testing.T, in *Input) {
				*in = zeroFindingInput(t, consolidate.ExecComplete)
			},
			wantIssues: 0, wantScope: "Complete",
		},
		{
			name: "zero findings, review partial",
			mutate: func(t *testing.T, in *Input) {
				*in = zeroFindingInput(t, consolidate.ExecPartial)
			},
			wantIssues: 0, wantScope: "Incomplete", wantPhrase: "not completed",
		},
		{
			name:       "cancelled run",
			mutate:     func(t *testing.T, in *Input) { in.Doc.RunStatus.ExecutionStatus = consolidate.ExecCancelled },
			wantIssues: -1, wantScope: "Cancelled",
		},
		{
			name:       "interrupted run",
			mutate:     func(t *testing.T, in *Input) { in.Doc.RunStatus.ExecutionStatus = "interrupted" },
			wantIssues: -1, wantScope: "Interrupted",
		},
		{
			name: "coverage never recorded",
			mutate: func(t *testing.T, in *Input) {
				in.Coverage = nil
			},
			wantIssues: -1, wantScope: "Incomplete",
		},
		{
			name: "unresolved candidates only",
			mutate: func(t *testing.T, in *Input) {
				keepOnlyClasses(in, consolidate.ClassUnresolvedExplicit, consolidate.ClassUnresolvedFailed)
				in.Groups = nil
			},
			wantIssues: 0, wantScope: "Incomplete", wantPhrase: "Needs review",
		},
		{
			name: "historical run with no recorded status",
			mutate: func(t *testing.T, in *Input) {
				in.Doc.RunStatus.ExecutionStatus = ""
				in.Doc.RunStatus.ValidationMode = ""
			},
			wantIssues: -1, wantScope: "Unknown",
		},
	}

	// Patterns for the four things no status combination may produce.
	fabrications := []struct {
		name string
		re   *regexp.Regexp
	}{
		{"a fabricated scan success", regexp.MustCompile(`(?i)\bscan (?:succeeded|completed successfully)\b|\bfully (?:reviewed|assessed)\b`)},
		{"a security assurance", regexp.MustCompile(`(?i)\bis secure\b|\bno vulnerabilities\b|\ball clear\b|\bzero risk\b`)},
		{"a fabricated severity score", regexp.MustCompile(`(?i)\b(?:CVSS|risk score|severity score)[\s:]*v?[0-9]`)},
		{"an executed test claim", regexp.MustCompile(`(?i)\btests? (?:passed|were executed|ran)\b|\bexploit (?:succeeded|verified by execution)\b`)},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := fixture016Input(t)
			tc.mutate(t, &in)
			m := BuildModel(in)
			p := m.Presentation
			if p == nil {
				t.Fatal("no presentation projection")
			}
			if tc.wantIssues >= 0 && p.Counts.IssuesToFix != tc.wantIssues {
				t.Errorf("issues to fix = %d, want %d", p.Counts.IssuesToFix, tc.wantIssues)
			}
			if p.Scope.Execution != tc.wantScope {
				t.Errorf("execution reads %q, want %q", p.Scope.Execution, tc.wantScope)
			}
			// The severity split always sums to the headline, including when it is zero.
			sum := 0
			for _, s := range DisplaySeverities {
				sum += p.Counts.Severity[s]
			}
			if sum != p.Counts.IssuesToFix {
				t.Errorf("severity split sums to %d but the headline is %d", sum, p.Counts.IssuesToFix)
			}

			bodies := map[string]string{
				"markdown":        renderMarkdownModel(in, m),
				"standalone html": renderHTMLModel(in, m),
			}
			for name, body := range bodies {
				for _, f := range fabrications {
					if loc := f.re.FindString(body); loc != "" {
						t.Errorf("%s contains %s: %q", name, f.name, loc)
					}
				}
				if tc.wantPhrase != "" && !strings.Contains(body, tc.wantPhrase) {
					t.Errorf("%s does not state %q", name, tc.wantPhrase)
				}
				// Every case offers the reader something to do next.
				if !strings.Contains(body, hdrPriority) && !strings.Contains(body, "Priority actions") &&
					!strings.Contains(body, "Next step") {
					t.Errorf("%s offers no next action", name)
				}
			}
		})
	}
}

// keepOnlyClasses filters the recorded findings down to the given classes, leaving each
// record otherwise untouched so nothing is invented.
func keepOnlyClasses(in *Input, classes ...consolidate.Class) {
	want := map[consolidate.Class]bool{}
	for _, c := range classes {
		want[c] = true
	}
	kept := make([]map[string]any, 0, len(in.Doc.Findings))
	counts := map[consolidate.Class]int{}
	for _, f := range in.Doc.Findings {
		cls := consolidate.Classify(f)
		if want[cls] {
			kept = append(kept, f)
			counts[cls]++
		}
	}
	in.Doc.Findings = kept
	in.Doc.ClassCounts = counts
	in.Doc.SeveritySupported = map[string]int{}
}
