package report

import (
	"strings"
	"testing"
)

// T079 (FR-026, C-C10): "Coverage and limitations" states occurrences vs sessions
// vs stop reasons WITH the note that the three views do not sum to each other, so a
// reader cannot add them up. Absent for runs with no session record.
func TestCoverageRendersFailureOccurrencesVersusSessions(t *testing.T) {
	in := replayInput(t)
	if md := renderMarkdownModel(in, BuildModel(in)); strings.Contains(md, "### Verification failures") {
		t.Error("a run without session aggregates must not render a failure block")
	}
	in.Failures = &FailureAggregates{
		Sessions: 171, Calls: 940,
		// 3 occurrences across 2 sessions: the two views deliberately disagree.
		OccurrencesByClass: map[string]int{"invalid_submission": 3, "turn_exhaustion": 27},
		SessionsByClass:    map[string]int{"invalid_submission": 2, "turn_exhaustion": 27},
		StopReasons:        map[string]int{"complete": 58, "max_turns": 27, "tool_repair": 86},
		ExplicitUnresolved: 8, AmendedSessions: 2,
		OverlapNote: "Occurrences count every failure; sessions affected counts sessions with at least one failure of that class; " +
			"a session can appear under several classes and ends with exactly one stop reason, so these views do not sum to each other.",
	}
	m := BuildModel(in)
	md := renderMarkdownModel(in, m)
	h := renderHTMLModel(in, m)

	// Feature 016 (T036): the verification-failure block moved into "Scan details", where
	// scanner troubleshooting belongs. Every assertion below is unchanged.
	cov := sectionOf(t, md, hdrScanDetail)
	for _, want := range []string{
		"### Verification failures",
		"| Failure class | Occurrences | Sessions affected |",
		"| invalid_submission | 3 | 2 |", // occurrences != sessions, both shown
		"| turn_exhaustion | 27 | 27 |",
		"| Stop reason | Sessions |",
		"| max_turns | 27 |",
		"do not sum to each other",
		"verification_calls.jsonl",
		"**Explicit `unresolved` decisions**: 8",
		"a verifier judgement, not a failure",
		"**Sessions that amended a citation**: 2",
	} {
		if !strings.Contains(cov, want) {
			t.Errorf("markdown coverage section lacks %q", want)
		}
	}
	for _, want := range []string{
		">Verification failures</h3>",
		"<th>Occurrences</th><th>Sessions affected</th>",
		"do not sum to each other",
		"verification_calls.jsonl",
		"a verifier judgement, not a failure",
	} {
		if !strings.Contains(h, want) {
			t.Errorf("html lacks %q", want)
		}
	}
	// The block belongs to Coverage and limitations, never to the findings sections.
	if i, j := strings.Index(md, "### Verification failures"), strings.Index(md, "## Coverage and limitations"); i < j {
		t.Error("the failure block must sit inside Coverage and limitations")
	}
	// An older record with no note of its own still gets one.
	in.Failures.OverlapNote = ""
	if md2 := renderMarkdownModel(in, BuildModel(in)); !strings.Contains(md2, "do not sum to each other") {
		t.Error("a record without an overlap note must still disclose that the views do not sum")
	}
	// No failures recorded at all is stated, not left blank.
	in.Failures = &FailureAggregates{Sessions: 12, Calls: 40}
	if md3 := renderMarkdownModel(in, BuildModel(in)); !strings.Contains(md3, "No tool or submission failure was recorded") {
		t.Error("zero failures must be stated explicitly")
	}
}
