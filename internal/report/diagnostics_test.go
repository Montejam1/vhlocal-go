package report

import (
	"regexp"
	"strings"
	"testing"
)

const hdrDiagnostics = "### Technical diagnostics"

// T070 (FR-019, C-C4, C-C5): the operator's troubleshooting material is present under
// "Technical diagnostics" — failure classes, stop reasons, per-call records, provider and
// model provenance with credentials redacted, configuration, phase detail, raw statuses,
// tool errors, candidate identifiers and recovery flags — collapsed in the interactive view
// and excluded from the default print body.
func TestTechnicalDiagnosticsArePresentAndSeparated(t *testing.T) {
	in := replayInput(t)
	// The per-call aggregates exist only when the run recorded verification sessions, so the
	// corpus for this test carries them, as a real verified run does.
	in.Failures = &FailureAggregates{
		Sessions: 87, OccurrencesByClass: map[string]int{"invalid_submission": 3, "turn_exhaustion": 27},
		SessionsByClass: map[string]int{"invalid_submission": 2, "turn_exhaustion": 27},
		StopReasons:     map[string]int{"complete": 58, "max_turns": 27},
		OverlapNote:     "Occurrences count every failure; sessions affected counts sessions with at least one failure of that class.",
	}
	m := BuildModel(in)
	md := renderMarkdownModel(in, m)

	at := strings.Index(md, hdrDiagnostics)
	if at < 0 {
		t.Fatalf("the report has no %q section", hdrDiagnostics)
	}
	diag := md[at:]

	wants := []struct{ what, pattern string }{
		{"a verification failure class", `\[(?:invalid_submission|turn_exhaustion|tool_envelope|invalid_tool_args)\]|\| (?:invalid_submission|turn_exhaustion) \|`},
		{"stop reasons", `(?i)stop reason`},
		{"the per-call record reference", `verification_calls\.jsonl`},
		{"the model that produced the candidates", `(?i)\*\*Model\*\*|\bModel:`},
		{"the inference endpoint", `(?i)inference endpoint`},
		{"a credentials statement", `(?i)credential`},
		{"configuration", `(?i)### Configuration|\*\*Code execution\*\*`},
		{"phase detail", `(?i)\| Phase \|`},
		{"the raw recorded statuses", "recorded as `"},
		{"candidate identifiers", `CAND-[0-9a-f]{8}`},
		{"recovery steps", `(?i)recovery`},
	}
	for _, w := range wants {
		re := regexp.MustCompile(w.pattern)
		if !re.MatchString(diag) {
			t.Errorf("Technical diagnostics lacks %s (/%s/)", w.what, w.pattern)
		}
	}

	// None of it precedes the vulnerability content.
	if at < strings.Index(md, hdrIssues) {
		t.Error("Technical diagnostics appears before the issues to fix")
	}
	// And none of it is in the opening.
	opening := md[:strings.Index(md, hdrIssues)]
	for _, bad := range []string{"verification_calls.jsonl", "turn_exhaustion", "Stop reason", "Recovery"} {
		if strings.Contains(opening, bad) {
			t.Errorf("the opening carries the diagnostic %q", bad)
		}
	}

	// Credentials are never recorded, whatever the endpoint URL carried.
	withCreds := in
	withCreds.Host = "http://operator:s3cr3t-token@127.0.0.1:11434"
	mc := BuildModel(withCreds)
	for name, body := range map[string]string{
		"markdown":        renderMarkdownModel(withCreds, mc),
		"standalone html": renderHTMLModel(withCreds, mc),
	} {
		if strings.Contains(body, "s3cr3t-token") {
			t.Errorf("%s leaked a credential from the endpoint URL", name)
		}
		if strings.Contains(body, "operator:") {
			t.Errorf("%s leaked endpoint userinfo", name)
		}
		if !strings.Contains(body, "127.0.0.1:11434") {
			t.Errorf("%s dropped the endpoint host while redacting", name)
		}
	}

	// Interactive: collapsed. Print: excluded from the default body.
	h := renderHTMLModel(in, m)
	if !strings.Contains(h, `<details id="technical-diagnostics"`) {
		t.Error("Technical diagnostics is not a collapsed section in the html")
	}
	if !regexp.MustCompile(`@media print\{[^}]*`).MatchString(h) {
		t.Fatal("the html has no print stylesheet")
	}
	if !strings.Contains(h, `#technical-diagnostics{display:none}`) {
		t.Error("the default print body does not exclude Technical diagnostics")
	}
	// An operator can still print it deliberately.
	if !strings.Contains(h, `value="diagnostics"`) {
		t.Error("there is no export scope that includes the diagnostics")
	}
}
