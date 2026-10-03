package report

import (
	"encoding/json"
	"regexp"
	"strings"
	"testing"
)

// T016 (FR-009, C-P14): the report invents no score, no external identifier, no host
// attribute and no claim that an exploit succeeded. A reference template having such a
// field is not a reason to populate one; the field is omitted instead.
//
// The check runs over the generated artifacts rather than the source, so a value that
// reaches a reader through any renderer is caught. Recorded text the scan itself wrote
// is exempt only where the model genuinely recorded it, which for this corpus is nowhere.
func TestGeneratedArtifactsFabricateNothing(t *testing.T) {
	in := fixture016Input(t)
	m := BuildModel(in)
	projection, err := json.Marshal(m.Presentation)
	if err != nil {
		t.Fatal(err)
	}
	// The recorded inference endpoint is provenance that Principle IV requires the report
	// to carry, so it is removed before the asset-attribute patterns run. What C-P14 bars
	// is presenting the SCANNED TARGET as a network host, which a source-code scanner has
	// no basis for; it does not bar recording which endpoint served the scan.
	strip := func(body string) string {
		if h := strings.TrimSpace(in.Host); h != "" {
			body = strings.ReplaceAll(body, h, "[recorded inference endpoint]")
			if u := strings.TrimPrefix(strings.TrimPrefix(h, "https://"), "http://"); u != "" && u != h {
				body = strings.ReplaceAll(body, u, "[recorded inference endpoint]")
				if host, _, found := strings.Cut(u, ":"); found && host != "" {
					body = strings.ReplaceAll(body, host, "[recorded inference endpoint]")
				}
			}
		}
		return body
	}
	artifacts := map[string]string{
		"presentation projection": strip(string(projection)),
		"markdown":                strip(renderMarkdownModel(in, m)),
		"standalone html":         strip(renderHTMLModel(in, m)),
	}

	// Patterns for things the record cannot support. Each is a shape, not a word, so a
	// legitimate mention in recorded prose does not trip it.
	forbidden := []struct {
		name string
		re   *regexp.Regexp
	}{
		{"a CVSS score", regexp.MustCompile(`(?i)\bCVSS[\s:]*v?[0-9]`)},
		{"a CVSS vector", regexp.MustCompile(`(?i)\bAV:[NALP]/AC:`)},
		{"a CVE identifier", regexp.MustCompile(`\bCVE-\d{4}-\d{4,}\b`)},
		{"a vendor advisory identifier", regexp.MustCompile(`(?i)\b(?:GHSA-[a-z0-9-]{10,}|RHSA-\d|MS\d{2}-\d{3})\b`)},
		{"a vendor plugin or check id", regexp.MustCompile(`(?i)\b(?:plugin|qid)[\s:#]*\d{3,}`)},
		{"an exploitation likelihood score", regexp.MustCompile(`(?i)\b(?:EPSS|exploit probability|likelihood score)\b`)},
		{"a business risk score", regexp.MustCompile(`(?i)\b(?:risk score|business risk)[\s:]*\d`)},
		{"a host or network asset attribute", regexp.MustCompile(`(?i)\b(?:NetBIOS|MAC address|operating system fingerprint)\b`)},
		{"an IPv4 asset address", regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)},
		{"an open port claim", regexp.MustCompile(`(?i)\bport\s+\d{1,5}/(?:tcp|udp)\b`)},
		{"a successful exploit claim", regexp.MustCompile(`(?i)\b(?:exploit (?:succeeded|was successful)|successfully exploited|proven exploitable by execution)\b`)},
	}
	for artifact, body := range artifacts {
		for _, f := range forbidden {
			if loc := f.re.FindString(body); loc != "" {
				t.Errorf("%s contains %s: %q", artifact, f.name, loc)
			}
		}
	}
}

// T016 (FR-016, C-R3): nothing claims a fix was applied or a test executed. Suggested
// checks are suggestions until a record says otherwise.
func TestGeneratedArtifactsClaimNoExecution(t *testing.T) {
	in := fixture016Input(t)
	m := BuildModel(in)
	bodies := map[string]string{
		"markdown":        renderMarkdownModel(in, m),
		"standalone html": renderHTMLModel(in, m),
	}
	forbidden := []*regexp.Regexp{
		regexp.MustCompile(`(?i)\btests? (?:passed|all pass|were executed|ran successfully)\b`),
		regexp.MustCompile(`(?i)\b(?:fix|patch) (?:was )?(?:applied|verified by execution)\b`),
		regexp.MustCompile(`(?i)\bwe (?:ran|executed) (?:the )?(?:target|application|exploit)\b`),
	}
	for name, body := range bodies {
		for _, re := range forbidden {
			if loc := re.FindString(body); loc != "" {
				t.Errorf("%s claims execution: %q", name, loc)
			}
		}
	}
	// The static-only boundary is stated, not merely implied.
	md := bodies["markdown"]
	if !strings.Contains(md, "never executed") && !strings.Contains(strings.ToLower(md), "source-code analysis") {
		t.Error("the report must state that the assessment was static")
	}
}

// T016 (FR-005, C-P10): with review incomplete, nothing reads as an all-clear. This
// corpus is a partial scan, so no reassuring conclusion is permitted anywhere.
func TestIncompleteScanOffersNoAllClear(t *testing.T) {
	in := fixture016Input(t)
	m := BuildModel(in)
	if m.Presentation.Scope.Execution == "Complete" {
		t.Fatal("fixture precondition: this corpus records an incomplete run")
	}
	bodies := map[string]string{
		"markdown":        renderMarkdownModel(in, m),
		"standalone html": renderHTMLModel(in, m),
	}
	for name, body := range bodies {
		low := strings.ToLower(body)
		for _, phrase := range []string{"all clear", "no vulnerabilities found", "the application is secure", "zero risk", "clean bill of health"} {
			if strings.Contains(low, phrase) {
				t.Errorf("%s offers an all-clear conclusion on an incomplete scan: %q", name, phrase)
			}
		}
	}
}
