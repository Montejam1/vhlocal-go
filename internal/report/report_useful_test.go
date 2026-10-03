package report

import (
	"strings"
	"testing"

	"vhlocal/internal/consolidate"
)

func usefulDoc() consolidate.Doc {
	supported := map[string]any{
		"id": "CAND-sup", "title": "SQL injection in search", "severity": "High", "severity_rank": 2,
		"cwe": "CWE-89", "location": "app/db.py:21", "entry_point": "ROUTE /api/search",
		"data_flow": "q -> execute()", "classification": consolidate.ClassStaticallySupported,
		"verification_status": "supported", "from_confirmed": true, "duplicate_of": nil, "fix": "parameterize",
		"verification_record": map[string]any{
			"entry_point": "ROUTE /api/search", "attacker_control": "q query parameter",
			"preconditions": "none", "defenses_reviewed": "none observed",
			"security_impact": "database read/write", "rationale": "term concatenated into SQL",
			"evidence": []any{map[string]any{"path": "app/db.py", "start_line": 18, "end_line": 22}},
		},
	}
	rejected := map[string]any{
		"id": "CAND-rej", "title": "Path traversal", "severity": "Medium", "severity_rank": 3,
		"cwe": "CWE-22", "location": "app/files.py:10", "classification": consolidate.ClassHypothesis,
		"verification_status": "rejected", "verification_reason": "confined under INVOICE_DIR", "duplicate_of": nil,
	}
	unresolved := map[string]any{
		"id": "CAND-unr", "title": "Possible IDOR", "severity": "Medium", "severity_rank": 3,
		"cwe": "CWE-639", "location": "app/api.py:5", "classification": consolidate.ClassHypothesis,
		"verification_status": "unresolved", "verification_reason": "no decision submitted — session ended: max_turns",
		"duplicate_of": nil,
	}
	return consolidate.Doc{
		Findings: []map[string]any{supported, rejected, unresolved},
		Counts:   map[string]int{"High": 1, "Medium": 2},
		RunStatus: consolidate.RunStatus{
			ExecutionStatus: "complete", CoverageStatus: "complete", ValidationMode: "static_reasoning",
		},
	}
}

func usefulInput() Input {
	return Input{
		Target: "vulnapp", Model: "m", Host: "h", Doc: usefulDoc(),
		Nav:   []NavLink{{Label: "Threat model", Path: "threat_model.md"}, {Label: "SBOM", Path: "sbom.cdx.json"}},
		Repro: map[string]map[string]any{"CAND-sup": {"candidate_id": "CAND-sup", "kind": "test", "path": "exploit_tests/CAND-sup.py", "status": "authored"}},
	}
}

// CB-15/CB-16/CB-17 (US6): supported-first, separated sections, full review detail,
// no candidate-total-as-confirmed.
//
// Feature 016 (T036): this describes the legacy document in full — "## Findings" with a
// "### CAND-" section per detection and an Appendix A. The legacy renderer still produces
// it for a report saved before feature 016 (FR-026, C-C7), so every assertion is kept and
// read from that path. The new document's per-issue reader sections, which carry the same
// recorded review detail, are built and asserted in User Story 2 (T037-T053).
func TestReportSupportedFirstWithDetail(t *testing.T) {
	in0 := usefulInput()
	md := renderMarkdownLegacy(in0, BuildModel(in0))

	// Feature 015 layout: supported findings under "## Findings" (### per finding),
	// rejected/unresolved candidates in Appendix A.
	iSup := strings.Index(md, "## Findings\n")
	iCov := strings.Index(md, "## Coverage and limitations")
	iRej := strings.Index(md, "### Rejected candidates")
	iUnr := strings.Index(md, "### Unresolved (explicit decision)")
	if iSup < 0 || iCov < 0 || iRej < 0 || iUnr < 0 {
		t.Fatalf("missing sections: sup=%d cov=%d rej=%d unr=%d", iSup, iCov, iRej, iUnr)
	}
	if !(iSup < iRej && iSup < iUnr) {
		t.Errorf("supported findings must lead the report")
	}
	// CB-16: full review detail for the supported finding.
	supBlock := md[iSup:iCov]
	for _, want := range []string{"### CAND-sup", "q query parameter", "Attacker prerequisites", "Reviewed defenses",
		"database read/write", "term concatenated into SQL", "app/db.py:18-22", "authored test", "ROUTE /api/search"} {
		if !strings.Contains(supBlock, want) {
			t.Errorf("supported detail missing %q", want)
		}
	}
	// The rejected candidate must NOT appear in the supported section.
	if strings.Contains(supBlock, "CAND-rej") {
		t.Errorf("rejected candidate leaked into the supported section")
	}
	// CB-17: no conflation of candidate total with confirmed count.
	if !strings.Contains(md, "not a confirmed-vulnerability count") {
		t.Errorf("report must state that a candidate total is not a confirmed count")
	}
	// Navigation present (FR-032).
	if !strings.Contains(md, "threat_model.md") || !strings.Contains(md, "sbom.cdx.json") {
		t.Errorf("navigation links to intelligence artifacts missing")
	}
}

// CB-20 (US7, FR-035): the report surfaces requested-vs-actual partitions and
// documents that max_partitions caps the model plan (not the total).
func TestReportPartitionTransparency(t *testing.T) {
	in := usefulInput()
	in.Doc.Meta = map[string]any{
		"max_partitions": float64(8), "partitions": []any{"SG-1", "SG-2"},
		"partition_source": "model_table", "coverage_partitions_added": []any{"SG-3"},
		"threat_model_partitions": []any{"SG-4", "SG-5"},
	}
	md := RenderMarkdown(in)
	for _, want := range []string{"requested cap 8", "resolved 2", "model_table", "+1 coverage", "+2 threat-model", "caps the model's plan"} {
		if !strings.Contains(md, want) {
			t.Errorf("partition transparency line missing %q", want)
		}
	}
}

// CB-18 / T041: Markdown, HTML, and the machine-readable count agree on the number
// of supported findings.
func TestReportRenderingsAgree(t *testing.T) {
	in := usefulInput()
	md := RenderMarkdown(in)
	htmlOut := RenderHTML(in)
	legacyMD := renderMarkdownLegacy(in, BuildModel(in))
	legacyHTML := renderHTMLLegacy(in, BuildModel(in))

	// Machine-readable truth: supported findings in the doc.
	jsonSupported := 0
	for _, f := range in.Doc.Findings {
		if isSupported(f) {
			jsonSupported++
		}
	}
	if jsonSupported != 1 {
		t.Fatalf("fixture should have 1 supported finding, got %d", jsonSupported)
	}
	// Feature 016 (T036): the reader-facing label for this quantity is "Supported
	// detections", recorded in Scan details; the count itself is unchanged.
	if !strings.Contains(md, "- **Supported detections**: 1") {
		t.Errorf("markdown detection count disagrees")
	}
	if !strings.Contains(htmlOut, "<b>Supported detections</b>: 1") {
		t.Errorf("html detection count disagrees")
	}
	// Both renderings stay traceable to the detection that established the issue.
	if !strings.Contains(md, "CAND-sup") || !strings.Contains(htmlOut, "CAND-sup") {
		t.Errorf("the new document lost the backing detection id")
	}
	// The recorded review detail is still rendered by the legacy path; US2 brings it into
	// the new document's five reader sections.
	if !strings.Contains(legacyMD, "database read/write") || !strings.Contains(legacyHTML, "database read/write") {
		t.Errorf("legacy rendering lost the recorded review detail")
	}
}
