package report

import (
	"fmt"
	"strings"
	"testing"

	"vhlocal/internal/consolidate"
)

// T024 (C-A7, C-A8, FR-007, FR-008): index rows and finding details carry the
// structured fields; evidence renders as code with a path:start-end caption;
// missing fix/evidence are stated; candidates live in Appendix A with reasons and
// actions; per-agent rows are not in the main body.
func TestIndexRowsAndFindingDetails(t *testing.T) {
	in := replayInput(t)
	m := BuildModel(in)
	// Feature 016 (T036): this test describes the per-detection index of the legacy
	// document, which feature 016 replaces with a per-issue index. The legacy renderer is
	// still what a report saved before this feature renders through (FR-026, C-C7), so
	// every assertion below is kept and read from that path. The new document's rows,
	// anchors and deep links are asserted in anchors_test.go and document_order_test.go.
	md := renderMarkdownLegacy(in, m)
	for _, row := range m.Index {
		if row.ID == "" || row.Title == "" || row.Severity == "" || row.Surface == "" || row.Anchor != "finding-"+row.ID {
			t.Errorf("index row incomplete: %+v", row)
		}
		switch row.EvidenceStatus {
		case EvidenceCaptured, EvidenceMissing, NotVerified:
		default:
			t.Errorf("row %s evidence_status %q", row.ID, row.EvidenceStatus)
		}
		if !strings.Contains(md, "(#"+row.Anchor+")") || !strings.Contains(md, `<a id="`+row.Anchor+`"></a>`) {
			t.Errorf("row %s lacks a working anchor in Markdown", row.ID)
		}
	}
	// Evidence excerpts as fenced code with captions.
	withEv := 0
	for _, f := range m.Findings {
		for _, e := range f.Evidence {
			cap := fmt.Sprintf("`%s:%d-%d`", e.Path, e.Start, e.End)
			if !strings.Contains(md, cap) {
				t.Errorf("%s: evidence caption %s missing", f.ID, cap)
			}
			withEv++
		}
	}
	if withEv == 0 {
		t.Fatal("fixture has no evidence")
	}
	if !strings.Contains(md, "  ```\n") {
		t.Error("evidence must render as fenced code")
	}
	// Appendix A rows carry reason + action; failed rows carry a class.
	appA := sectionBetween(md, "## Appendix A — Candidates", "## Appendix B — Execution")
	if !strings.Contains(appA, "### Rejected candidates") || !strings.Contains(appA, "### Unresolved (explicit decision)") || !strings.Contains(appA, "### Unresolved (session failed)") {
		t.Error("Appendix A headings missing")
	}
	if !strings.Contains(appA, "· action: ") || !strings.Contains(appA, "[invalid_submission]") {
		t.Error("Appendix A rows must carry actions and failure classes")
	}
	// Per-agent rows only in Appendix B.
	body := md[:strings.Index(md, "## Appendix B — Execution")]
	if strings.Contains(body, "| hunt:sg-") {
		t.Error("per-agent rows leaked into the main body")
	}
	// Explicit unresolved rows are distinct from failed sessions.
	if len(m.Appendix.UnresolvedExplicit) != 8 || len(m.Appendix.UnresolvedFailed) != 113 {
		t.Errorf("explicit/failed split = %d/%d", len(m.Appendix.UnresolvedExplicit), len(m.Appendix.UnresolvedFailed))
	}
}

func TestMissingFixAndEvidenceAreExplicit(t *testing.T) {
	in := Input{Target: "t", Doc: consolidate.Doc{
		RunStatus: consolidate.RunStatus{ExecutionStatus: "complete", CoverageStatus: "complete", ValidationMode: "static_reasoning"},
		Findings: []map[string]any{{
			"id": "CAND-1", "title": "No fix, no evidence", "severity": "High", "severity_rank": 1,
			"location": "a.py:3", "verification_status": "supported", "from_confirmed": true,
		}},
	}}
	// Feature 016 (T036): "fix not provided" is exactly the phrasing FR-015 removes from
	// the reader-facing document, so these assertions now describe the legacy path, which
	// still renders pre-016 models. The new document's wording is asserted in US2.
	m0 := BuildModel(in)
	md := renderMarkdownLegacy(in, m0)
	h := renderHTMLLegacy(in, m0)
	for _, want := range []string{"- **Recommended fix**: not provided", "- **Captured evidence**: none (not verified)"} {
		if !strings.Contains(md, want) {
			t.Errorf("markdown lacks %q", want)
		}
	}
	for _, want := range []string{"<dt>Recommended fix</dt><dd>not provided</dd>", "<dt>Captured evidence</dt><dd>none (not verified)</dd>"} {
		if !strings.Contains(h, want) {
			t.Errorf("html lacks %q", want)
		}
	}
	m := BuildModel(in)
	if m.Index[0].EvidenceStatus != EvidenceMissing || m.Index[0].Action != "fix not provided" {
		t.Errorf("index row = %+v", m.Index[0])
	}
}
