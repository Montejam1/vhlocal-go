package report

import (
	"html"
	"strings"
	"testing"
)

// T077 (FR-021, C-P26): the Markdown and the standalone HTML tell the same story for the
// frozen fixture — the same issues, the same totals, the same guidance and the same status
// facts. Both read the one projection, so a disagreement here means a renderer invented
// something.
func TestMarkdownAndHTMLAgreeOnEveryIssue(t *testing.T) {
	in := fixture016Input(t)
	m := BuildModel(in)
	p := m.Presentation
	md := renderMarkdownModel(in, m)
	h := renderHTMLModel(in, m)
	esc := html.EscapeString

	for _, is := range p.Issues {
		ref := strings.ToLower(is.Ref)
		// Membership: the same detections under the same issue on both surfaces.
		for _, mem := range is.Members {
			if !strings.Contains(md, mem.FindingID) {
				t.Errorf("markdown omits detection %s of %s", mem.FindingID, is.Ref)
			}
			if !strings.Contains(h, esc(mem.FindingID)) {
				t.Errorf("html omits detection %s of %s", mem.FindingID, is.Ref)
			}
		}
		// Identity: title, severity and the stable reference.
		if !strings.Contains(md, is.Title) || !strings.Contains(h, esc(is.Title)) {
			t.Errorf("%s title missing from a surface", is.Ref)
		}
		if !strings.Contains(md, "### "+is.Severity+" — ") {
			t.Errorf("%s severity heading missing from the markdown", is.Ref)
		}
		if !strings.Contains(h, `id="`+ref+`"`) {
			t.Errorf("%s anchor missing from the html", is.Ref)
		}
		// Guidance: the same provenance label and the same first step.
		if is.HowToFixIt.Label != "" {
			if !strings.Contains(md, is.HowToFixIt.Label) || !strings.Contains(h, esc(is.HowToFixIt.Label)) {
				t.Errorf("%s guidance label differs across surfaces", is.Ref)
			}
		}
		if len(is.HowToFixIt.Steps) > 0 {
			step := is.HowToFixIt.Steps[0]
			if !strings.Contains(md, step) || !strings.Contains(h, esc(step)) {
				t.Errorf("%s first remediation step differs across surfaces", is.Ref)
			}
		}
	}

	// Totals: every reader-facing figure appears on both surfaces.
	c := p.Counts
	for _, n := range []int{c.IssuesToFix, c.NeedsReview, c.Dismissed, c.Detections, c.CandidatesExamined} {
		s := itoa016(n)
		if !strings.Contains(md, s) {
			t.Errorf("markdown lacks the figure %s", s)
		}
		if !strings.Contains(h, s) {
			t.Errorf("html lacks the figure %s", s)
		}
	}
	for _, sev := range DisplaySeverities {
		if !strings.Contains(md, sev) || !strings.Contains(h, sev) {
			t.Errorf("the severity category %s is missing from a surface", sev)
		}
	}

	// Status facts: the scope note, word for word.
	if !strings.Contains(md, p.Opening.ScopeSentence) {
		t.Error("the markdown scope sentence differs from the projection")
	}
	if !strings.Contains(h, esc(p.Opening.ScopeSentence)) {
		t.Error("the html scope sentence differs from the projection")
	}
	// Needs review and dismissed items appear on both.
	for _, it := range p.ReviewItems {
		if !strings.Contains(md, it.Title) || !strings.Contains(h, esc(it.Title)) {
			t.Errorf("review item %s missing from a surface", it.Ref)
		}
	}
	for _, d := range p.Dismissed {
		if !strings.Contains(md, d.Title) || !strings.Contains(h, esc(d.Title)) {
			t.Errorf("dismissed record %s missing from a surface", d.Ref)
		}
	}
}

// T080 (SC-010, C-P23, C-P25): the default body carries one detail section per primary
// issue — 34 for this fixture, not the 49 detections — with no per-detection duplicate and
// no execution appendix, while every original detection and diagnostic fact stays reachable.
func TestDefaultBodyHasOneSectionPerIssue(t *testing.T) {
	base := loadFixture016Baseline(t)
	in := fixture016Input(t)
	m := BuildModel(in)
	md := renderMarkdownModel(in, m)

	details := sectionOf(t, md, hdrDetails)
	n := strings.Count(details, "\n### ")
	if n != base.ExpectedAfter.DetailSections {
		t.Errorf("detail sections = %d, want %d (before this feature: %d)",
			n, base.ExpectedAfter.DetailSections, base.Document.DetailSections)
	}
	if n >= base.Document.DetailSections {
		t.Errorf("detail sections did not reduce: %d against a %d baseline", n, base.Document.DetailSections)
	}
	// No per-detection duplicate: a detection id heads no section of its own.
	if strings.Contains(details, "\n### CAND-") {
		t.Error("a detection has its own detail section")
	}
	// Every detection is still reachable inside the issue it belongs to.
	for _, is := range m.Presentation.Issues {
		for _, mem := range is.Members {
			if !strings.Contains(details, mem.FindingID) {
				t.Errorf("detection %s is not reachable in the issue details", mem.FindingID)
			}
		}
	}
	// No execution appendix in the default reading flow; the tables live under diagnostics.
	if strings.Contains(md, "## Appendix B") || strings.Contains(md, "## Appendix A") {
		t.Error("the redesigned document still carries the feature-015 appendices")
	}
	if i := strings.Index(md, "| Phase | Agents |"); i >= 0 && i < strings.Index(md, hdrDiagnostics) {
		t.Error("the per-phase execution table appears outside Technical diagnostics")
	}
	// And the diagnostics facts are still there to be found.
	for _, fact := range []string{"Candidates examined", "Recorded statuses", "Technical diagnostics"} {
		if !strings.Contains(md, fact) {
			t.Errorf("the diagnostic fact %q is no longer reachable", fact)
		}
	}
	// SC-010 measures consolidation, not length: the reduction must come from merging
	// detections and relocating diagnostics, never from dropping content. The document is
	// NOT required to be shorter in lines, and this one is not — it carries real
	// remediation guidance per issue where the 2,777-line baseline carried "fix not
	// provided" 54 times, and every relocated diagnostic stayed in the file. What must
	// hold is that each detection is counted once and nothing was deleted.
	seen := map[string]int{}
	for _, is := range m.Presentation.Issues {
		for _, mem := range is.Members {
			seen[mem.FindingID]++
		}
	}
	for id, n := range seen {
		if n != 1 {
			t.Errorf("detection %s is counted %d times across issues", id, n)
		}
	}
	if len(seen) != base.Counts.SupportedDetections {
		t.Errorf("issues account for %d detections, records say %d", len(seen), base.Counts.SupportedDetections)
	}
	// Every recorded evidence excerpt is still in the document.
	excerpts := 0
	for _, is := range m.Presentation.Issues {
		for _, e := range is.Evidence {
			excerpts++
			if !strings.Contains(md, e.Path) {
				t.Errorf("evidence excerpt %s:%d-%d was dropped", e.Path, e.Start, e.End)
			}
		}
	}
	if excerpts == 0 {
		t.Fatal("fixture precondition: no evidence excerpts")
	}
}
