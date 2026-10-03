package report

import (
	"regexp"
	"strings"
	"testing"

	"vhlocal/internal/guidance"
)

// T043 (FR-014, C-R1, C-R2, C-P24): resolution order is recorded, then general, then
// investigate; a recorded recommendation is never overwritten by the family table; every
// recommendation declares its provenance; and "fix not provided" never appears as an
// action. The baseline for this corpus is 54 occurrences of that phrase.
func TestGuidanceResolutionOrderAndProvenance(t *testing.T) {
	base := loadFixture016Baseline(t)
	in := fixture016Input(t)
	m := BuildModel(in)
	p := m.Presentation
	if len(p.Issues) == 0 {
		t.Fatal("fixture established no issues")
	}

	valid := map[string]bool{
		guidance.ProvRecorded: true, guidance.ProvGeneral: true, guidance.ProvInvestigate: true,
	}
	investigated := 0
	for _, is := range p.Issues {
		r := is.HowToFixIt
		if !valid[r.Provenance] {
			t.Errorf("%s: provenance %q is not one of recorded, general, investigate", is.Ref, r.Provenance)
		}
		if len(r.Steps) == 0 {
			t.Errorf("%s: no remediation steps at all", is.Ref)
		}
		if r.Label == "" {
			t.Errorf("%s: the reader is not told where this advice came from", is.Ref)
		}
		if !strings.Contains(r.Label, "implemented or tested") {
			t.Errorf("%s: the label does not disclose that nothing was implemented or tested: %q", is.Ref, r.Label)
		}
		if r.Provenance == guidance.ProvInvestigate {
			investigated++
		}
	}
	// The fixture carries weaknesses in no known family, so the investigate branch is
	// exercised — if it were never reached, this test would prove nothing about it.
	if investigated == 0 {
		t.Error("no issue took the investigate branch; the fixture's unfamilied weaknesses were silently given family advice")
	}

	// Recorded guidance is used as recorded. This corpus records no fixes at all, which is
	// why the before-state said "fix not provided" 54 times; assert that precondition
	// rather than assuming it.
	if base.Counts.FindingsWithEmptyFix != base.Counts.SupportedDetections {
		t.Fatalf("fixture precondition changed: %d of %d detections carry no recorded fix",
			base.Counts.FindingsWithEmptyFix, base.Counts.SupportedDetections)
	}
	for _, is := range p.Issues {
		if is.HowToFixIt.Provenance == guidance.ProvRecorded {
			t.Errorf("%s claims a recorded recommendation, but no finding in this corpus records one", is.Ref)
		}
	}

	// "fix not provided" is gone from every surface.
	notProvided := regexp.MustCompile(`(?i)fix not provided|not provided`)
	for name, body := range map[string]string{
		"markdown":        renderMarkdownModel(in, m),
		"standalone html": renderHTMLModel(in, m),
	} {
		if loc := notProvided.FindString(body); loc != "" {
			t.Errorf("%s still says %q (baseline: %d occurrences)", name, loc, base.Document.FixNotProvidedOccurrences)
		}
	}
}

// T043: a recorded recommendation that addresses the observed mechanism survives intact
// through the projection, rather than being replaced by the reviewed table.
func TestRecordedGuidanceIsNotOverwritten(t *testing.T) {
	in := fixture016Input(t)
	recorded := "Pass the tenant id as a bound query parameter and re-check the caller's permission on the loaded row."
	found := false
	for _, f := range in.Doc.Findings {
		if !isSupported(f) {
			continue
		}
		f["fix"] = recorded
		found = true
		break
	}
	if !found {
		t.Fatal("fixture has no supported finding")
	}
	m := BuildModel(in)
	for _, is := range m.Presentation.Issues {
		if is.HowToFixIt.Provenance != guidance.ProvRecorded {
			continue
		}
		if len(is.HowToFixIt.Steps) == 0 || is.HowToFixIt.Steps[0] != recorded {
			t.Errorf("%s: the recorded recommendation was rewritten: %v", is.Ref, is.HowToFixIt.Steps)
		}
		return
	}
	t.Error("a recorded recommendation was not carried through as recorded")
}
