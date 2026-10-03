package guidance

import (
	"strings"

	"vhlocal/internal/knowledge"
)

// Feature 016 (FR-014, C-R1, C-R2, C-R3): guidance resolution.
//
// The order is fixed: a recorded recommendation that addresses the observed weakness
// mechanism is used as recorded and is never overwritten by the family table; otherwise the
// reviewed family guidance is used and labelled as general; otherwise the reader is told to
// investigate. Nothing resolved here is ever described as an implemented or tested fix, and
// "fix not provided" is never an outcome.

// Provenance values for a resolved recommendation.
const (
	ProvRecorded    = "recorded"
	ProvGeneral     = "general"
	ProvInvestigate = "investigate"
)

// Disclosure labels. Each says where the advice came from and that nothing has been done.
const (
	LabelRecorded    = "Recorded during the review of this finding. Nothing here has been implemented or tested."
	LabelGeneral     = "General guidance for this weakness class, not written against this code. Nothing here has been implemented or tested."
	LabelDiverged    = "General guidance for this weakness class, because the recorded recommendation does not address the weakness that was observed. The recorded text is kept below. Nothing here has been implemented or tested."
	LabelInvestigate = "No reviewed guidance exists for this weakness class, so this is an instruction to investigate rather than weakness-specific advice. Nothing here has been implemented or tested."
)

// Request is what the records say about one issue.
type Request struct {
	// Family is the recorded weakness family key, when the record carries one.
	Family string
	// CWE is the recorded or normalized CWE, used to derive the family when Family is empty.
	CWE string
	// CanonicalName is the recorded canonical weakness name, for the reader-facing text.
	CanonicalName string
	// RecordedFix is the recommendation the review recorded, verbatim and possibly empty.
	RecordedFix string
}

// Recommendation is the resolved advice for one issue.
type Recommendation struct {
	Provenance string
	Mechanism  string
	Steps      []string
	Checks     []string
	// MissingDecision names the policy or invariant the records cannot establish.
	MissingDecision string
	// Label is the reader-facing disclosure of where this came from.
	Label string
	// RecordedNote carries a recorded recommendation that does not address the observed
	// mechanism: kept visible, never presented as the mechanism fix (C-R9).
	RecordedNote string
	// Family is the family key that was used, empty on the investigate branch.
	Family string
}

// investigateSteps is the investigate branch. It names the work to do without borrowing
// any family's mechanism wording (C-R4).
var investigateSteps = []string{
	"Establish the weakness class from the cited code before changing anything: what an attacker controls, what the code does with it, and what the consequence is.",
	"Choose the change that removes that mechanism rather than one that hides its symptom, and record the choice with the finding so a later review does not have to derive it again.",
}

// investigateChecks are generic because the mechanism is not yet established.
var investigateChecks = []string{
	"Once the mechanism is established, add a test that exercises it and expects the new behaviour.",
}

// Resolve returns the recommendation for one issue, in the order recorded, general,
// investigate.
func Resolve(r Request) Recommendation {
	family := strings.TrimSpace(r.Family)
	g, ok := For(family)
	if !ok {
		// Derive the family from the recorded CWE. A CWE in no family stays in no family.
		if f := knowledge.FamilyOf(r.CWE); f != nil {
			family = f.Key
			g, ok = For(family)
		}
	}
	recorded := strings.TrimSpace(r.RecordedFix)

	switch {
	case recorded != "" && (!ok || appliesToMechanism(recorded, g)):
		// The record wins and is never rewritten by the table (C-R1).
		rec := Recommendation{
			Provenance: ProvRecorded, Steps: []string{recorded},
			Label: LabelRecorded, Family: family,
		}
		if ok {
			rec.Mechanism, rec.Checks, rec.MissingDecision = g.Mechanism, g.Checks, g.RequiresDecision
		} else {
			rec.Checks = investigateChecks
		}
		return rec
	case recorded != "" && ok:
		// Recorded but inapplicable to the observed mechanism: use the mechanism fix,
		// disclose the divergence, and keep the recorded text visible (C-R9).
		return Recommendation{
			Provenance: ProvGeneral, Mechanism: g.Mechanism, Steps: g.Steps, Checks: g.Checks,
			MissingDecision: g.RequiresDecision, Label: LabelDiverged,
			RecordedNote: recorded, Family: family,
		}
	case ok:
		return Recommendation{
			Provenance: ProvGeneral, Mechanism: g.Mechanism, Steps: g.Steps, Checks: g.Checks,
			MissingDecision: g.RequiresDecision, Label: LabelGeneral, Family: family,
		}
	default:
		return Recommendation{
			Provenance: ProvInvestigate, Steps: investigateSteps,
			Checks: investigateChecks, Label: LabelInvestigate,
		}
	}
}

// genericCleaning are the shapes of a recommendation that only cleans input. For a family
// whose fix IS input or output handling, these appear among its FixSignals and are matched
// there first; for any other family they are evidence that the recorded recommendation does
// not address the observed mechanism.
var genericCleaning = []string{
	"encode", "escape", "sanitiz", "validate the input", "validate input",
	"input validation", "strip", "filter the input",
}

// appliesToMechanism reports whether a recorded recommendation addresses this mechanism.
// It overrides the record only on positive evidence of a mismatch: unrecognised but
// specific text is trusted, because the review saw the code and this table did not.
func appliesToMechanism(recorded string, g WeaknessGuidance) bool {
	low := strings.ToLower(recorded)
	for _, s := range g.FixSignals {
		if strings.Contains(low, s) {
			return true
		}
	}
	for _, c := range genericCleaning {
		if strings.Contains(low, c) {
			return false
		}
	}
	return true
}
