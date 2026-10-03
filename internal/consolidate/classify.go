// Classify is the single classification of a finding (supported / rejected /
// unresolved_explicit / unresolved_failed / duplicate) used by every report
// surface (feature 015, FR-002). Before it, four independent rules disagreed
// (report.isSupported, Build's counts, reports.Load, the main UI).
package consolidate

// Class is a finding's report classification.
type Class string

const (
	ClassSupported          Class = "supported"
	ClassRejected           Class = "rejected"
	ClassUnresolvedExplicit Class = "unresolved_explicit" // the verifier submitted an `unresolved` verdict
	ClassUnresolvedFailed   Class = "unresolved_failed"   // no decision (session failed) or hypothesis
	ClassDuplicate          Class = "duplicate"
)

// Classify classifies a finding map as serialized in findings.json.
// Rules, in precedence order:
//   - duplicate_of != null                                   → duplicate
//   - from_confirmed, verification_status=="supported", or
//     classification ∈ {reviewed, statically_supported}      → supported
//   - verification_status=="rejected"                        → rejected
//   - verification_record.verdict=="unresolved"              → unresolved_explicit
//   - otherwise                                              → unresolved_failed
func Classify(f map[string]any) Class {
	if f == nil {
		return ClassUnresolvedFailed
	}
	if f["duplicate_of"] != nil {
		return ClassDuplicate
	}
	vs, _ := f["verification_status"].(string)
	cls, _ := f["classification"].(string)
	if f["from_confirmed"] == true || vs == "supported" || cls == ClassReviewed || cls == ClassStaticallySupported {
		return ClassSupported
	}
	if vs == "rejected" {
		return ClassRejected
	}
	if rec, ok := f["verification_record"].(map[string]any); ok {
		if verdict, _ := rec["verdict"].(string); verdict == "unresolved" {
			return ClassUnresolvedExplicit
		}
	}
	return ClassUnresolvedFailed
}

// ClassifyFinding classifies a typed Finding with the same rules.
func ClassifyFinding(f Finding) Class {
	if f.DuplicateOf != nil {
		return ClassDuplicate
	}
	if f.FromConfirmed || f.VerificationStatus == "supported" || f.Classification == ClassReviewed || f.Classification == ClassStaticallySupported {
		return ClassSupported
	}
	if f.VerificationStatus == "rejected" {
		return ClassRejected
	}
	if verdict, _ := f.VerificationRecord["verdict"].(string); verdict == "unresolved" {
		return ClassUnresolvedExplicit
	}
	return ClassUnresolvedFailed
}

// severityKey normalizes an empty severity to the explicit Unrated bucket so
// totals always account for every finding.
func severityKey(sev string) string {
	if sev == "" {
		return DefaultSeverity
	}
	return sev
}
