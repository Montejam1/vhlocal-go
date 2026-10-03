package consolidate

import "strings"

// QualityStrictness levels (parity with the Python quality battery).
const (
	StrictLenient  = "lenient"
	StrictBalanced = "balanced"
	StrictStrict   = "strict"
)

// sink families require a source-pattern (attacker input reaching the sink);
// for these, a location+CWE alone is not enough at balanced/strict.
var sinkFamilies = map[string]bool{
	"sql-injection": true, "command-injection": true, "code-injection": true,
	"path-traversal": true, "ssrf": true, "xss": true, "template-injection": true,
	"nosql-injection": true, "xxe": true, "deserialization": true,
}

// EvaluateQuality runs the pre-report corroboration battery on a finding at the
// given strictness, against the target repo (repo may be "" on a re-render). It
// returns the per-check results and whether the finding clears the "statically
// supported" bar. Deterministic — the publishing decision is code, not model
// judgment (Principle I / FR-014).
//
// Source corroboration (FR-024/025) gates support: a FAIL (cited source present
// but no matching sink) refutes support; a logic/authorization class or a class the
// checker has no rule for can never be supported on prose; only "unavailable" (no
// checkout) falls back to the structural signals so re-renders keep their tier.
func EvaluateQuality(f *Finding, strictness, repo string) ([]map[string]string, bool) {
	hasLoc := strings.TrimSpace(f.Location) != ""
	hasCWE := strings.TrimSpace(f.CWE) != "" || strings.TrimSpace(f.NormalizedCWE) != ""
	// a source-pattern signal: attacker input named in entry point / data flow.
	hasSource := hasArrow(f.DataFlow) || strings.TrimSpace(f.EntryPoint) != ""
	fromConfirmed := f.FromConfirmed
	cor := checkSourceCorroborated(f, repo)
	ce := checkClassEvidence(f, repo)

	checks := []map[string]string{
		check("location", hasLoc, "a file:line sink location is present"),
		check("cwe", hasCWE, "a CWE classification is present"),
		check("source_pattern", hasSource, "attacker input traced to the sink"),
		check("corroboration", fromConfirmed, "survived Phase 2b falsification"),
		check("source_corroborated", cor.status == "pass", cor.reason),
		check("class_evidence", ce.status != "fail", ce.reason),
	}

	isSink := sinkFamilies[f.CWEFamily]
	structural := func() bool {
		switch strictness {
		case StrictLenient:
			return hasLoc || hasCWE || hasSource
		case StrictStrict:
			return hasLoc && hasCWE && hasSource && (fromConfirmed || !isSink)
		default: // balanced
			if isSink {
				return hasLoc && hasCWE && hasSource
			}
			return hasLoc && hasCWE
		}
	}
	if strictness == StrictLenient {
		// Lenient keeps the permissive one-signal bar (a source FAIL still can't
		// hurt because lenient is explicitly minimal-evidence).
		return checks, structural()
	}
	// Class-specific veto (FR-025): a class_evidence FAIL refutes support even with a
	// sink; a PASS on a primary-evidence class (CORS) establishes it on its own.
	if ce.status == "fail" {
		return checks, false
	}
	if ce.status == "pass" && isPrimaryEvidenceClass(f) {
		return checks, hasLoc && hasCWE
	}
	switch {
	case cor.status == "pass":
		return checks, hasLoc && hasCWE // the source proves the sink
	case cor.status == "fail":
		return checks, false // the source refutes the class
	case cor.kind == "logic" || cor.kind == "uncovered":
		return checks, false // cannot assess on prose; retain uncertainty
	default: // "unavailable" — no checkout / re-render: keep tier via structural signals
		return checks, structural()
	}
}

// ApplyQuality sets QualityChecks and, when the bar is cleared, promotes a finding
// to statically_supported; otherwise leaves it as a hypothesis with a reason.
// Called after ApplyKnowledge. repo enables source corroboration (may be "").
//
// A structured verification disposition (US3) takes PRECEDENCE over the
// deterministic source-corroboration battery: a candidate the verifier rejected or
// left unresolved is never statically supported (even if a sink is present), and a
// supported one is confirmed. The battery decides only when no verification ran.
func ApplyQuality(f *Finding, strictness, repo string) {
	switch f.VerificationStatus {
	case "rejected", "unresolved":
		f.QualityChecks, _ = EvaluateQuality(f, strictness, repo)
		f.Classification = ClassHypothesis
		f.Assessment = AssessUnresolved
		f.FindingState = StateUnresolved
		if f.HypothesisReason == "" {
			f.HypothesisReason = "verification " + f.VerificationStatus
			if f.VerificationReason != "" {
				f.HypothesisReason += ": " + f.VerificationReason
			}
		}
		f.ValidationMethod = ValidationStatic
		return
	case "supported":
		f.QualityChecks, _ = EvaluateQuality(f, strictness, repo)
		f.Classification = ClassStaticallySupported
		f.Assessment = AssessSupported
		f.FindingState = StateStaticallySupported
		f.ValidationMethod = ValidationStatic
		return
	}
	// A validated, source-grounded review record tiers the finding `reviewed` —
	// above the harness's own quality battery (US3; FR-011). The battery is still
	// recorded so the report can show corroboration alongside the review.
	if reviewed, reason := ReviewSupport(f, repo); reviewed {
		f.QualityChecks, _ = EvaluateQuality(f, strictness, repo)
		f.Classification = ClassReviewed
		f.Assessment = AssessSupported
		f.FindingState = StateStaticallySupported
		f.AssessmentReason = reason
		f.ValidationMethod = ValidationStatic
		return
	}
	checks, cleared := EvaluateQuality(f, strictness, repo)
	f.QualityChecks = checks
	if cleared {
		f.Classification = ClassStaticallySupported
		f.Assessment = AssessSupported
		f.FindingState = StateStaticallySupported
	} else {
		f.Classification = ClassHypothesis
		f.Assessment = AssessUnresolved
		f.FindingState = StateUnresolved
		if f.HypothesisReason == "" {
			f.HypothesisReason = "did not clear the " + strictnessOrDefault(strictness) + " corroboration bar"
		}
	}
	f.ValidationMethod = ValidationStatic
}

func strictnessOrDefault(s string) string {
	if s == "" {
		return StrictBalanced
	}
	return s
}

func check(name string, ok bool, reason string) map[string]string {
	status := "fail"
	if ok {
		status = "pass"
	}
	return map[string]string{"name": name, "status": status, "reason": reason}
}

func hasArrow(s string) bool {
	return strings.Contains(s, "->") || strings.Contains(s, "→")
}
