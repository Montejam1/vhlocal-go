// Package consolidate turns raw per-agent hunt output into the deterministic
// findings record (findings.json) and drives report rendering. All labeling,
// deduplication, normalization, and status computation are deterministic code,
// not model judgment (constitution Principle I & FR-014). Model claims (status,
// exploit_test) are kept verbatim and distinct from harness-derived state.
package consolidate

import "strings"

// Vocabulary constants (parity with Python consolidate.py).
const (
	TestNotRun = "not_run"
	TestPassed = "passed"
	TestFailed = "failed"

	ValidationStatic  = "static_reasoning"
	ValidationDynamic = "dynamic_execution"

	StateStaticallySupported  = "statically_supported"
	StateDynamicallyConfirmed = "dynamically_confirmed"
	StateUnresolved           = "unresolved"

	PoCAuthored = "authored"
	PoCNone     = "none"

	AssessSupported  = "supported"
	AssessUnresolved = "unresolved"

	ClassHypothesis          = "hypothesis"
	ClassStaticallySupported = "statically_supported"
	ClassReviewed            = "reviewed"

	CVENotApplicable = "CVE-N/A"
	DefaultSeverity  = "Unrated"
	UnknownRank      = 7
)

// Finding is one candidate/confirmed vulnerability. Field order and json tags
// mirror the Python Finding dataclass; to_dict appends potential_severity.
type Finding struct {
	ID                  string              `json:"id"`
	Title               string              `json:"title"`
	Severity            string              `json:"severity"`
	SeverityRank        int                 `json:"severity_rank"`
	CWE                 string              `json:"cwe"`
	Location            string              `json:"location"`
	EntryPoint          string              `json:"entry_point"`
	DataFlow            string              `json:"data_flow"`
	Status              string              `json:"status"` // raw model claim
	PoC                 string              `json:"poc"`
	ExploitTest         string              `json:"exploit_test"` // raw model claim
	Fix                 string              `json:"fix"`
	Source              string              `json:"source"`
	SourceID            string              `json:"source_id"`
	VerificationStatus  string              `json:"verification_status"`
	VerificationReason  string              `json:"verification_reason"`
	VerificationRecord  map[string]any      `json:"verification_record"`
	StableIdentity      string              `json:"stable_identity"`
	DuplicateOf         *string             `json:"duplicate_of"`
	RootCauseKey        string              `json:"root_cause_key"`
	ClusterID           string              `json:"cluster_id"`
	PoCStatus           string              `json:"poc_status"`
	TestStatus          string              `json:"test_status"`
	ValidationMethod    string              `json:"validation_method"`
	FindingState        string              `json:"finding_state"`
	Assessment          string              `json:"assessment"`
	Classification      string              `json:"classification"`
	CandidateKey        string              `json:"candidate_key"`
	HypothesisReason    string              `json:"hypothesis_reason"`
	AssessmentReason    string              `json:"assessment_reason"`
	Description         string              `json:"description"`
	Exploitability      string              `json:"exploitability"`
	Reference           string              `json:"reference"`
	CVE                 string              `json:"cve"`
	NormalizedCWE       string              `json:"normalized_cwe"`
	CWEFamily           string              `json:"cwe_family"`
	CanonicalName       string              `json:"canonical_name"`
	NormalizedSeverity  string              `json:"normalized_severity"`
	ReportedSeverity    string              `json:"reported_severity"`
	FindingLifecycle    string              `json:"finding_lifecycle"`
	Votes               int                 `json:"votes"`
	VoteSamples         int                 `json:"vote_samples"`
	FromConfirmed       bool                `json:"from_confirmed"`
	AssessmentInherited bool                `json:"assessment_inherited"`
	QualityChecks       []map[string]string `json:"quality_checks"`
	// ReviewRecord is an explicit, source-grounded review supplied by a reviewer/
	// integration (never inferred from a model label). A validated record tiers the
	// finding `reviewed` — above `statically_supported` (feature 006, FR-011). It is
	// an input channel, not serialized output.
	ReviewRecord *ReviewRecord `json:"-"`
}

// ReviewRecord is an explicit review decision on record for a finding (parity with
// the reference verification_records channel). Validated by ReviewSupport.
type ReviewRecord struct {
	Verdict          string
	Revision         string
	Reviewer         string
	Rationale        string
	EntryPoint       string
	AttackerControl  string
	Preconditions    string
	DefensesReviewed string
	SecurityImpact   string
	Evidence         []ReviewEvidence
}

// ReviewEvidence is one immutable source citation inside a ReviewRecord.
type ReviewEvidence struct {
	Path      string
	StartLine int
	EndLine   int
	Quote     string
}

// NewFinding returns a Finding with the dataclass defaults applied.
func NewFinding(id string) Finding {
	return Finding{
		ID: id, Severity: DefaultSeverity, SeverityRank: UnknownRank,
		Classification: ClassHypothesis, CVE: CVENotApplicable,
		VerificationRecord: map[string]any{}, QualityChecks: []map[string]string{},
	}
}

// ToMap serializes a Finding to an ordered-agnostic map, appending
// potential_severity (mirror of severity) as the Python to_dict does.
func (f Finding) ToMap() map[string]any {
	var dup any // untyped nil (not a typed *string nil) so JSON emits null and == nil works
	if f.DuplicateOf != nil {
		dup = *f.DuplicateOf
	}
	m := map[string]any{
		"id": f.ID, "title": f.Title, "severity": f.Severity, "severity_rank": f.SeverityRank,
		"cwe": f.CWE, "location": f.Location, "entry_point": f.EntryPoint, "data_flow": f.DataFlow,
		"status": f.Status, "poc": f.PoC, "exploit_test": f.ExploitTest, "fix": f.Fix,
		"source": f.Source, "source_id": f.SourceID,
		"verification_status": f.VerificationStatus, "verification_reason": f.VerificationReason,
		"verification_record": f.VerificationRecord, "stable_identity": f.StableIdentity,
		"duplicate_of": dup, "root_cause_key": f.RootCauseKey, "cluster_id": f.ClusterID,
		"poc_status": f.PoCStatus, "test_status": f.TestStatus, "validation_method": f.ValidationMethod,
		"finding_state": f.FindingState, "assessment": f.Assessment, "classification": f.Classification,
		"candidate_key": f.CandidateKey, "hypothesis_reason": f.HypothesisReason,
		"assessment_reason": f.AssessmentReason, "description": f.Description,
		"exploitability": f.Exploitability, "reference": f.Reference, "cve": f.CVE,
		"normalized_cwe": f.NormalizedCWE, "cwe_family": f.CWEFamily, "canonical_name": f.CanonicalName,
		"normalized_severity": f.NormalizedSeverity, "reported_severity": f.ReportedSeverity,
		"finding_lifecycle": f.FindingLifecycle, "votes": f.Votes, "vote_samples": f.VoteSamples,
		"from_confirmed": f.FromConfirmed, "assessment_inherited": f.AssessmentInherited,
		"quality_checks": f.QualityChecks, "potential_severity": f.Severity,
	}
	return m
}

// severity ordering (most severe first): lowercase key -> (rank, canonical label).
var severityOrder = []struct {
	key   string
	label string
}{
	{"critical", "Critical"}, {"high+", "High+"}, {"high", "High"},
	{"medium", "Medium"}, {"moderate", "Medium"}, {"low", "Low"},
	{"informational", "Informational"}, {"info", "Informational"},
}

var sevRank = func() map[string]int {
	m := map[string]int{}
	for i, s := range severityOrder {
		if _, ok := m[s.key]; !ok {
			m[s.key] = i
		}
	}
	return m
}()

var sevLabel = func() map[string]string {
	m := map[string]string{}
	for _, s := range severityOrder {
		m[s.key] = s.label
	}
	return m
}()

// sevKey matches the longest severity key that is a substring of s (lowercased).
func sevKey(s string) string {
	s = strings.ToLower(s)
	best := ""
	for k := range sevRank {
		if strings.Contains(s, k) && len(k) > len(best) {
			best = k
		}
	}
	return best
}

// SeverityLabel returns the canonical label for a raw severity string.
func SeverityLabel(raw string) string {
	if k := sevKey(raw); k != "" {
		return sevLabel[k]
	}
	return DefaultSeverity
}

// SeverityRank returns the sort rank (0 = most severe, UnknownRank = unknown).
func SeverityRankOf(raw string) int {
	if k := sevKey(raw); k != "" {
		return sevRank[k]
	}
	return UnknownRank
}
