package engine

// OutcomeSummary is the honest completion block (feature 014, FR-021/022,
// data-model "OutcomeSummary"). Every count is a distinct axis; none is derived
// from another (constitution II). It is persisted in scan_meta.json (RunRecord)
// and mirrored into findings.json run_status.outcome and the report.
type OutcomeSummary struct {
	Units                  UnitCounts         `json:"units"`
	Candidates             CandidateCounts    `json:"candidates"`
	FailedAssignments      []FailedAssignment `json:"failed_assignments"`
	FailedCandidates       []FailedCandidate  `json:"failed_candidates"`
	MissingArtifacts       []string           `json:"missing_artifacts"`
	DisabledOptionalPhases []string           `json:"disabled_optional_phases"`
	RecoverySteps          []string           `json:"recovery_steps"`
}

// UnitCounts are the review-unit disposition counts (FR-010/012).
type UnitCounts struct {
	Total                int `json:"total"`
	Assigned             int `json:"assigned"`
	Attempted            int `json:"attempted"`
	ReviewedWithFindings int `json:"reviewed_with_findings"`
	ReviewedNoIssue      int `json:"reviewed_no_issue"`
	Partial              int `json:"partial"`
	Failed               int `json:"failed"`
	Skipped              int `json:"skipped"`
	Unsupported          int `json:"unsupported"`
	NotReviewed          int `json:"not_reviewed"`
	// SourceExposed (feature 015 axis): routes whose handler span was read by a valid
	// unit regardless of disposition — activity, never analysis credit.
	SourceExposed int `json:"source_exposed,omitempty"`
}

// CandidateCounts are the verification outcome counts (FR-019).
type CandidateCounts struct {
	Supported  int `json:"supported"`
	Rejected   int `json:"rejected"`
	Unresolved int `json:"unresolved"`
}

// FailedAssignment names a hunt assignment whose deliverable never validated (FR-017).
type FailedAssignment struct {
	UnitID string `json:"unit_id"`
	Path   string `json:"path"`
	Reason string `json:"reason"`
}

// FailedCandidate names a candidate left unresolved and why (FR-018/019).
type FailedCandidate struct {
	CandidateID string `json:"candidate_id"`
	Class       string `json:"class"`
	Reason      string `json:"reason"`
	// Operation / Code (feature 015, FR-026): the failed operation and error code of
	// the dominant failure, so the report appendix can name them.
	Operation string `json:"operation,omitempty"`
	Code      string `json:"code,omitempty"`
}
