package consolidate

// RunStatus carries the three independent status axes (constitution Principle II).
// No axis is derived from another; degradation always carries reasons.
type RunStatus struct {
	ExecutionStatus         string   `json:"execution_status"`
	CoverageStatus          string   `json:"coverage_status"`
	CoverageDegradedReasons []string `json:"coverage_degraded_reasons"`
	ValidationMode          string   `json:"validation_mode"`
	// Outcome is the honest completion block (feature 014, FR-021/022): distinct counts
	// for review units, candidates, failed assignments/candidates, missing artifacts,
	// disabled optional phases and deterministic recovery steps. Filled by the engine
	// (engine.OutcomeSummary) — opaque here so the consolidate package stays
	// dependency-free. Additive; nil when absent.
	Outcome any `json:"outcome,omitempty"`
}

// Execution status values.
const (
	ExecAborted    = "aborted"
	ExecCancelled  = "cancelled"
	ExecComplete   = "complete"
	ExecPartial    = "partial"
	ExecIncomplete = "incomplete"
	ExecUnknown    = "unknown"

	CovComplete = "complete"
	CovPartial  = "partial"
	CovDegraded = "degraded"
)

// StatusInput is the engine-observed data ComputeRunStatus reads.
type StatusInput struct {
	Aborted          string
	Cancelled        bool
	PhasesRequested  []string
	PhasesCompleted  []string
	BashEnabled      bool
	CoverageComplete bool // from the coverage ledger (total>0 && not_reviewed==0)
	CoverageKnown    bool // a coverage ledger was built
	NotReviewed      int
	DegradedReasons  []string // shallow-run signals, hunt-halt, etc.
}

// ComputeRunStatus derives the three axes deterministically.
func ComputeRunStatus(in StatusInput) RunStatus {
	var rs RunStatus

	// Execution axis.
	switch {
	case in.Aborted != "":
		rs.ExecutionStatus = ExecAborted
	case in.Cancelled:
		rs.ExecutionStatus = ExecCancelled
	case len(in.PhasesRequested) == 0:
		rs.ExecutionStatus = ExecUnknown
	default:
		done := map[string]bool{}
		for _, p := range in.PhasesCompleted {
			done[p] = true
		}
		nDone := 0
		for _, p := range in.PhasesRequested {
			if done[p] {
				nDone++
			}
		}
		switch {
		case nDone == len(in.PhasesRequested):
			rs.ExecutionStatus = ExecComplete
		case nDone == 0:
			rs.ExecutionStatus = ExecIncomplete
		default:
			rs.ExecutionStatus = ExecPartial
		}
	}

	// Coverage axis (independent of execution).
	reasons := append([]string{}, in.DegradedReasons...)
	if in.NotReviewed > 0 {
		reasons = append(reasons, "entry points not reviewed")
	}
	switch {
	case len(reasons) > 0:
		rs.CoverageStatus = CovDegraded
	case in.CoverageKnown && in.CoverageComplete:
		rs.CoverageStatus = CovComplete
	default:
		rs.CoverageStatus = CovPartial
	}
	rs.CoverageDegradedReasons = reasons

	// Validation mode: dynamic only when code was executed (never by default).
	if in.BashEnabled {
		rs.ValidationMode = ValidationDynamic
	} else {
		rs.ValidationMode = ValidationStatic
	}
	return rs
}
