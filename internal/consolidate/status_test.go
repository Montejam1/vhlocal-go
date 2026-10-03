package consolidate

import "testing"

// C-X3 (feature 005, FR-040): the three status axes stay independent — execution
// complete does not imply coverage complete, and all three are always present.
func TestStatusAxesIndependent(t *testing.T) {
	rs := ComputeRunStatus(StatusInput{
		PhasesRequested: []string{"1", "2"}, PhasesCompleted: []string{"1", "2"},
		CoverageKnown: true, CoverageComplete: false, NotReviewed: 5,
		DegradedReasons: []string{"entry points not reviewed"},
	})
	if rs.ExecutionStatus != ExecComplete {
		t.Errorf("execution should be complete, got %q", rs.ExecutionStatus)
	}
	if rs.CoverageStatus != CovDegraded {
		t.Errorf("coverage must not be derived from execution; want degraded, got %q", rs.CoverageStatus)
	}
	if rs.ValidationMode == "" || rs.ExecutionStatus == "" || rs.CoverageStatus == "" {
		t.Error("all three status axes must always be present")
	}
	// A cancelled run is cancelled, never aborted (FR-C5).
	c := ComputeRunStatus(StatusInput{Cancelled: true, PhasesRequested: []string{"1"}})
	if c.ExecutionStatus != ExecCancelled {
		t.Errorf("cancelled run must report cancelled, got %q", c.ExecutionStatus)
	}
}
