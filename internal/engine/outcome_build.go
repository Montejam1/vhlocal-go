package engine

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"vhlocal/internal/report"
	"vhlocal/internal/verification"
)

// buildOutcome assembles the honest completion block (feature 014, FR-021/022)
// from persisted records only — review_units.json, verification_reconciliation.json,
// verification_sessions.json, hunt_execution.json, artifact_manifest.json — plus
// the record's own artifact errors and skipped phases. Because every input is a
// record, `vhlocal report` regeneration reproduces the identical block (FR-023):
// nothing here is derived from in-memory state that a re-render would lack.
//
// Counts are distinct axes and are never derived from one another (constitution II):
// review units come from the evidence record, candidates from the reconciliation,
// failed assignments from the hunt deliverable statuses, failed candidates from the
// per-session failure classes.
func buildOutcome(spec ScanSpec, rec *RunRecord, ru *ReviewUnits) *OutcomeSummary {
	o := &OutcomeSummary{
		FailedAssignments:      []FailedAssignment{},
		FailedCandidates:       []FailedCandidate{},
		MissingArtifacts:       []string{},
		DisabledOptionalPhases: []string{},
		RecoverySteps:          []string{},
	}
	if ru != nil {
		o.Units = ru.Counts
	}

	// Candidates: the reconciliation's own counts (the verification phase's record).
	recon := loadReconciliation(spec.ResultsDir)
	if recon != nil {
		o.Candidates = CandidateCounts{
			Supported:  recon.Counts["supported"],
			Rejected:   recon.Counts["rejected"],
			Unresolved: recon.Counts["unresolved"],
		}
	}

	// Failed assignments: every planned hunt deliverable that never validated, plus
	// misplaced files (present on disk, never deleted, not an assignment's output).
	if hx, ok := loadHuntExecution(spec.ResultsDir); ok {
		for _, f := range hx.Detail {
			if f.Status == HuntFileValid {
				continue
			}
			o.FailedAssignments = append(o.FailedAssignments, FailedAssignment{
				UnitID: f.UnitID, Path: f.Path, Reason: huntFileReason(f),
			})
		}
	}

	// Failed candidates: unresolved verification candidates, classed by the dominant
	// per-operation failure of their session (FR-018) when one was recorded.
	if recon != nil {
		sessions := verification.LoadSessions(spec.ResultsDir)
		invalidCitation := invalidCitationCandidates(spec.ResultsDir)
		for _, r := range recon.Results {
			if r.Status != "unresolved" {
				continue
			}
			fc := FailedCandidate{CandidateID: r.CandidateID, Reason: r.Reason}
			switch {
			case invalidCitation[r.CandidateID] != "":
				// Feature 015 (FR-025): the hunt cited something the harness could not
				// resolve; no session ran. Its own class, never "not_attempted".
				fc.Class, fc.Operation, fc.Code = ClassInvalidCitation, "citation", invalidCitation[r.CandidateID]
			case r.Record != nil:
				// The model DID decide — it submitted an `unresolved` verdict with its own
				// rationale. That is a model judgement, not a tool failure, even when the
				// session also had recoverable tool errors on the way (seen live: 8 such
				// candidates were mislabelled by an incidental invalid_tool_args count).
				fc.Class = ClassUnresolvedVerdict
			default:
				if s, ok := sessions[r.CandidateID]; ok {
					fc.Class = s.DominantClass()
					if fc.Class == "" && s.StopReason == "cancelled" {
						fc.Class = "cancelled"
					}
				}
				if fc.Class == "" {
					fc.Class = "not_attempted"
				}
			}
			o.FailedCandidates = append(o.FailedCandidates, fc)
		}
		sort.Slice(o.FailedCandidates, func(i, j int) bool {
			return o.FailedCandidates[i].CandidateID < o.FailedCandidates[j].CandidateID
		})
	}

	// Missing artifacts: the reproduction validator's errors (FR-020) — a supported
	// candidate with no disposition, a registered file that is absent, or an
	// unregistered file. They are persisted on the record, so regeneration sees them.
	o.MissingArtifacts = append(o.MissingArtifacts, rec.ArtifactErrors...)
	o.MissingArtifacts = dedupStrings(o.MissingArtifacts)
	sort.Strings(o.MissingArtifacts)

	// Disabled optional phases: a deliberately-disabled phase is named with its
	// toggle so "phases=all" with threat_model=false reads as a choice, not a gap.
	for _, key := range rec.PhasesSkipped {
		if key == "1t" && !spec.ThreatModel {
			o.DisabledOptionalPhases = append(o.DisabledOptionalPhases, "1t (threat_model=false)")
		}
	}

	o.RecoverySteps = recoverySteps(rec, o)
	return o
}

// ClassUnresolvedVerdict labels a candidate the verifier explicitly submitted as
// `unresolved` (a decision record exists); distinct from every failure class so
// recovery steps about tool contracts/turn limits never count it.
const ClassUnresolvedVerdict = "unresolved_verdict"

// huntFileReason phrases a non-valid deliverable status for the operator.
func huntFileReason(f HuntFile) string {
	switch f.Status {
	case HuntFileMissing:
		return fmt.Sprintf("deliverable never written after %d attempt(s)", max(1, f.Attempts))
	case HuntFileEmpty:
		return fmt.Sprintf("deliverable empty after %d attempt(s)", max(1, f.Attempts))
	case HuntFileMalformed:
		return "deliverable did not match the hunt contract"
	case HuntFileMisplaced:
		return "unplanned file under results/ (kept on disk; not an assignment's output)"
	case HuntFileDuplicate:
		return "duplicate deliverable path"
	}
	return f.Status
}

// recoverySteps derives deterministic operator actions from the outcome and the
// record. Order is fixed; steps are only emitted for conditions that exist.
func recoverySteps(rec *RunRecord, o *OutcomeSummary) []string {
	var steps []string
	if rec.Cancelled || rec.Aborted != "" {
		steps = append(steps, "resume this scan (--resume) to finish the interrupted phases without redoing valid work")
	} else if len(rec.PhasesRequested) > len(rec.PhasesCompleted) {
		steps = append(steps, "re-run with --resume: not every requested phase completed")
	}
	if len(o.FailedAssignments) > 0 {
		steps = append(steps, fmt.Sprintf("re-run the %d failed hunt assignment(s) listed in hunt_execution.json (detail.status != valid)", len(o.FailedAssignments)))
	}
	if o.Units.NotReviewed > 0 || o.Units.Skipped > 0 {
		steps = append(steps, "enable coverage enforcement (--enforce-coverage) so unreviewed entry points get a bounded follow-up unit")
	}
	if rec.BudgetHaltedReason != "" {
		steps = append(steps, "raise the token budget: the run halted on budget ("+rec.BudgetHaltedReason+")")
	}
	byClass := map[string]int{}
	for _, fc := range o.FailedCandidates {
		byClass[fc.Class]++
	}
	if byClass[verification.FailTransport] > 0 {
		steps = append(steps, "check the inference endpoint: verification sessions failed on transport")
	}
	if byClass[verification.FailTurnExhaustion] > 0 {
		steps = append(steps, "raise the verification turn limit or use a stronger --verify-model: sessions exhausted their turns")
	}
	if byClass[verification.FailToolEnvelope]+byClass[verification.FailInvalidToolArgs]+byClass[verification.FailInvalidSubmission] > 0 {
		steps = append(steps, "use a model that follows the tool contract (see verification_sessions.json last_contract_violation)")
	}
	if len(o.MissingArtifacts) > 0 {
		steps = append(steps, "re-run phase 3 (reproduction) to register the missing artifacts listed in artifact_manifest.json")
	}
	for _, p := range o.DisabledOptionalPhases {
		if strings.HasPrefix(p, "1t") {
			steps = append(steps, "enable the threat model (threat_model=true) to run phase 1t")
		}
	}
	if len(o.FailedAssignments)+len(o.FailedCandidates) > 0 {
		steps = append(steps, "inspect the scan log (log?tail=) around the failing unit/candidate for the exact model response")
	}
	if steps == nil {
		steps = []string{}
	}
	return steps
}

// loadReconciliation reads verification_reconciliation.json (nil when absent).
func loadReconciliation(resultsDir string) *verification.Reconciliation {
	b, err := os.ReadFile(filepath.Join(resultsDir, verification.ReconciliationFile))
	if err != nil {
		return nil
	}
	var r verification.Reconciliation
	if json.Unmarshal(b, &r) != nil {
		return nil
	}
	return &r
}

// reportGaps projects the review-unit gaps for the report (FR-016). Nil when there
// is no record (the section is then omitted); empty when the record has no gaps.
func reportGaps(ru *ReviewUnits) []report.ReviewGap {
	if ru == nil {
		return nil
	}
	out := make([]report.ReviewGap, 0, len(ru.Gaps))
	for _, g := range ru.Gaps {
		out = append(out, report.ReviewGap{RouteID: g.RouteID, Reason: g.Reason})
	}
	return out
}

// coverageView projects the review-unit record onto the report's source-review
// axis (feature 015). Under v1 semantics a completed review IS the read overlap,
// so exposure equals completion; v2 records carry a separate exposure axis.
func coverageView(ru *ReviewUnits) *report.CoverageView {
	if ru == nil {
		return nil
	}
	completed := ru.Counts.ReviewedWithFindings + ru.Counts.ReviewedNoIssue
	exposed := completed
	if ru.SemanticsVersion >= CoverageSemanticsV2 {
		exposed = ru.Counts.SourceExposed
	}
	cv := &report.CoverageView{Completed: completed, Exposed: exposed, Total: ru.Counts.Total, SemanticsVersion: max(ru.SemanticsVersion, CoverageSemanticsV1)}
	if ru.SemanticsVersion >= CoverageSemanticsV2 {
		a := ru.Axes
		cv.Axes = &report.CoverageAxes{Discovered: a.Discovered, SupportedInventory: a.SupportedInventory, Assigned: a.Assigned, Attempted: a.Attempted,
			SourceExposed: a.SourceExposed, CompletedReview: a.CompletedReview, Verified: a.Verified}
	}
	return cv
}

// ClassInvalidCitation marks a candidate whose hunt citation failed validation and
// therefore never had a verification session (feature 015, FR-025).
const ClassInvalidCitation = "invalid_citation"

// invalidCitationCandidates maps candidate id → citation error code for the
// manifest's invalid_citation candidates (empty when the manifest is absent).
func invalidCitationCandidates(resultsDir string) map[string]string {
	out := map[string]string{}
	b, err := os.ReadFile(filepath.Join(resultsDir, verification.CandidateManifestFile))
	if err != nil {
		return out
	}
	var m verification.Manifest
	if json.Unmarshal(b, &m) != nil {
		return out
	}
	for _, c := range m.Candidates {
		if !c.HasValidCitation() {
			code := "invalid"
			if c.Citation != nil && c.Citation.Error != nil {
				code = c.Citation.Error.Code
			}
			out[c.ID] = code
		}
	}
	return out
}

// failureAggregates projects verification_metrics.json `session_aggregates` onto the
// report (feature 015, FR-026/C-C10). Records only: identical at finalize and at
// regeneration. Nil when the run has no session aggregate.
func failureAggregates(resultsDir string) *report.FailureAggregates {
	b, err := os.ReadFile(filepath.Join(resultsDir, verification.MetricsFile))
	if err != nil {
		return nil
	}
	var doc struct {
		Agg *report.FailureAggregates `json:"session_aggregates"`
	}
	if json.Unmarshal(b, &doc) != nil || doc.Agg == nil || doc.Agg.Sessions == 0 {
		return nil
	}
	return doc.Agg
}
