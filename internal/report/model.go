// ReportModel is the single authoritative report source (feature 015, FR-001/002):
// built once in finalize from records, persisted as report_model.json, rendered by
// every surface (Markdown, HTML, main UI, React, print). Every count derives from
// consolidate.Classify; nothing here is recomputed by a viewer.
package report

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"vhlocal/internal/consolidate"
)

// ModelVersion is the report_model.json schema version.
const ModelVersion = 1

// ModelFile is the persisted report model in the results directory.
const ModelFile = "report_model.json"

// ReportModel — see data-model.md "ReportModel".
type ReportModel struct {
	Version     int    `json:"version"`
	ScanID      string `json:"scan_id"`
	Target      Target `json:"target"`
	GeneratedAt string `json:"generated_at"`
	Status      Status `json:"status"`
	Counts      Counts `json:"counts"`
	// SeveritySupported sums to Counts.Supported; SeverityCandidates covers every
	// non-duplicate candidate regardless of status (labelled as such wherever shown).
	SeveritySupported  map[string]int    `json:"severity_supported"`
	SeverityCandidates map[string]int    `json:"severity_candidates"`
	Summary            Summary           `json:"summary"`
	Index              []IndexRow        `json:"index"`
	Findings           []FindingDetail   `json:"findings"`
	Groups             []Group           `json:"groups"`
	Appendix           Appendix          `json:"appendix"`
	Refs               map[string]string `json:"refs"`
	// CoverageSemanticsLabel names the evidence standard behind source-review counts
	// ("read-overlap evidence (v1)" | "validated handler dispositions (v2)").
	CoverageSemanticsLabel string `json:"coverage_semantics_label,omitempty"`
	// DiagramSummary is the threat-model diagram validation state (feature 015).
	DiagramSummary string `json:"diagram_summary,omitempty"`
	// Presentation is the feature-016 reader-facing projection. Nil for a report saved
	// before this feature, which renders as a legacy report (FR-026, C-C7).
	Presentation *Presentation `json:"presentation,omitempty"`
}

type Target struct {
	Name         string `json:"name"`
	RepoBasename string `json:"repo_basename"`
	Revision     string `json:"revision,omitempty"`
	Branch       string `json:"branch,omitempty"`
}

// Status carries the run axes verbatim; the queue job status is never part of it.
type Status struct {
	Execution       string   `json:"execution"`
	Coverage        string   `json:"coverage"`
	ValidationMode  string   `json:"validation_mode"`
	DegradedReasons []string `json:"degraded_reasons"`
}

type Counts struct {
	Supported          int          `json:"supported"`
	RemediationGroups  int          `json:"remediation_groups"`
	Rejected           int          `json:"rejected"`
	UnresolvedExplicit int          `json:"unresolved_explicit"`
	UnresolvedFailed   int          `json:"unresolved_failed"`
	TotalCandidates    int          `json:"total_candidates"`
	Duplicates         int          `json:"duplicates"`
	SourceReview       SourceReview `json:"source_review"`
}

// SourceReview is the coverage axis the report cites (never derived from execution).
type SourceReview struct {
	Completed        int `json:"completed"`
	Exposed          int `json:"exposed"`
	Total            int `json:"total"`
	SemanticsVersion int `json:"semantics_version"`
	// Axes are the independent coverage axes of a v2 record (feature 015, FR-015);
	// nil for v1 records, whose only evidence is the read overlap.
	Axes *CoverageAxes `json:"axes,omitempty"`
}

// CoverageAxes mirrors engine.CoverageAxes: none of these is derived from another.
type CoverageAxes struct {
	Discovered         int `json:"discovered"`
	SupportedInventory int `json:"supported_inventory"`
	Assigned           int `json:"assigned"`
	Attempted          int `json:"attempted"`
	SourceExposed      int `json:"source_exposed"`
	CompletedReview    int `json:"completed_review"`
	Verified           int `json:"verified"`
}

type Summary struct {
	Words       int       `json:"words"`
	Leading     []Leading `json:"leading"`
	Limitations []string  `json:"limitations"`
	Narrative   string    `json:"narrative"`
}

type Leading struct {
	Ref      string `json:"ref"` // index anchor
	Title    string `json:"title"`
	Severity string `json:"severity"`
	Surface  string `json:"surface"`
	Action   string `json:"action"`
}

// Evidence statuses on index rows.
const (
	EvidenceCaptured = "evidence_captured"
	EvidenceMissing  = "evidence_missing"
	NotVerified      = "not_verified"
)

type IndexRow struct {
	ID             string `json:"id"`
	GroupID        string `json:"group_id,omitempty"`
	Role           string `json:"role,omitempty"`       // primary | occurrence (feature 015, FR-020)
	GroupSize      int    `json:"group_size,omitempty"` // members in the row's group
	Title          string `json:"title"`
	Severity       string `json:"severity"`
	Surface        string `json:"surface"`
	EvidenceStatus string `json:"evidence_status"`
	Action         string `json:"action,omitempty"`
	Anchor         string `json:"anchor"`
}

type Evidence struct {
	Path  string `json:"path"`
	Start int    `json:"start"`
	End   int    `json:"end"`
	Quote string `json:"quote"`
}

type Reproduction struct {
	Kind   string `json:"kind,omitempty"`
	Status string `json:"status"` // authored | deferred | none
	Path   string `json:"path,omitempty"`
	Reason string `json:"reason,omitempty"`
}

type Verification struct {
	Status             string `json:"status"`
	Reason             string `json:"reason,omitempty"`
	ExplicitUnresolved bool   `json:"explicit_unresolved"`
}

type FindingDetail struct {
	ID              string       `json:"id"`
	GroupID         string       `json:"group_id,omitempty"`
	Title           string       `json:"title"`
	Severity        string       `json:"severity"`
	CWE             string       `json:"cwe,omitempty"`
	NormalizedCWE   string       `json:"normalized_cwe,omitempty"`
	CanonicalName   string       `json:"canonical_name,omitempty"`
	Location        string       `json:"location"`
	EntryPoint      string       `json:"entry_point,omitempty"`
	Impact          string       `json:"impact,omitempty"`
	Prerequisites   string       `json:"prerequisites,omitempty"`
	AttackerControl string       `json:"attacker_control,omitempty"`
	SourceToSink    string       `json:"source_to_sink,omitempty"`
	Defenses        string       `json:"defenses,omitempty"`
	Rationale       string       `json:"rationale,omitempty"`
	Evidence        []Evidence   `json:"evidence"`
	Fix             string       `json:"fix,omitempty"`
	Reproduction    Reproduction `json:"reproduction"`
	Verification    Verification `json:"verification"`
	Classification  string       `json:"classification,omitempty"`
}

// Group is a remediation group (feature 015, US5). Empty until groups are built.
type Group struct {
	ID                  string        `json:"id"`
	Family              string        `json:"family"`
	CanonicalName       string        `json:"canonical_name,omitempty"`
	Anchor              string        `json:"anchor"` // "file:line — function"
	Status              string        `json:"status"` // established | suggested
	Members             []GroupMember `json:"members"`
	Size                int           `json:"size"`
	Fix                 string        `json:"fix,omitempty"`
	DecisionStatus      string        `json:"decision_status"`
	MembersChangedSince bool          `json:"members_changed_since"`
}

type GroupMember struct {
	ID         string `json:"id"`
	Role       string `json:"role"` // primary | occurrence
	StableID   string `json:"stable_id,omitempty"`
	EntryPoint string `json:"entry_point,omitempty"`
}

// GroupsFromConsolidate projects remediation_groups.json onto the report model.
func GroupsFromConsolidate(g consolidate.Groups) []Group {
	out := make([]Group, 0, len(g.Groups))
	for _, cg := range g.Groups {
		anchor := fmt.Sprintf("%s:%d", cg.Anchor.File, cg.Anchor.Line)
		if cg.Anchor.Function != "" {
			anchor += " — " + cg.Anchor.Function
		}
		rg := Group{ID: cg.ID, Family: cg.Family, CanonicalName: cg.CanonicalName, Anchor: anchor, Status: cg.Status,
			Members: []GroupMember{}, Size: len(cg.Members), Fix: cg.Fix, DecisionStatus: cg.DecisionStatus, MembersChangedSince: cg.MembersChangedSince}
		for _, m := range cg.Members {
			rg.Members = append(rg.Members, GroupMember{ID: m.FindingID, Role: m.Role, StableID: m.StableID, EntryPoint: m.EntryPoint})
		}
		out = append(out, rg)
	}
	return out
}

type CandidateRow struct {
	ID       string `json:"id"`
	Title    string `json:"title"`
	Location string `json:"location"`
	Reason   string `json:"reason"`
	Action   string `json:"action,omitempty"`
}

type FailedRow struct {
	ID        string `json:"id"`
	Title     string `json:"title"`
	Location  string `json:"location"`
	Class     string `json:"class,omitempty"`
	Operation string `json:"operation,omitempty"`
	Code      string `json:"code,omitempty"`
	Message   string `json:"message"`
}

type PhaseRow struct {
	Phase            string         `json:"phase"`
	Agents           int            `json:"agents"`
	Turns            int            `json:"turns"`
	Stops            map[string]int `json:"stops"`
	Produced         bool           `json:"produced"`
	PromptTokens     int            `json:"prompt_tokens"`
	CompletionTokens int            `json:"completion_tokens"`
}

type Appendix struct {
	Rejected           []CandidateRow `json:"rejected"`
	UnresolvedExplicit []CandidateRow `json:"unresolved_explicit"`
	UnresolvedFailed   []FailedRow    `json:"unresolved_failed"`
	Phases             []PhaseRow     `json:"phases"`
	AgentsRef          string         `json:"agents_ref"`
	ArtifactsRef       string         `json:"artifacts_ref"`
}

// CoverageView is what finalize/regeneration know about source review (from the
// review-units record); nil for runs without one.
// ---------------------------------------------------------------------------
// Feature 016: the reader-facing presentation projection.
//
// Every surface reads this and none recomputes grouping, severity, counts or
// remediation for itself (FR-021, C-P26, C-P27). The existing fields above are
// retained unchanged so historical readers and the previous feature's integrity
// assertions keep working; a saved report without a Presentation renders as a legacy
// report with its unavailable values disclosed (FR-026, C-C7, C-C8).
// ---------------------------------------------------------------------------

// PresentationVersion stamps the projection so a reader can tell which presentation a
// saved report was produced with.
const PresentationVersion = 1

// Remediation provenance values (data-model "RemediationRecommendation.provenance").
const (
	// GuidanceRecorded is per-finding guidance recorded by the scan.
	GuidanceRecorded = "recorded"
	// GuidanceGeneral is reviewed weakness-family guidance, disclosed as general.
	GuidanceGeneral = "general"
	// GuidanceInvestigate names what to inspect when no safe recommendation follows
	// from the record. It is never a silent stand-in for advice.
	GuidanceInvestigate = "investigate"
)

// Review item kinds (data-model "ReviewItem.kind").
const (
	// ReviewInconclusive is an explicit unresolved decision: a judgement, not a failure.
	ReviewInconclusive = "inconclusive"
	// ReviewIncomplete is an assessment that did not finish.
	ReviewIncomplete = "incomplete"
)

// Presentation is the whole reader-facing projection for one report.
type Presentation struct {
	Version     int               `json:"version"`
	Identity    ReportIdentity    `json:"identity"`
	Opening     OpeningProse      `json:"opening"`
	Scope       ScopeNote         `json:"scope"`
	Counts      ReportCounts      `json:"counts"`
	Priority    []PriorityAction  `json:"priority"`
	Issues      []PrimaryIssue    `json:"issues"`
	ReviewItems []ReviewItem      `json:"review_items"`
	Dismissed   []DismissedRecord `json:"dismissed"`
	// GroupingNotes records recorded groups that were not used as a reporting unit, with
	// the reason. Rendered in Scan details, never in the vulnerability list (FR-008).
	GroupingNotes []string `json:"grouping_notes,omitempty"`
}

// ReportIdentity is what the report is about (FR-002, C-P2).
type ReportIdentity struct {
	Application string `json:"application"`
	ScanDate    string `json:"scan_date"`
	Timezone    string `json:"timezone,omitempty"`
	Revision    string `json:"revision,omitempty"`
}

// OpeningProse is the bounded opening. Words counts RiskSummary plus ScopeSentence and
// excludes the title, metric labels and values, and the priority rows (FR-002, C-P3).
type OpeningProse struct {
	RiskSummary   string `json:"risk_summary"`
	ScopeSentence string `json:"scope_sentence,omitempty"`
	Words         int    `json:"words"`
	Trimmed       bool   `json:"trimmed,omitempty"`
}

// ScopeNote carries the three independent status facts once, in plain language. None is
// derived from another and unknown coverage stays unknown (FR-004, C-P9).
type ScopeNote struct {
	Execution        string `json:"execution"`
	CoverageComplete int    `json:"coverage_completed"`
	CoverageTotal    int    `json:"coverage_total"`
	// CoverageExposed is shown only where labeled as exposure, never as reviewed.
	CoverageExposed int    `json:"coverage_exposed"`
	CoverageKnown   bool   `json:"coverage_known"`
	Method          string `json:"method"`
	GapSentence     string `json:"gap_sentence,omitempty"`
	EntryPointGloss string `json:"entry_point_gloss"`
}

// ReportCounts are the reader-facing totals. NeedsReview is never added into
// IssuesToFix, and CandidatesExamined appears only where labeled (FR-003, C-P6).
type ReportCounts struct {
	IssuesToFix        int            `json:"issues_to_fix"`
	Severity           map[string]int `json:"severity"`
	NeedsReview        int            `json:"needs_review"`
	NeedsInconclusive  int            `json:"needs_review_inconclusive"`
	NeedsIncomplete    int            `json:"needs_review_incomplete"`
	Dismissed          int            `json:"dismissed"`
	Detections         int            `json:"detections"`
	CandidatesExamined int            `json:"candidates_examined"`
}

// PriorityAction is one row of the at-most-five priority list (FR-010, C-P21).
type PriorityAction struct {
	Ref          string `json:"ref"`
	Issue        string `json:"issue"`
	Severity     string `json:"severity"`
	AffectedArea string `json:"affected_area"`
	Action       string `json:"action"`
}

// PrimaryIssue is one established defect requiring remediation: the reporting unit for
// totals, charts, priority rows, index rows and detail sections (FR-007, C-P11).
type PrimaryIssue struct {
	Ref                string             `json:"ref"`
	GroupID            string             `json:"group_id,omitempty"`
	Title              string             `json:"title"`
	Severity           string             `json:"severity"`
	OriginalSeverities []string           `json:"original_severities,omitempty"`
	Family             string             `json:"family,omitempty"`
	CWE                string             `json:"cwe,omitempty"`
	CanonicalName      string             `json:"canonical_name,omitempty"`
	DetectionCount     int                `json:"detection_count"`
	Members            []IssueMember      `json:"members"`
	Locations          []AffectedLocation `json:"locations"`
	EntryPoints        []string           `json:"entry_points,omitempty"`
	WhatWeFound        string             `json:"what_we_found"`
	WhyItMatters       string             `json:"why_it_matters"`
	// Context that must stay visible beside the claim (FR-012, C-P18): the access an
	// attacker needs, what they control, and the safeguards the review looked at.
	AccessRequired     string                    `json:"access_required,omitempty"`
	AttackerControl    string                    `json:"attacker_control,omitempty"`
	SafeguardsReviewed string                    `json:"safeguards_reviewed,omitempty"`
	HowToFixIt         RemediationRecommendation `json:"how_to_fix_it"`
	HowToCheckTheFix   []string                  `json:"how_to_check_the_fix"`
	Evidence           []Evidence                `json:"evidence"`
	// GroupingNote is set only when a recorded group was not used as-is, naming why.
	GroupingNote string `json:"grouping_note,omitempty"`
}

// IssueMember is one backing supported finding, traceable to its original identity.
type IssueMember struct {
	FindingID  string `json:"finding_id"`
	StableID   string `json:"stable_id,omitempty"`
	Role       string `json:"role"`
	EntryPoint string `json:"entry_point,omitempty"`
	Severity   string `json:"severity,omitempty"`
}

// AffectedLocation is one deduplicated affected location. CitationCount records how
// many detections cited it and never multiplies the location count (FR-013, C-P15).
type AffectedLocation struct {
	File          string `json:"file"`
	Lines         string `json:"lines,omitempty"`
	EntryPoint    string `json:"entry_point,omitempty"`
	Revision      string `json:"revision,omitempty"`
	CitationCount int    `json:"citation_count"`
	Available     bool   `json:"available"`
}

// RemediationRecommendation is the resolved advice for one issue. A recommendation is
// never described as an implemented or tested fix (FR-014, C-R2, C-R3).
type RemediationRecommendation struct {
	Provenance      string   `json:"provenance"`
	Steps           []string `json:"steps"`
	MissingDecision string   `json:"missing_decision,omitempty"`
	Checks          []string `json:"checks,omitempty"`
	Label           string   `json:"label,omitempty"`
	// Mechanism states what is wrong, in one clause, for the reader-facing fix section.
	Mechanism string `json:"mechanism,omitempty"`
	// RecordedNote carries a recorded recommendation that does not address the observed
	// weakness mechanism: kept visible, never presented as the mechanism fix (C-R9).
	RecordedNote string `json:"recorded_note,omitempty"`
}

// ReviewItem is an allegation whose assessment is inconclusive or unfinished. It never
// contributes to vulnerability or severity totals (FR-017, C-C1, C-C2).
type ReviewItem struct {
	Ref                 string `json:"ref"`
	Kind                string `json:"kind"`
	Title               string `json:"title,omitempty"`
	Location            string `json:"location,omitempty"`
	WhatIsUnresolved    string `json:"what_is_unresolved"`
	NextStep            string `json:"next_step"`
	ProvisionalSeverity string `json:"provisional_severity,omitempty"`
	DiagnosticsRef      string `json:"diagnostics_ref,omitempty"`
}

// DismissedRecord is a rejected candidate kept available with its recorded reason.
// Presentation never alters a recorded decision (FR-018, C-C3).
type DismissedRecord struct {
	Ref      string `json:"ref"`
	Title    string `json:"title"`
	Location string `json:"location,omitempty"`
	Reason   string `json:"reason"`
	Decision string `json:"decision,omitempty"`
}

type CoverageView struct {
	Completed        int
	Exposed          int
	Total            int
	SemanticsVersion int
	Axes             *CoverageAxes
}

// BuildModel assembles the report model from the report Input (records only).
func BuildModel(in Input) ReportModel {
	m := ReportModel{
		Version: ModelVersion, ScanID: in.ScanID, GeneratedAt: in.FinishedAt,
		Target: Target{Name: in.Target, RepoBasename: filepath.Base(in.Repo), Revision: in.GitCommit, Branch: in.GitBranch},
		Status: Status{
			Execution: in.Doc.RunStatus.ExecutionStatus, Coverage: in.Doc.RunStatus.CoverageStatus,
			ValidationMode: in.Doc.RunStatus.ValidationMode, DegradedReasons: append([]string{}, in.Doc.RunStatus.CoverageDegradedReasons...),
		},
		SeveritySupported: map[string]int{}, SeverityCandidates: map[string]int{},
		Index: []IndexRow{}, Findings: []FindingDetail{}, Groups: in.Groups,
		Appendix: Appendix{Rejected: []CandidateRow{}, UnresolvedExplicit: []CandidateRow{}, UnresolvedFailed: []FailedRow{}, Phases: []PhaseRow{},
			AgentsRef: "scan_meta.json#agents", ArtifactsRef: "artifact_manifest.json"},
		Refs: map[string]string{
			"findings": "findings.json", "review_units": "review_units.json", "coverage_ledger": "coverage_ledger.json",
			"hunt_execution": "hunt_execution.json", "sessions": "verification_sessions.json",
			"reconciliation": "verification_reconciliation.json", "artifact_manifest": "artifact_manifest.json",
		},
	}
	if m.Groups == nil {
		m.Groups = []Group{}
	}
	if in.Coverage != nil {
		m.Counts.SourceReview = SourceReview{Completed: in.Coverage.Completed, Exposed: in.Coverage.Exposed, Total: in.Coverage.Total, SemanticsVersion: in.Coverage.SemanticsVersion, Axes: in.Coverage.Axes}
		m.CoverageSemanticsLabel = in.CoverageLabel
	}
	if len(in.Groups) > 0 {
		m.Refs["remediation_groups"] = consolidate.GroupsFile
	}
	if in.Diagram != "" {
		m.Refs["diagram"] = "threat_model_diagram.json"
		m.DiagramSummary = in.Diagram
	}
	failedClass := failedCandidateClasses(in.Doc.RunStatus.Outcome)
	groupOf := map[string]string{}
	for _, g := range in.Groups {
		for _, mem := range g.Members {
			groupOf[mem.ID] = g.ID
		}
	}

	var supported []map[string]any
	for _, f := range in.Doc.Findings {
		cls := consolidate.Classify(f)
		sev := severityOf(f)
		if cls != consolidate.ClassDuplicate {
			m.SeverityCandidates[sev]++
		}
		switch cls {
		case consolidate.ClassDuplicate:
			m.Counts.Duplicates++
		case consolidate.ClassSupported:
			m.Counts.Supported++
			m.SeveritySupported[sev]++
			supported = append(supported, f)
		case consolidate.ClassRejected:
			m.Counts.Rejected++
			m.Appendix.Rejected = append(m.Appendix.Rejected, CandidateRow{
				ID: str(f["id"]), Title: str(f["title"]), Location: str(f["location"]),
				Reason: orText(str(f["verification_reason"]), "reason not recorded"), Action: "no action — refuted by source review",
			})
		case consolidate.ClassUnresolvedExplicit:
			m.Counts.UnresolvedExplicit++
			reason := rec(f, "rationale")
			if reason == "" {
				reason = str(f["verification_reason"])
			}
			m.Appendix.UnresolvedExplicit = append(m.Appendix.UnresolvedExplicit, CandidateRow{
				ID: str(f["id"]), Title: str(f["title"]), Location: str(f["location"]),
				Reason: orText(reason, "reason not recorded"), Action: "investigate: the verifier could not establish or refute this",
			})
		default:
			m.Counts.UnresolvedFailed++
			reason := str(f["verification_reason"])
			if reason == "" {
				reason = str(f["hypothesis_reason"])
			}
			fr := FailedRow{ID: str(f["id"]), Title: str(f["title"]), Location: str(f["location"]), Message: orText(reason, "no verification decision")}
			if fc, ok := failedClass[fr.ID]; ok {
				fr.Class, fr.Operation, fr.Code = fc.Class, fc.Operation, fc.Code
				if fc.Reason != "" {
					fr.Message = fc.Reason
				}
			}
			m.Appendix.UnresolvedFailed = append(m.Appendix.UnresolvedFailed, fr)
		}
	}
	m.Counts.TotalCandidates = m.Counts.Supported + m.Counts.Rejected + m.Counts.UnresolvedExplicit + m.Counts.UnresolvedFailed
	m.Counts.RemediationGroups = len(m.Groups)

	sortBySeverity(supported)
	// Group-first order (FR-020): findings stay in severity order, but every group is
	// emitted contiguously where its highest-severity member first appears — the
	// primary row first, occurrences beneath. Ungrouped findings keep their place.
	roleOf := map[string]string{}
	sizeOf := map[string]int{}
	for _, g := range in.Groups {
		for _, mem := range g.Members {
			roleOf[mem.ID] = mem.Role
			sizeOf[mem.ID] = len(g.Members)
		}
	}
	byID := map[string]map[string]any{}
	for _, f := range supported {
		byID[str(f["id"])] = f
	}
	var ordered []map[string]any
	emitted := map[string]bool{}
	for _, f := range supported {
		id := str(f["id"])
		if emitted[id] {
			continue
		}
		gid := groupOf[id]
		if gid == "" {
			ordered = append(ordered, f)
			emitted[id] = true
			continue
		}
		var members []map[string]any
		for _, g := range in.Groups {
			if g.ID != gid {
				continue
			}
			for _, mem := range g.Members { // primary is first in the record
				if mf, ok := byID[mem.ID]; ok && !emitted[mem.ID] {
					if mem.Role == "primary" {
						members = append([]map[string]any{mf}, members...)
					} else {
						members = append(members, mf)
					}
					emitted[mem.ID] = true
				}
			}
		}
		if len(members) > 1 {
			occ := members[1:]
			sortBySeverity(occ)
		}
		ordered = append(ordered, members...)
	}
	for _, f := range ordered {
		d := findingDetail(f, in)
		d.GroupID = groupOf[d.ID]
		m.Findings = append(m.Findings, d)
		m.Index = append(m.Index, IndexRow{
			ID: d.ID, GroupID: d.GroupID, Role: roleOf[d.ID], GroupSize: sizeOf[d.ID], Title: d.Title, Severity: d.Severity, Surface: surfaceOf(d),
			EvidenceStatus: evidenceStatus(d), Action: actionOf(d), Anchor: "finding-" + d.ID,
		})
	}
	sortRows := func(rows []CandidateRow) {
		sort.SliceStable(rows, func(i, j int) bool { return rows[i].ID < rows[j].ID })
	}
	sortRows(m.Appendix.Rejected)
	sortRows(m.Appendix.UnresolvedExplicit)
	sort.SliceStable(m.Appendix.UnresolvedFailed, func(i, j int) bool { return m.Appendix.UnresolvedFailed[i].ID < m.Appendix.UnresolvedFailed[j].ID })
	m.Appendix.Phases = phaseRows(in)
	m.Summary = buildSummary(&m, in)
	m.Presentation = buildPresentation(&m, in)
	return m
}

// buildPresentation assembles the feature-016 reader-facing projection from the model
// and the records. Every surface reads this; none recomputes it (FR-021, C-P27).
func buildPresentation(m *ReportModel, in Input) *Presentation {
	issues, severity, groupingNotes := buildPrimaryIssues(in)
	p := &Presentation{
		Version:  PresentationVersion,
		Identity: buildIdentity(m, in),
		Scope:    buildScopeNote(m),
		Issues:   issues,
		Priority: BuildPriorityActions(issues, MaxLeading),
		Counts: ReportCounts{
			IssuesToFix: len(issues),
			Severity:    severity,
			// Needs review is labelled separately and is NEVER added into IssuesToFix.
			NeedsReview:        m.Counts.UnresolvedExplicit + m.Counts.UnresolvedFailed,
			NeedsInconclusive:  m.Counts.UnresolvedExplicit,
			NeedsIncomplete:    m.Counts.UnresolvedFailed,
			Dismissed:          m.Counts.Rejected,
			Detections:         m.Counts.Supported,
			CandidatesExamined: m.Counts.TotalCandidates,
		},
		ReviewItems:   buildReviewItems(in, m),
		Dismissed:     buildDismissed(in),
		GroupingNotes: groupingNotes,
	}
	p.Opening = buildOpening(p.Counts, p.Scope, p.Identity.Application)
	return p
}

// buildReviewItems projects the unsettled allegations onto the reader-facing "Needs review"
// list (FR-017, C-C1, C-C2; T072).
//
// Two kinds, labelled distinctly and never merged: an explicit `unresolved` verdict is a
// judgement the verifier made, while a failed session means the assessment did not finish.
// Neither contributes to a vulnerability or severity total, and any recorded severity stays
// explicitly provisional — it was proposed by the allegation, not established by review.
func buildReviewItems(in Input, m *ReportModel) []ReviewItem {
	out := []ReviewItem{}
	failed := map[string]FailedRow{}
	for _, r := range m.Appendix.UnresolvedFailed {
		failed[r.ID] = r
	}
	n := 0
	for _, f := range in.Doc.Findings {
		cls := consolidate.Classify(f)
		if cls != consolidate.ClassUnresolvedExplicit && cls != consolidate.ClassUnresolvedFailed {
			continue
		}
		n++
		it := ReviewItem{
			Ref:      fmt.Sprintf("REVIEW-%03d", n),
			Title:    orText(str(f["title"]), "untitled allegation"),
			Location: strings.TrimSpace(str(f["location"])),
		}
		// A recorded severity here is the allegation's own proposal. It is kept so a reader
		// can triage, and labelled so it is never mistaken for an assessment.
		it.ProvisionalSeverity = strings.TrimSpace(str(f["severity"]))

		if cls == consolidate.ClassUnresolvedExplicit {
			it.Kind = ReviewInconclusive
			reason := firstNonEmptyText(rec(f, "rationale"), str(f["verification_reason"]))
			it.WhatIsUnresolved = "The review examined this and reached no decision either way."
			if reason != "" {
				it.WhatIsUnresolved += " Recorded reason: " + reason
			}
			it.NextStep = "Read the cited code and decide: nothing about this allegation has been established or refuted."
		} else {
			it.Kind = ReviewIncomplete
			it.WhatIsUnresolved = "Assessment not completed: the review stopped before reaching a decision."
			it.NextStep = "Re-examine this location; nothing has been established either way."
			if r, ok := failed[str(f["id"])]; ok && r.Class != "" {
				it.DiagnosticsRef = "scan details — unfinished verification sessions (" + r.ID + ")"
			} else {
				it.DiagnosticsRef = "scan details — unfinished verification sessions"
			}
		}
		out = append(out, it)
	}
	// Deterministic order: unresolved judgements first, then unfinished assessments, each
	// by title so two runs over the same records render identically.
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind == ReviewInconclusive
		}
		if out[i].Title != out[j].Title {
			return out[i].Title < out[j].Title
		}
		return out[i].Location < out[j].Location
	})
	for i := range out {
		out[i].Ref = fmt.Sprintf("REVIEW-%03d", i+1)
	}
	return out
}

// buildDismissed keeps every refuted candidate available with the reason and the decision
// recorded at the time. Presentation never re-decides a dismissal (FR-018, C-C3; T074).
func buildDismissed(in Input) []DismissedRecord {
	out := []DismissedRecord{}
	for _, f := range in.Doc.Findings {
		if consolidate.Classify(f) != consolidate.ClassRejected {
			continue
		}
		out = append(out, DismissedRecord{
			Title:    orText(str(f["title"]), "untitled candidate"),
			Location: strings.TrimSpace(str(f["location"])),
			Reason:   orText(firstNonEmptyText(str(f["verification_reason"]), rec(f, "rationale")), "reason not recorded"),
			Decision: "refuted by review on " + orText(str(f["verification_status"]), "an unrecorded status"),
		})
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Title != out[j].Title {
			return out[i].Title < out[j].Title
		}
		return out[i].Location < out[j].Location
	})
	for i := range out {
		out[i].Ref = fmt.Sprintf("DISMISSED-%03d", i+1)
	}
	return out
}

// buildIdentity records what the report is about. A value the scan did not record stays
// empty rather than being invented (FR-002, C-P2).
func buildIdentity(m *ReportModel, in Input) ReportIdentity {
	id := ReportIdentity{Application: orText(m.Target.Name, in.Target), Revision: m.Target.Revision}
	when := orText(in.FinishedAt, in.StartedAt)
	if when == "" || when == "unrecorded" {
		return id
	}
	id.ScanDate = when
	// The timezone is whatever the record carries; "Z" is UTC. Nothing is localised,
	// because the reader's zone is unknown here.
	if strings.HasSuffix(when, "Z") {
		id.Timezone = "UTC"
	} else if i := strings.LastIndexAny(when, "+-"); i > 10 {
		id.Timezone = "UTC" + when[i:]
	}
	return id
}

// plainExecution renders the recorded execution status in reader-facing words without
// collapsing it into the other axes or improving it.
func plainExecution(status string) string {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "complete":
		return "Complete"
	case "partial", "incomplete":
		return "Incomplete"
	case "cancelled":
		return "Cancelled"
	case "aborted":
		return "Stopped by an error"
	case "interrupted":
		return "Interrupted"
	case "":
		return "Unknown"
	default:
		return status
	}
}

// plainMethod renders the recorded validation mode. It never claims an exploit ran.
func plainMethod(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "static_reasoning", "static", "":
		return "Source-code analysis"
	case "dynamic", "dynamic_execution":
		return "Source-code analysis with executed validation"
	default:
		return mode
	}
}

// findingDetail maps one supported finding to its structured detail. Fields come
// from the verification record first (the source-grounded review), then the
// finding's own fields; nothing is invented.
func findingDetail(f map[string]any, in Input) FindingDetail {
	id := str(f["id"])
	d := FindingDetail{
		ID: id, Title: str(f["title"]), Severity: severityOf(f), CWE: str(f["cwe"]),
		NormalizedCWE: str(f["normalized_cwe"]), CanonicalName: str(f["canonical_name"]),
		Location: str(f["location"]), Classification: str(f["classification"]),
		Impact: rec(f, "security_impact"), Prerequisites: rec(f, "preconditions"),
		AttackerControl: rec(f, "attacker_control"), Defenses: rec(f, "defenses_reviewed"),
		Rationale: rec(f, "rationale"), Fix: str(f["fix"]), Evidence: []Evidence{},
	}
	d.EntryPoint = rec(f, "entry_point")
	if d.EntryPoint == "" {
		d.EntryPoint = str(f["entry_point"])
	}
	d.SourceToSink = str(f["data_flow"])
	if vr, ok := f["verification_record"].(map[string]any); ok {
		for _, e := range asSlice(vr["evidence"]) {
			em, _ := e.(map[string]any)
			if em == nil {
				continue
			}
			d.Evidence = append(d.Evidence, Evidence{Path: str(em["path"]), Start: toInt(em["start_line"]), End: toInt(em["end_line"]), Quote: str(em["quote"])})
		}
		verdict := str(vr["verdict"])
		d.Verification = Verification{Status: str(f["verification_status"]), Reason: str(f["verification_reason"]), ExplicitUnresolved: verdict == "unresolved"}
	} else {
		d.Verification = Verification{Status: str(f["verification_status"]), Reason: str(f["verification_reason"])}
	}
	d.Reproduction = Reproduction{Status: "none"}
	if e := in.Repro[id]; e != nil {
		d.Reproduction = Reproduction{Kind: str(e["kind"]), Status: str(e["status"]), Path: str(e["path"]), Reason: str(e["reason"])}
		if d.Reproduction.Status == "" {
			d.Reproduction.Status = d.Reproduction.Kind
		}
	}
	return d
}

func surfaceOf(d FindingDetail) string {
	if d.EntryPoint != "" {
		return d.EntryPoint
	}
	if i := strings.IndexByte(d.Location, ':'); i > 0 {
		return d.Location[:i]
	}
	return d.Location
}

func evidenceStatus(d FindingDetail) string {
	switch {
	case len(d.Evidence) > 0:
		return EvidenceCaptured
	case d.Verification.Status == "supported":
		return EvidenceMissing
	}
	return NotVerified
}

func actionOf(d FindingDetail) string {
	if strings.TrimSpace(d.Fix) == "" {
		return "fix not provided"
	}
	return clampWords(d.Fix, 24)
}

// failedCandidate mirrors engine.OutcomeSummary.failed_candidates[] through JSON
// (the report package cannot import the engine).
type failedCandidate struct {
	CandidateID string `json:"candidate_id"`
	Class       string `json:"class"`
	Reason      string `json:"reason"`
	Operation   string `json:"operation,omitempty"`
	Code        string `json:"code,omitempty"`
}

func failedCandidateClasses(outcome any) map[string]failedCandidate {
	out := map[string]failedCandidate{}
	if outcome == nil {
		return out
	}
	b, err := json.Marshal(outcome)
	if err != nil {
		return out
	}
	var oc struct {
		FailedCandidates []failedCandidate `json:"failed_candidates"`
	}
	if json.Unmarshal(b, &oc) != nil {
		return out
	}
	for _, fc := range oc.FailedCandidates {
		out[fc.CandidateID] = fc
	}
	return out
}

// phaseRows summarizes the per-agent rows by phase (the agent rows themselves are
// on demand via AgentsRef).
func phaseRows(in Input) []PhaseRow {
	byPhase := map[string]*PhaseRow{}
	var order []string
	for _, o := range phaseOutcomes(in) {
		r, ok := byPhase[o.Phase]
		if !ok {
			r = &PhaseRow{Phase: o.Phase, Stops: map[string]int{}, Produced: o.Produced}
			byPhase[o.Phase] = r
			order = append(order, o.Phase)
		}
		r.Agents++
		r.Turns += o.Turns
		r.Stops[o.Stop]++
		r.PromptTokens += o.PT
		r.CompletionTokens += o.CT
	}
	out := make([]PhaseRow, 0, len(order))
	for _, p := range order {
		out = append(out, *byPhase[p])
	}
	return out
}

func severityOf(f map[string]any) string {
	s := str(f["severity"])
	if s == "" {
		return consolidate.DefaultSeverity
	}
	return s
}

func sortBySeverity(fs []map[string]any) {
	sort.SliceStable(fs, func(i, j int) bool {
		ri, rj := toInt(fs[i]["severity_rank"]), toInt(fs[j]["severity_rank"])
		if ri != rj {
			return ri < rj
		}
		return str(fs[i]["id"]) < str(fs[j]["id"])
	})
}

func orText(s, alt string) string {
	if strings.TrimSpace(s) == "" {
		return alt
	}
	return s
}

// clampWords keeps the first n words of s.
func clampWords(s string, n int) string {
	ws := strings.Fields(s)
	if len(ws) <= n {
		return strings.Join(ws, " ")
	}
	return strings.Join(ws[:n], " ") + " …"
}

// WriteModel persists report_model.json (indented, deterministic key order).
func WriteModel(m ReportModel, resultsDir string) (string, error) {
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return "", err
	}
	p := filepath.Join(resultsDir, ModelFile)
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o644); err != nil {
		return "", err
	}
	return p, os.Rename(tmp, p)
}

// LoadModel reads a persisted report model.
func LoadModel(resultsDir string) (ReportModel, error) {
	var m ReportModel
	b, err := os.ReadFile(filepath.Join(resultsDir, ModelFile))
	if err != nil {
		return m, err
	}
	if err := json.Unmarshal(b, &m); err != nil {
		return m, fmt.Errorf("%s: %w", ModelFile, err)
	}
	return m, nil
}
