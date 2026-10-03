package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"vhlocal/internal/agent"
	"vhlocal/internal/client"
	"vhlocal/internal/inventory"
	"vhlocal/internal/phases"
	"vhlocal/internal/recognize"
	"vhlocal/internal/tools"
)

// Feature 014 US2 (FR-010..016): evidence-backed review units.
//
// Every eligible entry point (feature-012 inventory) maps to a hunt assignment or
// an explicit reason; every attempted unit ends with ONE validated disposition per
// assigned route, derived from OBSERVED tool evidence — the unit's deliverable
// validated AND the route's handler span was actually READ by that unit (ReadSpan)
// AND the route lies in the unit's assigned scope AND the revision is current.
// A prose claim, a path mention, a read outside the span, or a normal agent stop
// never establishes review. This is what makes "reviewed, no issue" real without
// manufacturing a finding, and keeps 8/100 honest when only 8 were reviewed.

// ReviewUnitsFile is the persisted record consumed by BuildLedger and the report.
const ReviewUnitsFile = "review_units.json"

// Disposition vocabulary (FR-012).
const (
	RevWithFindings = "reviewed_with_findings"
	RevNoIssue      = "reviewed_no_issue"
	RevPartial      = "partial"
	RevFailed       = "failed"
	RevSkipped      = "skipped"
	RevUnsupported  = "unsupported"
	RevNotReviewed  = "not_reviewed"
)

// Gap reasons (FR-015).
const (
	GapUnsupportedScope  = "unsupported_scope"
	GapAssignmentFailure = "assignment_failure"
	GapCancelled         = "cancelled"
	GapBudget            = "budget"
	GapModelToolFailure  = "model_tool_failure"
	GapRetryExhausted    = "retry_exhausted"
	GapNotAttempted      = "not_attempted"
	// GapNoDisposition (feature 015): the handler was read (source exposure) but no
	// validated per-handler disposition credits it.
	GapNoDisposition = "no_disposition"
)

type ReviewAssignment struct {
	RouteID  string `json:"route_id"`
	File     string `json:"file"`
	Line     int    `json:"line"`
	Language string `json:"language,omitempty"`
	UnitID   string `json:"unit_id,omitempty"` // partition slug whose units cover this route
	Reason   string `json:"reason,omitempty"`  // when unassigned
}

type ReviewDisposition struct {
	RouteID     string   `json:"route_id"`
	Disposition string   `json:"disposition"`
	Rationale   string   `json:"rationale"`
	UnitLabel   string   `json:"unit_label,omitempty"`
	Evidence    []string `json:"evidence,omitempty"`
	// Feature 015 (semantics v2): the structured per-handler conclusions and the
	// harness verdict on each; empty under v1.
	Checks        []CheckResult        `json:"checks,omitempty"`
	HandlerBlocks []HandlerDisposition `json:"handler_dispositions,omitempty"`
	Exposed       bool                 `json:"source_exposed,omitempty"`
	Unresolved    []string             `json:"unresolved,omitempty"`
}

type ReviewUnitRecord struct {
	UnitID        string           `json:"unit_id"`
	Label         string           `json:"label"`
	Partition     string           `json:"partition"`
	Class         string           `json:"class"`
	Sample        int              `json:"sample"`
	Attempts      int              `json:"attempts"`
	Deliverable   string           `json:"deliverable"`
	Valid         bool             `json:"valid"`
	StoppedReason string           `json:"stopped_reason"`
	Produced      bool             `json:"produced"`
	Skipped       string           `json:"skipped,omitempty"`
	Reads         []agent.ReadSpan `json:"reads,omitempty"`
	// Feature 015 (T051): the unit's disposition tally; NoDispositions marks a valid
	// deliverable that wrote no `## Handler dispositions` section.
	Dispositions   *DispositionCounts `json:"dispositions,omitempty"`
	NoDispositions bool               `json:"no_dispositions,omitempty"`
}

type ReviewGap struct {
	RouteID string `json:"route_id"`
	Reason  string `json:"reason"`
}

// ReviewUnits is the persisted record.
type ReviewUnits struct {
	// SemanticsVersion (feature 015, FR-019): 1 = read-overlap evidence (feature 014),
	// 2 = validated structured dispositions. Absent on disk ⇒ 1 when loaded.
	SemanticsVersion int                 `json:"semantics_version,omitempty"`
	Revision         string              `json:"revision"`
	Assignments      []ReviewAssignment  `json:"assignments"`
	Units            []ReviewUnitRecord  `json:"units"`
	Dispositions     []ReviewDisposition `json:"dispositions"`
	Gaps             []ReviewGap         `json:"gaps"`
	FollowUpRan      bool                `json:"follow_up_ran"`
	Counts           UnitCounts          `json:"counts"`
	// Axes (feature 015, FR-015): the separate coverage axes; none derived from another.
	Axes CoverageAxes `json:"axes"`
	// Unrecognized (feature 015): disposition blocks naming no inventory route —
	// recorded with identity=fabricated, never credited.
	Unrecognized []HandlerDisposition `json:"unrecognized_dispositions,omitempty"`
}

// CoverageAxes are the feature-015 coverage axes (data-model "review units v2").
type CoverageAxes struct {
	Discovered         int `json:"discovered"`
	SupportedInventory int `json:"supported_inventory"`
	Assigned           int `json:"assigned"`
	Attempted          int `json:"attempted"`
	SourceExposed      int `json:"source_exposed"`
	CompletedReview    int `json:"completed_review"`
	Verified           int `json:"verified"`
}

// unitEvidence is collected during the hunt (unexported, not serialized directly).
type unitEvidence struct {
	label, partSlug, class string
	sample                 int
	deliverable            string
	valid                  bool
	stopped                string
	produced               bool
	reads                  []agent.ReadSpan
	skipped                string // reason when the unit never ran
	attempts               int
	followUp               bool
	citation               *CitationStats // feature 015 (FR-025): per-unit citation validation
}

// RouteID is the stable identity for an inventory route: file:line + method path.
func RouteID(r inventory.Route) string {
	return fmt.Sprintf("%s:%d %s %s", r.File, r.Line, r.Method, r.Path)
}

// partitionCovers reports whether a partition's scope description names the route's
// file, its subsystem (as a whole token), or its "METHOD PATH".
func partitionCovers(p phases.Partition, r inventory.Route) bool {
	d := p.Description
	if r.File != "" && strings.Contains(d, r.File) {
		return true
	}
	if r.Method != "" && r.Path != "" && strings.Contains(d, r.Method+" "+r.Path) {
		return true
	}
	if r.Subsystem != "" {
		for _, tok := range strings.FieldsFunc(d, func(c rune) bool {
			return !(c == '_' || c == '-' || c == '/' || c == '.' || (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'))
		}) {
			if tok == r.Subsystem {
				return true
			}
		}
	}
	return false
}

// handlerSpans memoizes handler spans per route (file+line).
type handlerSpans struct {
	repo  string
	cache map[string]recognize.Scope
	src   map[string][]byte
}

func newHandlerSpans(repo string) *handlerSpans {
	return &handlerSpans{repo: repo, cache: map[string]recognize.Scope{}, src: map[string][]byte{}}
}

func (h *handlerSpans) scopeFor(r inventory.Route) recognize.Scope {
	key := fmt.Sprintf("%s:%d", r.File, r.Line)
	if sc, ok := h.cache[key]; ok {
		return sc
	}
	src, ok := h.src[r.File]
	if !ok {
		b, err := os.ReadFile(filepath.Join(h.repo, r.File))
		if err != nil {
			b = nil
		}
		src, h.src[r.File] = b, b
	}
	var sc recognize.Scope
	if src != nil {
		lang, ok := recognize.LanguageFor(r.File)
		if !ok && r.Language != "" {
			lang, ok = recognize.Language(r.Language), true
		}
		if !ok {
			lang = recognize.LangPython
		}
		// A registration-style route (Go HandleFunc) names its handler: the honest
		// span is the HANDLER FUNCTION, not the registration block — otherwise reading
		// the registration list would "cover" every handler at once (FR-014).
		line := r.Line
		if r.Handler != "" {
			if hl := handlerDeclLine(src, r.Handler); hl > 0 {
				line = hl
			}
		}
		sc = recognize.EnclosingScope(lang, src, line)
	}
	h.cache[key] = sc
	return sc
}

// handlerDeclLine finds the 1-based line declaring `func <name>(` (or `func (recv) <name>(`);
// 0 when absent. Purely textual; the recognizer already validated the reference.
func handlerDeclLine(src []byte, name string) int {
	if i := strings.LastIndex(name, "."); i >= 0 {
		name = name[i+1:] // pkg.Handler / recv.Method → method name
	}
	for i, ln := range strings.Split(string(src), "\n") {
		t := strings.TrimSpace(ln)
		if !strings.HasPrefix(t, "func ") {
			continue
		}
		rest := strings.TrimPrefix(t, "func ")
		if strings.HasPrefix(rest, "(") { // method: skip receiver
			if j := strings.Index(rest, ")"); j >= 0 {
				rest = strings.TrimSpace(rest[j+1:])
			}
		}
		if strings.HasPrefix(rest, name+"(") {
			return i + 1
		}
	}
	return 0
}

// relFile normalizes a ReadSpan file (absolute or relative) to repo-relative.
func relFile(repo, f string) string {
	if filepath.IsAbs(f) {
		if rel, err := filepath.Rel(repo, f); err == nil && !strings.HasPrefix(rel, "..") {
			return filepath.ToSlash(rel)
		}
		return f
	}
	return filepath.ToSlash(filepath.Clean(f))
}

// readIntersects reports whether a read span overlaps a handler span.
func readIntersects(rd agent.ReadSpan, sc recognize.Scope) bool {
	if !sc.Found {
		return false
	}
	end := rd.End
	if end <= 0 {
		end = 1 << 30 // to EOF
	}
	return rd.Start <= sc.End && end >= sc.Start
}

// buildReviewUnits derives assignments, dispositions and gaps from the hunt's unit
// evidence, the inventory, the partitions and the resolved finding locations.
func buildReviewUnitsV1(spec ScanSpec, rec *RunRecord, routes []inventory.Route, findingLocs []inventory.FindingLoc) *ReviewUnits {
	// Gaps is always an array in the record (a live 100/100 run wrote `null`, which
	// contract readers had to special-case); empty means "no gaps", not "unknown".
	ru := &ReviewUnits{Revision: rec.GitCommit, FollowUpRan: rec.followUpRan, Gaps: []ReviewGap{}}
	spans := newHandlerSpans(spec.Repo)

	// Units (deterministic order by label).
	units := append([]unitEvidence(nil), rec.units...)
	sort.SliceStable(units, func(i, j int) bool { return units[i].label < units[j].label })
	byPart := map[string][]unitEvidence{}
	for _, u := range units {
		ru.Units = append(ru.Units, ReviewUnitRecord{
			UnitID: u.partSlug + "_" + strings.ToLower(u.class), Label: u.label, Partition: u.partSlug,
			Class: u.class, Sample: u.sample, Attempts: u.attempts, Deliverable: u.deliverable,
			Valid: u.valid, StoppedReason: u.stopped, Produced: u.produced, Skipped: u.skipped, Reads: u.reads,
		})
		byPart[u.partSlug] = append(byPart[u.partSlug], u)
	}

	// Assignments: each route → covering partition (first in deterministic order).
	for _, r := range routes {
		a := ReviewAssignment{RouteID: RouteID(r), File: r.File, Line: r.Line, Language: r.Language}
		for _, p := range rec.parts {
			if partitionCovers(p, r) {
				a.UnitID = p.Slug()
				break
			}
		}
		if a.UnitID == "" {
			a.Reason = "no hunt partition covers this entry point"
		}
		ru.Assignments = append(ru.Assignments, a)
	}

	// Dispositions.
	ru.Counts.Total = len(routes)
	for i, r := range routes {
		a := ru.Assignments[i]
		d := ReviewDisposition{RouteID: a.RouteID}
		sc := spans.scopeFor(r)

		// In-span finding → reviewed with findings (the unchanged ledger rule).
		hasFinding := false
		for _, f := range findingLocs {
			if f.File == r.File && ((sc.Found && f.Line >= sc.Start && f.Line <= sc.End) || (!sc.Found && f.Line == r.Line)) {
				hasFinding = true
				d.Evidence = append(d.Evidence, fmt.Sprintf("finding at %s:%d within handler", f.File, f.Line))
			}
		}
		switch {
		case hasFinding:
			d.Disposition, d.Rationale = RevWithFindings, "finding located inside the handler span"
			ru.Counts.ReviewedWithFindings++
		case a.UnitID == "":
			d.Disposition, d.Rationale = RevUnsupported, a.Reason
			ru.Counts.Unsupported++
			ru.Gaps = append(ru.Gaps, ReviewGap{RouteID: a.RouteID, Reason: GapUnsupportedScope})
		default:
			ru.Counts.Assigned++
			us := byPart[a.UnitID]
			ran, anyValid, anyFailed := false, false, false
			var skipReason string
			for _, u := range us {
				if u.skipped != "" {
					skipReason = u.skipped
					continue
				}
				ran = true
				if u.valid {
					anyValid = true
				} else {
					anyFailed = true
				}
			}
			if !ran {
				d.Disposition = RevSkipped
				reason := GapAssignmentFailure
				switch skipReason {
				case GapCancelled, GapBudget, GapModelToolFailure:
					reason = skipReason
				}
				d.Rationale = "no unit of the covering partition ran (" + reason + ")"
				ru.Counts.Skipped++
				ru.Gaps = append(ru.Gaps, ReviewGap{RouteID: a.RouteID, Reason: reason})
				break
			}
			ru.Counts.Attempted++
			if !sc.Found {
				d.Disposition, d.Rationale = RevNotReviewed, "handler span could not be resolved; only an in-span finding could evidence review"
				ru.Counts.NotReviewed++
				ru.Gaps = append(ru.Gaps, ReviewGap{RouteID: a.RouteID, Reason: GapUnsupportedScope})
				break
			}
			// Evidence: a VALID unit of the covering partition READ the handler span.
			evidenced := false
			for _, u := range us {
				if !u.valid {
					continue
				}
				for _, rd := range u.reads {
					if relFile(spec.Repo, rd.File) == r.File && readIntersects(rd, sc) {
						evidenced = true
						d.UnitLabel = u.label
						d.Evidence = append(d.Evidence, fmt.Sprintf("read %s:%d-%d by %s (deliverable valid)", r.File, rd.Start, rd.End, u.label))
						break
					}
				}
				if evidenced {
					break
				}
			}
			switch {
			case evidenced:
				d.Disposition, d.Rationale = RevNoIssue, "handler span read by a validated unit; no finding located in it (not proof of absence of vulnerabilities)"
				ru.Counts.ReviewedNoIssue++
			case anyValid:
				d.Disposition, d.Rationale = RevPartial, "the covering unit(s) completed but never read this handler's span"
				ru.Counts.Partial++
				reason := GapNotAttempted
				if rec.followUpRan {
					reason = GapRetryExhausted
				}
				ru.Gaps = append(ru.Gaps, ReviewGap{RouteID: a.RouteID, Reason: reason})
			case anyFailed:
				d.Disposition, d.Rationale = RevFailed, "no covering unit produced a valid deliverable"
				ru.Counts.Failed++
				reason := GapModelToolFailure
				if rec.followUpRan {
					reason = GapRetryExhausted
				}
				ru.Gaps = append(ru.Gaps, ReviewGap{RouteID: a.RouteID, Reason: reason})
			default:
				d.Disposition, d.Rationale = RevNotReviewed, "no evidence of review"
				ru.Counts.NotReviewed++
				ru.Gaps = append(ru.Gaps, ReviewGap{RouteID: a.RouteID, Reason: GapNotAttempted})
			}
		}
		ru.Dispositions = append(ru.Dispositions, d)
	}
	return ru
}

func writeReviewUnits(resultsDir string, ru *ReviewUnits) error {
	_, err := writeJSON(filepath.Join(resultsDir, ReviewUnitsFile), ru)
	return err
}

func loadReviewUnits(resultsDir string) (*ReviewUnits, bool) {
	b, err := os.ReadFile(filepath.Join(resultsDir, ReviewUnitsFile))
	if err != nil {
		return nil, false
	}
	var ru ReviewUnits
	if json.Unmarshal(b, &ru) != nil {
		return nil, false
	}
	if ru.SemanticsVersion == 0 {
		ru.SemanticsVersion = 1
	}
	return &ru, true
}

// ledgerEvidence converts review dispositions into the ledger's evidence input.
// Evidence recorded at a DIFFERENT revision is stale and contributes nothing
// (FR-014): only in-span findings can then mark a route reviewed.
func ledgerEvidence(ru *ReviewUnits, currentRevision string) map[string]inventory.RouteEvidence {
	out := map[string]inventory.RouteEvidence{}
	if ru == nil || (ru.Revision != "" && currentRevision != "" && ru.Revision != currentRevision) {
		return out
	}
	for _, d := range ru.Dispositions {
		switch d.Disposition {
		case RevNoIssue:
			out[d.RouteID] = inventory.RouteEvidence{Disposition: inventory.DispReviewedNoIssue, UnitID: d.UnitLabel, Reason: d.Rationale, EvidenceRef: strings.Join(d.Evidence, "; ")}
		case RevUnsupported:
			out[d.RouteID] = inventory.RouteEvidence{Disposition: inventory.DispExcluded, Reason: d.Rationale}
		}
	}
	return out
}

// gapsByPartition returns, per covering partition slug, the routes assigned to it
// whose handler span has not yet been read by a valid unit (used for follow-up).
func gapsByPartitionV1(spec ScanSpec, rec *RunRecord, routes []inventory.Route) map[string][]inventory.Route {
	spans := newHandlerSpans(spec.Repo)
	valid := map[string][]unitEvidence{}
	for _, u := range rec.units {
		if u.valid {
			valid[u.partSlug] = append(valid[u.partSlug], u)
		}
	}
	out := map[string][]inventory.Route{}
	for _, r := range routes {
		var slug string
		for _, p := range rec.parts {
			if partitionCovers(p, r) {
				slug = p.Slug()
				break
			}
		}
		if slug == "" {
			continue
		}
		sc := spans.scopeFor(r)
		if !sc.Found {
			continue
		}
		read := false
		for _, u := range valid[slug] {
			for _, rd := range u.reads {
				if relFile(spec.Repo, rd.File) == r.File && readIntersects(rd, sc) {
					read = true
					break
				}
			}
			if read {
				break
			}
		}
		if !read {
			out[slug] = append(out[slug], r)
		}
	}
	return out
}

// recordSkippedUnits records every planned (partition × class × sample) unit that
// never ran, with the real reason (cancelled / budget / model_tool_failure via the
// breaker / assignment_failure), so its routes read `skipped` honestly (FR-015).
func recordSkippedUnits(rec *RunRecord, parts []phases.Partition, groups []phases.ClassGroup, nSamples int,
	ctx context.Context, brk, budgetTrip func() bool) {
	ran := map[string]bool{}
	for _, u := range rec.units {
		ran[u.label] = true
	}
	reason := GapAssignmentFailure
	switch {
	case ctx.Err() != nil:
		reason = GapCancelled
	case budgetTrip():
		reason = GapBudget
	case brk():
		reason = GapModelToolFailure
	}
	for _, part := range parts {
		for _, g := range groups {
			for si := 1; si <= nSamples; si++ {
				label := "hunt:" + part.Slug() + ":" + strings.ToLower(g.Code)
				if nSamples > 1 {
					label = fmt.Sprintf("%s.s%d", label, si)
				}
				if ran[label] {
					continue
				}
				rec.units = append(rec.units, unitEvidence{label: label, partSlug: part.Slug(), class: g.Code, sample: si, skipped: reason})
			}
		}
	}
}

// runFollowUpUnits schedules ONE bounded follow-up unit per partition that still has
// unreviewed entry points (FR-015), under the existing ctx/budget/breaker rules. The
// unit's task names the exact unreviewed routes so its reads (real tool evidence)
// can close the gaps; a normal stop without a valid deliverable closes nothing.
func runFollowUpUnits(ctx context.Context, rec *RunRecord, p client.Provider, sb *tools.Sandbox, spec ScanSpec, skill SkillSource,
	system, shared, base, model, resultsSub string, maxTurns int, parts []phases.Partition, emit Emit, stop func() bool) {
	gaps := gapsByPartition(spec, rec, rec.routes)
	if len(gaps) == 0 {
		return
	}
	rec.followUpRan = true
	classPrompt := ""
	for _, cg := range phases.ClassGroups {
		cp, _ := skill.Prompt(cg.PromptFile)
		classPrompt += cp + "\n\n"
	}
	g := phases.ClassGroup{Code: "FOLLOWUP", Blurb: "the specific entry points that have not been reviewed yet"}
	for _, part := range parts {
		rs, ok := gaps[part.Slug()]
		if !ok || len(rs) == 0 {
			continue
		}
		if ctx.Err() != nil || stop() {
			return
		}
		var scope strings.Builder
		scope.WriteString(part.Description + "\n\nUNREVIEWED ENTRY POINTS — read each handler and review it:\n")
		for _, r := range rs {
			fmt.Fprintf(&scope, "- %s %s (%s:%d)\n", r.Method, r.Path, r.File, r.Line)
		}
		label := "hunt:" + part.Slug() + ":followup"
		sfile := filepath.Join(resultsSub, part.Slug()+"_followup.md")
		emit.emit("retry", map[string]any{"label": label, "attempt": 1, "reason": fmt.Sprintf("%d unreviewed entry point(s) in partition %s", len(rs), part.Ident)})
		emit.emit("agent_start", map[string]any{"label": label, "model": model, "partition": part.Ident, "class": g.Code})
		task := buildHuntTask(spec, scope.String(), g, shared, base, classPrompt, sfile, assignedHandlers(rec.routes, part)...)
		cfg := agent.Config{Model: model, NumCtx: spec.NumCtx, MaxTurns: maxTurns,
			Temperature: spec.Temperature, MaxOutputTokens: spec.MaxOutputTokens,
			ReasoningEffort: spec.ReasoningEffort, DeliverablePath: sfile}
		pp := recordPrompts(p, rec.prompts, promptMeta{scanTag: spec.ScanTag, phase: "2", label: label, role: "hunt", model: model})
		res, err := agent.Run(ctx, pp, sb, cfg, system, task)
		recordAgent(rec, "2", model, res)
		rec.Agents[len(rec.Agents)-1].Label = label
		rec.Agents[len(rec.Agents)-1].Partition = part.Ident
		rec.Agents[len(rec.Agents)-1].VulnClass = g.Code
		rec.Agents[len(rec.Agents)-1].Produced = res.Produced
		valid := err == nil && deliverableValid(sfile)
		rec.units = append(rec.units, unitEvidence{label: label, partSlug: part.Slug(), class: g.Code, sample: 1,
			deliverable: sfile, valid: valid, stopped: res.StoppedReason, produced: res.Produced, reads: res.Reads, attempts: 1, followUp: true})
		if valid {
			emit.emit("output_written", map[string]any{"label": label, "path": sfile})
		} else {
			emit.emit("validation_failure", map[string]any{"label": label, "path": sfile, "reason": "follow-up unit stopped without a valid deliverable"})
		}
		emit.emit("agent_done", map[string]any{"label": label, "turns": res.Turns, "stopped_reason": res.StoppedReason, "produced": res.Produced})
	}
}

// Coverage semantics versions (feature 015, FR-019).
const (
	CoverageSemanticsV1 = 1 // feature 014: valid deliverable + a read overlapping the handler span
	CoverageSemanticsV2 = 2 // feature 015: validated structured per-handler disposition
)

// SemanticsLabel names the evidence standard a record was produced under; every
// surface that shows v1 counts carries it so weaker evidence is never mistaken
// for analysis.
func SemanticsLabel(version int) string {
	switch version {
	case 0, CoverageSemanticsV1:
		return "read-overlap evidence (v1)"
	case CoverageSemanticsV2:
		return "validated handler dispositions (v2)"
	}
	return fmt.Sprintf("unknown coverage semantics (v%d)", version)
}

// Label returns the record's semantics label.
func (ru *ReviewUnits) Label() string {
	if ru == nil {
		return SemanticsLabel(0)
	}
	return SemanticsLabel(ru.SemanticsVersion)
}

// assignedHandlers lists the stable route ids a partition covers (feature 015):
// the unit's task names them and its dispositions must address them.
func assignedHandlers(routes []inventory.Route, p phases.Partition) []string {
	var out []string
	for _, r := range routes {
		if partitionCovers(p, r) {
			out = append(out, RouteID(r))
		}
	}
	return out
}
