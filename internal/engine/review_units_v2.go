package engine

import (
	"fmt"
	"sort"
	"strings"

	"vhlocal/internal/inventory"
)

// Feature 015 (FR-015..019) — coverage semantics v2.
//
// A route is `reviewed_no_issue` only when a VALIDATED structured disposition
// (dispositions.go) credits it: every planned weakness class of the covering
// partition is `done` or explained `n_a` by the unit of that class (or a follow-up
// unit). Reads are recorded as SOURCE EXPOSURE — a separate axis that never
// becomes analysis credit. Unresolved checks make the route `partial` with the
// reasons; a read without a disposition is a `no_disposition` gap that the
// existing bounded follow-up can close. Every rejected disposition is kept on the
// record with the harness verdict so an operator can see why it earned nothing.

// routeCredit is one route's v2 assessment.
type routeCredit struct {
	exposed    bool
	credited   bool
	partial    bool
	status     map[string]string
	unresolved []string
	blocks     []HandlerDisposition
	unitLabel  string
	planned    []string
}

// assessRoute derives a route's exposure and credit from the covering partition's
// units (dispositions are parsed from each valid unit's deliverable on disk).
func assessRoute(spec ScanSpec, rec *RunRecord, r inventory.Route, routeID string, us []unitEvidence,
	assigned map[string]bool, byID map[string]inventory.Route, spans *handlerSpans, dispCache map[string][]HandlerDisposition) routeCredit {
	rc := routeCredit{status: map[string]string{}}
	sc := spans.scopeFor(r)
	planned := map[string]bool{}
	for _, u := range us {
		if u.skipped != "" || u.class == "FOLLOWUP" {
			continue
		}
		planned[strings.ToUpper(u.class)] = true
	}
	for c := range planned {
		rc.planned = append(rc.planned, c)
	}
	sort.Strings(rc.planned)
	for _, u := range us {
		if !u.valid {
			continue
		}
		// Exposure: the unit READ the handler span.
		if sc.Found {
			for _, rd := range u.reads {
				if relFile(spec.Repo, rd.File) == r.File && readIntersects(rd, sc) {
					rc.exposed = true
					if rc.unitLabel == "" {
						rc.unitLabel = u.label
					}
					break
				}
			}
		}
		// Dispositions for this route from this unit, validated against the unit.
		ds, ok := dispCache[u.deliverable]
		if !ok {
			ds = readDispositions(u.deliverable)
			dispCache[u.deliverable] = ds
		}
		for _, d := range ds {
			if d.RouteID != routeID {
				continue
			}
			validateDisposition(&d, u, assigned, byID, spans, spec.Repo, rec.GitCommit, rec.GitCommit)
			rc.blocks = append(rc.blocks, d)
		}
	}
	rc.credited, rc.partial, rc.status, rc.unresolved = aggregateChecks(rc.planned, rc.blocks)
	return rc
}

// buildReviewUnits assembles the v2 record (assignments, units, dispositions, gaps,
// counts and axes) from live unit evidence. Regeneration never calls it (no
// in-memory evidence); it reloads the persisted record instead.
func buildReviewUnits(spec ScanSpec, rec *RunRecord, routes []inventory.Route, findingLocs []inventory.FindingLoc) *ReviewUnits {
	ru := &ReviewUnits{SemanticsVersion: CoverageSemanticsV2, Revision: rec.GitCommit, FollowUpRan: rec.followUpRan, Gaps: []ReviewGap{}}
	spans := newHandlerSpans(spec.Repo)

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

	byID := map[string]inventory.Route{}
	assignedByPart := map[string]map[string]bool{}
	for _, r := range routes {
		a := ReviewAssignment{RouteID: RouteID(r), File: r.File, Line: r.Line, Language: r.Language}
		byID[a.RouteID] = r
		for _, p := range rec.parts {
			if partitionCovers(p, r) {
				a.UnitID = p.Slug()
				break
			}
		}
		if a.UnitID == "" {
			a.Reason = "no hunt partition covers this entry point"
		} else {
			if assignedByPart[a.UnitID] == nil {
				assignedByPart[a.UnitID] = map[string]bool{}
			}
			assignedByPart[a.UnitID][a.RouteID] = true
		}
		ru.Assignments = append(ru.Assignments, a)
	}

	dispCache := map[string][]HandlerDisposition{}
	ru.Counts.Total = len(routes)
	ru.Axes.Discovered = len(routes)
	ru.Axes.SupportedInventory = len(routes)
	for i, r := range routes {
		a := ru.Assignments[i]
		d := ReviewDisposition{RouteID: a.RouteID}
		sc := spans.scopeFor(r)

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
			ru.Axes.CompletedReview++
			ru.Axes.Verified++
		case a.UnitID == "":
			d.Disposition, d.Rationale = RevUnsupported, a.Reason
			ru.Counts.Unsupported++
			ru.Gaps = append(ru.Gaps, ReviewGap{RouteID: a.RouteID, Reason: GapUnsupportedScope})
		default:
			ru.Counts.Assigned++
			ru.Axes.Assigned++
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
			ru.Axes.Attempted++
			if !sc.Found {
				d.Disposition, d.Rationale = RevNotReviewed, "handler span could not be resolved; only an in-span finding could evidence review"
				ru.Counts.NotReviewed++
				ru.Gaps = append(ru.Gaps, ReviewGap{RouteID: a.RouteID, Reason: GapUnsupportedScope})
				break
			}
			rc := assessRoute(spec, rec, r, a.RouteID, us, assignedByPart[a.UnitID], byID, spans, dispCache)
			d.Exposed = rc.exposed
			d.HandlerBlocks = rc.blocks
			d.UnitLabel = rc.unitLabel
			d.Unresolved = rc.unresolved
			for _, c := range rc.planned {
				st := rc.status[c]
				if st == "" {
					st = "missing"
				}
				d.Checks = append(d.Checks, CheckResult{Class: c, Status: st})
			}
			if rc.exposed {
				ru.Counts.SourceExposed++
				ru.Axes.SourceExposed++
				d.Evidence = append(d.Evidence, fmt.Sprintf("handler span read by %s (source exposure)", rc.unitLabel))
			}
			reason := GapNotAttempted
			if rec.followUpRan {
				reason = GapRetryExhausted
			}
			switch {
			case rc.credited:
				d.Disposition = RevNoIssue
				d.Rationale = "validated handler disposition: " + dispositionSummary(rc.status) + " — no issue identified within the stated scope (not proof of absence of vulnerabilities)"
				ru.Counts.ReviewedNoIssue++
				ru.Axes.CompletedReview++
			case rc.partial:
				d.Disposition = RevPartial
				d.Rationale = "handler disposition left checks unresolved: " + strings.Join(rc.unresolved, "; ")
				if len(rc.unresolved) == 0 {
					d.Rationale = "handler disposition incomplete: " + dispositionSummary(rc.status)
				}
				ru.Counts.Partial++
				ru.Gaps = append(ru.Gaps, ReviewGap{RouteID: a.RouteID, Reason: reason})
			case rc.exposed:
				d.Disposition = RevNotReviewed
				if len(rc.blocks) > 0 {
					d.Rationale = "handler span read, but no disposition validated (" + blockVerdicts(rc.blocks) + ") — source exposure only"
				} else {
					d.Rationale = "handler span read, but no handler disposition was recorded — source exposure only"
				}
				ru.Counts.NotReviewed++
				ru.Gaps = append(ru.Gaps, ReviewGap{RouteID: a.RouteID, Reason: GapNoDisposition})
			case anyValid:
				d.Disposition, d.Rationale = RevPartial, "the covering unit(s) completed but never read this handler's span"
				ru.Counts.Partial++
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
	// Blocks that name no inventory route are kept (identity=fabricated), never credited.
	for _, u := range units {
		if !u.valid {
			continue
		}
		ds, ok := dispCache[u.deliverable]
		if !ok {
			ds = readDispositions(u.deliverable)
			dispCache[u.deliverable] = ds
		}
		for _, d := range ds {
			if _, known := byID[d.RouteID]; known {
				continue
			}
			validateDisposition(&d, u, assignedByPart[u.partSlug], byID, spans, spec.Repo, rec.GitCommit, rec.GitCommit)
			ru.Unrecognized = append(ru.Unrecognized, d)
		}
	}
	// Per-unit tally (hunt_execution.detail mirrors it): parsed = credited + rejected.
	tally := map[string]*DispositionCounts{}
	count := func(d HandlerDisposition) {
		c := tally[d.UnitID]
		if c == nil {
			c = &DispositionCounts{}
			tally[d.UnitID] = c
		}
		c.Parsed++
		if d.Validation.OK() {
			c.Credited++
		} else {
			c.Rejected++
		}
	}
	for _, d := range ru.Dispositions {
		for _, hb := range d.HandlerBlocks {
			count(hb)
		}
	}
	for _, d := range ru.Unrecognized {
		count(d)
	}
	for i := range ru.Units {
		u := &ru.Units[i]
		if !u.Valid {
			continue
		}
		if c := tally[u.Label]; c != nil {
			u.Dispositions = c
		} else {
			u.Dispositions = &DispositionCounts{}
			u.NoDispositions = true
		}
	}
	return ru
}

// blockVerdicts summarizes why recorded dispositions were not credited.
func blockVerdicts(blocks []HandlerDisposition) string {
	var parts []string
	for _, b := range blocks {
		v := b.Validation
		var bad []string
		if v.Identity != ValOK {
			bad = append(bad, "identity="+v.Identity)
		}
		if v.Scope != ValOK {
			bad = append(bad, "scope="+v.Scope)
		}
		if v.Revision != ValOK {
			bad = append(bad, "revision="+v.Revision)
		}
		if v.Evidence != ValOK {
			bad = append(bad, "evidence="+v.Evidence)
		}
		if len(bad) == 0 {
			bad = append(bad, "checks incomplete")
		}
		parts = append(parts, b.UnitID+": "+strings.Join(bad, ","))
	}
	return strings.Join(parts, "; ")
}

// gapsByPartition returns, per covering partition slug, the routes that are not
// yet CREDITED (v2): unread handlers and handlers read without a validated
// disposition alike, so the bounded follow-up can close both.
func gapsByPartition(spec ScanSpec, rec *RunRecord, routes []inventory.Route) map[string][]inventory.Route {
	spans := newHandlerSpans(spec.Repo)
	byPart := map[string][]unitEvidence{}
	for _, u := range rec.units {
		byPart[u.partSlug] = append(byPart[u.partSlug], u)
	}
	byID := map[string]inventory.Route{}
	assignedByPart := map[string]map[string]bool{}
	slugOf := map[string]string{}
	for _, r := range routes {
		id := RouteID(r)
		byID[id] = r
		for _, p := range rec.parts {
			if partitionCovers(p, r) {
				slugOf[id] = p.Slug()
				if assignedByPart[p.Slug()] == nil {
					assignedByPart[p.Slug()] = map[string]bool{}
				}
				assignedByPart[p.Slug()][id] = true
				break
			}
		}
	}
	dispCache := map[string][]HandlerDisposition{}
	out := map[string][]inventory.Route{}
	for _, r := range routes {
		id := RouteID(r)
		slug := slugOf[id]
		if slug == "" || !spans.scopeFor(r).Found {
			continue
		}
		rc := assessRoute(spec, rec, r, id, byPart[slug], assignedByPart[slug], byID, spans, dispCache)
		if !rc.credited {
			out[slug] = append(out[slug], r)
		}
	}
	return out
}
