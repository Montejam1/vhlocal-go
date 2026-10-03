package engine

import (
	"encoding/json"
	"os"
	"path/filepath"

	"vhlocal/internal/consolidate"
	"vhlocal/internal/report"
	"vhlocal/internal/review"
)

// Feature 015 (FR-020, C-B11): remediation groups are built at finalize (live and
// regeneration alike) over the final findings, annotated with the members' review
// decisions — read-only against the review store — and persisted as one additive
// record. No finding, decision, evidence or review record is touched.

// buildRemediationGroups writes remediation_groups.json and returns the report view.
func buildRemediationGroups(spec ScanSpec, findings []consolidate.Finding) ([]report.Group, error) {
	g := consolidate.BuildGroups(findings, spec.Repo)
	annotateGroupDecisions(&g, spec.ResultsDir)
	if err := consolidate.WriteGroups(spec.ResultsDir, g); err != nil {
		return nil, err
	}
	return report.GroupsFromConsolidate(g), nil
}

// annotateGroupDecisions derives each group's decision_status from the members'
// review records (all-decided | mixed | undecided) and sets members_changed_since
// when a member's stable id is absent from the scan of the newest member decision.
// Decisions carry whole-second timestamps, so every decision tied for newest is
// considered; an unlocatable scan falls back to "did this member get a decision at
// that scan" — conservative, never silent.
func annotateGroupDecisions(g *consolidate.Groups, resultsDir string) {
	for i := range g.Groups {
		gr := &g.Groups[i]
		gr.DecisionStatus, gr.MembersChangedSince = "undecided", false
		recs := map[string]review.Record{}
		decided := 0
		var newest []review.Decision
		newestAt := -1.0
		for _, m := range gr.Members {
			rec, ok := review.Get(m.StableID)
			recs[m.StableID] = rec
			if !ok || len(rec.History) == 0 {
				continue
			}
			decided++
			head := rec.Head()
			switch {
			case head.DecidedAt > newestAt:
				newestAt, newest = head.DecidedAt, []review.Decision{head}
			case head.DecidedAt == newestAt:
				newest = append(newest, head)
			}
		}
		switch {
		case decided == 0:
			continue
		case decided == len(gr.Members):
			gr.DecisionStatus = "all-decided"
		default:
			gr.DecisionStatus = "mixed"
		}
		for _, d := range newest {
			if d.ScanID == "" {
				continue
			}
			present := scanStableIDs(resultsDir, d.ScanID)
			for _, m := range gr.Members {
				if present != nil {
					if !present[m.StableID] {
						gr.MembersChangedSince = true
					}
					continue
				}
				has := false
				for _, h := range recs[m.StableID].History {
					if h.ScanID == d.ScanID {
						has = true
						break
					}
				}
				if !has {
					gr.MembersChangedSince = true
				}
			}
		}
	}
}

// scanStableIDs returns the stable identities recorded in a scan's findings.json —
// this results dir when the id matches, else a sibling results dir under the same
// parent. nil when the scan cannot be located or read.
func scanStableIDs(resultsDir, scanID string) map[string]bool {
	dir := resultsDir
	if scanID != filepath.Base(resultsDir) {
		dir = filepath.Join(filepath.Dir(resultsDir), scanID)
	}
	b, err := os.ReadFile(filepath.Join(dir, "findings.json"))
	if err != nil {
		return nil
	}
	var doc struct {
		Findings []struct {
			StableIdentity string `json:"stable_identity"`
		} `json:"findings"`
	}
	if json.Unmarshal(b, &doc) != nil {
		return nil
	}
	out := map[string]bool{}
	for _, f := range doc.Findings {
		if f.StableIdentity != "" {
			out[f.StableIdentity] = true
		}
	}
	return out
}
