package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"vhlocal/internal/agent"
	"vhlocal/internal/citation"
	"vhlocal/internal/client"
	"vhlocal/internal/consolidate"
	"vhlocal/internal/tools"
)

// Feature 015 (FR-025, C-C3): citation validation at hunt ingestion. After a unit
// writes a valid deliverable, every extracted finding's citation is parsed and
// resolved. A unit with invalid citations gets exactly ONE bounded correction turn
// — a fresh bounded run of the same task carrying per-finding structured feedback
// (field, code, received, expected, aids) — counted as an attempt and recorded as
// `citation_repair`. Findings still invalid afterwards stay in the manifest as
// `invalid_citation` (visible, never verified, never dropped from totals). No
// helper shifts, clamps or guesses a citation.

// CitationStats is hunt_execution.detail[].citation.
type CitationStats struct {
	Findings        int `json:"findings"`
	Invalid         int `json:"invalid"`
	Repaired        int `json:"repaired"`
	Remaining       int `json:"remaining"`
	CorrectionTurns int `json:"correction_turns"`
}

// citationIssue is one finding's validation failure, rendered into feedback.
type citationIssue struct {
	Finding  string          `json:"finding"`
	Field    string          `json:"field"`
	Code     string          `json:"code"`
	Received string          `json:"received"`
	Expected string          `json:"expected"`
	Aids     *citation.Aids  `json:"aids,omitempty"`
	Error    *citation.Error `json:"-"`
}

// checkDeliverableCitations validates every finding's citation in a deliverable.
func checkDeliverableCitations(path, repo, revision string, binder *citation.Binder) (findings int, issues []citationIssue) {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, nil
	}
	fs := consolidate.ExtractFindings(string(b), path)
	for _, f := range fs {
		findings++
		c, perr := citation.Parse(f.Location)
		var cerr *citation.Error
		if perr != nil {
			cerr = perr
		} else if _, rerr := citation.Resolve(repo, revision, &c); rerr != nil {
			cerr = rerr
		}
		if cerr == nil {
			continue
		}
		issue := citationIssue{Finding: f.SourceID, Field: cerr.Field, Code: cerr.Code, Received: cerr.Received, Expected: cerr.Expected, Error: cerr}
		if issue.Finding == "" {
			issue.Finding = f.ID
		}
		if cerr.Aids != (citation.Aids{}) {
			a := cerr.Aids
			issue.Aids = &a
		} else if perr == nil && binder != nil && cerr.Code == citation.ERangeOutOfBounds {
			a := citation.AidsFor(binder.Bind(c))
			issue.Aids = &a
		}
		issues = append(issues, issue)
	}
	return findings, issues
}

// citationFeedback renders the correction-turn message. Each issue names the
// finding, the field, the error code, what was received and what is expected, plus
// any aids (file length, handler span, route) — never a corrected citation.
func citationFeedback(outFile string, issues []citationIssue) string {
	var b strings.Builder
	b.WriteString("## Citation corrections required (one correction turn)\n\n")
	b.WriteString("The deliverable you wrote contains findings whose **Location** could not be validated against the repository. ")
	b.WriteString("Rewrite the COMPLETE deliverable to the same path with every Location in the canonical form `path:start[-end]` (repository-relative path, 1-based lines, the sink statement lines). ")
	b.WriteString("Do not invent lines: re-read the file if needed. Keep every finding; do not drop one to pass.\n\n")
	for _, is := range issues {
		fmt.Fprintf(&b, "- finding %s · field `%s` · code `%s` · received `%s` · expected: %s", is.Finding, is.Field, is.Code, strings.ReplaceAll(is.Received, "`", "'"), is.Expected)
		if is.Aids != nil {
			ab, _ := json.Marshal(is.Aids)
			fmt.Fprintf(&b, " · aids: %s", ab)
		}
		b.WriteString("\n")
	}
	fmt.Fprintf(&b, "\nWrite the corrected deliverable to: %s\n", outFile)
	return b.String()
}

// citationCorrection runs the bounded correction turn for one unit when its valid
// deliverable carries invalid citations. It returns the stats, the correction run's
// result (nil when no correction ran) and whether the deliverable is still valid.
func citationCorrection(ctx context.Context, p client.Provider, sb *tools.Sandbox, cfg agent.Config, system, task, sfile, repo, revision string,
	binder *citation.Binder, allowed func() bool) (CitationStats, *agent.Result, bool) {
	n, issues := checkDeliverableCitations(sfile, repo, revision, binder)
	st := CitationStats{Findings: n, Invalid: len(issues), Remaining: len(issues)}
	if len(issues) == 0 || !allowed() || ctx.Err() != nil {
		return st, nil, true
	}
	st.CorrectionTurns = 1
	feedback := citationFeedback(sfile, issues)
	res, err := agent.Run(ctx, p, sb, cfg, system, task+"\n\n"+feedback)
	if err != nil {
		return st, &res, false
	}
	if !deliverableValid(sfile) {
		return st, &res, false
	}
	n2, issues2 := checkDeliverableCitations(sfile, repo, revision, binder)
	st.Findings = n2
	st.Remaining = len(issues2)
	if st.Repaired = st.Invalid - len(issues2); st.Repaired < 0 {
		st.Repaired = 0
	}
	return st, &res, true
}
