package consolidate

import (
	"os"
	"path/filepath"
	"strings"
)

// ReviewSupport validates a finding's explicit review record against the current
// checkout, returning whether it substantiates a `reviewed` tier and, if not, why
// it remains a hypothesis (feature 006, FR-011; parity with the reference
// evidence.review_support).
//
// Review records are supplied explicitly by a reviewer/integration, never inferred
// from a model CONFIRMED label. Matching quotes validate provenance against the
// live source (not the correctness of the reviewer's security reasoning): every
// cited quote must byte-match the current checkout, and the evidence must cover the
// finding's primary location.
//
// Documented approximation (plan Complexity #2): the reference additionally
// requires the record's revision to equal the run's git_commit. The Go
// ApplyQuality battery does not thread the target revision, so currency is enforced
// by the stronger live-source byte-match instead; the record must still name a
// revision (non-empty) to identify a target.
func ReviewSupport(f *Finding, repo string) (bool, string) {
	const na = "Further investigation required: "
	r := f.ReviewRecord
	if r == nil {
		return false, na + "no substantiated review is recorded."
	}
	if r.Verdict != "supported" {
		return false, na + "the review decision is not supported."
	}
	for _, s := range []string{r.Reviewer, r.Rationale, r.EntryPoint, r.AttackerControl,
		r.Preconditions, r.DefensesReviewed, r.SecurityImpact} {
		if strings.TrimSpace(s) == "" {
			return false, na + "the review decision or supporting reasoning is incomplete."
		}
	}
	if strings.TrimSpace(r.Revision) == "" {
		return false, na + "the review does not identify this target revision."
	}
	if repo == "" {
		return false, na + "source evidence cannot be checked without the target checkout."
	}
	file, line := locFileLine(f.Location)
	if file == "" || line < 1 {
		return false, na + "the candidate has no exact source location."
	}
	if len(r.Evidence) == 0 {
		return false, na + "the review has no source evidence."
	}
	covered := false
	for _, e := range r.Evidence {
		if !reviewQuoteMatches(e, repo) {
			return false, na + "a review quote does not match the live source at " + e.Path + "."
		}
		if pathMatches(e.Path, file) && e.StartLine <= line && line <= e.EndLine {
			covered = true
		}
	}
	if !covered {
		return false, na + "the review evidence does not cover the cited primary location."
	}
	return true, r.Rationale
}

func reviewQuoteMatches(e ReviewEvidence, repo string) bool {
	if repo == "" || e.Path == "" || filepath.IsAbs(e.Path) || strings.Contains(e.Path, "..") {
		return false
	}
	b, err := os.ReadFile(filepath.Join(repo, e.Path))
	if err != nil {
		return false
	}
	lines := strings.Split(string(b), "\n")
	if e.StartLine < 1 || e.EndLine > len(lines) || e.StartLine > e.EndLine {
		return false
	}
	want := strings.Join(lines[e.StartLine-1:e.EndLine], "\n")
	return strings.TrimRight(want, "\n") == strings.TrimRight(e.Quote, "\n")
}

func pathMatches(evPath, loc string) bool {
	return evPath == loc || strings.HasSuffix(evPath, "/"+loc) || strings.HasSuffix(loc, "/"+evPath)
}

func locFileLine(loc string) (string, int) {
	m := reFileLine.FindStringSubmatch(loc)
	if m == nil {
		return "", 0
	}
	n := 0
	for _, c := range m[2] {
		n = n*10 + int(c-'0')
	}
	return m[1], n
}
