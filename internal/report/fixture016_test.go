package report

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"vhlocal/internal/consolidate"
)

// Feature 016 (T003): the loader for the frozen acceptance corpus.
//
// It reads only testdata/report016 and builds a report Input from records, exactly as
// finalize and regeneration do. It never reads the operator's live stores, never
// consults $HOME, and every caller writes through t.TempDir() (FR-028, C-C12, C-C13).

// fixture016Dir resolves the frozen corpus from the module root, so the path never
// depends on the working directory or on a home directory.
func fixture016Dir(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 8; i++ {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			out := filepath.Join(dir, "testdata", "report016")
			if _, err := os.Stat(filepath.Join(out, "report_model.json")); err != nil {
				t.Fatalf("acceptance fixture missing at %s: %v (regenerate with go run ./testdata/report016/gen/main.go <scan>)", out, err)
			}
			return out
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Fatal("module root not found")
	return ""
}

// fixture016Baseline is the measured before-state recorded in baseline.json.
type fixture016Baseline struct {
	Document struct {
		Lines                        int `json:"lines"`
		Bytes                        int `json:"bytes"`
		ProseWordsBeforeFindingIndex int `json:"prose_words_before_findings_index"`
		DetailSections               int `json:"detail_sections"`
		FindingAnchors               int `json:"finding_anchors"`
		FixNotProvidedOccurrences    int `json:"fix_not_provided_occurrences"`
	} `json:"document"`
	OpeningWarning string `json:"opening_warning"`
	Counts         struct {
		CandidatesExamined   int `json:"candidates_examined"`
		SupportedDetections  int `json:"supported_detections"`
		EstablishedGroups    int `json:"established_groups"`
		GroupMembers         int `json:"group_members"`
		UniqueGroupMembers   int `json:"unique_group_members"`
		Rejected             int `json:"rejected"`
		UnresolvedExplicit   int `json:"unresolved_explicit"`
		UnresolvedFailed     int `json:"unresolved_failed"`
		NeedsReviewTotal     int `json:"needs_review_total"`
		FindingsWithEmptyFix int `json:"findings_with_empty_fix"`
	} `json:"counts"`
	Coverage struct {
		CompletedReview  int `json:"completed_review"`
		SourceExposed    int `json:"source_exposed"`
		TotalEntryPoints int `json:"total_entry_points"`
	} `json:"coverage"`
	GroupSeverity map[string]int `json:"group_severity_high_plus_folded_into_high"`
	ExpectedAfter struct {
		DetailSections                  int `json:"detail_sections"`
		FixNotProvidedOccurrences       int `json:"fix_not_provided_occurrences"`
		ProseWordsBeforeFindingIndexMax int `json:"prose_words_before_findings_index_max"`
		PriorityRowsMax                 int `json:"priority_rows_max"`
	} `json:"expected_after"`
}

func loadFixture016Baseline(t *testing.T) fixture016Baseline {
	t.Helper()
	var b fixture016Baseline
	raw, err := os.ReadFile(filepath.Join(fixture016Dir(t), "baseline.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &b); err != nil {
		t.Fatalf("baseline.json: %v", err)
	}
	return b
}

// fixture016Groups loads the recorded remediation groups.
func fixture016Groups(t *testing.T) consolidate.Groups {
	t.Helper()
	var g consolidate.Groups
	raw, err := os.ReadFile(filepath.Join(fixture016Dir(t), consolidate.GroupsFile))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &g); err != nil {
		t.Fatalf("%s: %v", consolidate.GroupsFile, err)
	}
	return g
}

// fixture016Doc loads findings.json as the consolidated document.
func fixture016Doc(t *testing.T) consolidate.Doc {
	t.Helper()
	var doc consolidate.Doc
	raw, err := os.ReadFile(filepath.Join(fixture016Dir(t), "findings.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("findings.json: %v", err)
	}
	return doc
}

// fixture016Input builds the report Input from the frozen records, the same way
// finalize does. Writes by callers go to t.TempDir(); this function writes nothing.
func fixture016Input(t *testing.T) Input {
	t.Helper()
	dir := fixture016Dir(t)
	doc := fixture016Doc(t)

	var meta struct {
		Repo        string  `json:"repo"`
		Model       string  `json:"model"`
		Host        string  `json:"host"`
		StartedAt   float64 `json:"started_at"`
		FinishedAt  float64 `json:"finished_at"`
		GitCommit   string  `json:"git_commit"`
		GitBranch   string  `json:"git_branch"`
		VerifyModel *string `json:"verify_model"`
		BashEnabled bool    `json:"bash_enabled"`
	}
	if raw, err := os.ReadFile(filepath.Join(dir, "scan_meta.json")); err == nil {
		_ = json.Unmarshal(raw, &meta)
	}

	// Coverage comes from the review-unit record, so the reader-facing figure is the
	// COMPLETED review count and the exposure axis stays separate (FR-004, C-P8).
	var ru struct {
		SemanticsVersion int                                `json:"semantics_version"`
		Counts           map[string]int                     `json:"counts"`
		Axes             map[string]int                     `json:"axes"`
		Gaps             []struct{ RouteID, Reason string } `json:"gaps"`
	}
	if raw, err := os.ReadFile(filepath.Join(dir, "review_units.json")); err == nil {
		_ = json.Unmarshal(raw, &ru)
	}
	cov := &CoverageView{
		Completed:        ru.Counts["reviewed_with_findings"] + ru.Counts["reviewed_no_issue"],
		Exposed:          ru.Counts["source_exposed"],
		Total:            ru.Counts["total"],
		SemanticsVersion: max(ru.SemanticsVersion, 1),
	}
	if ru.Axes != nil {
		cov.Completed, cov.Exposed = ru.Axes["completed_review"], ru.Axes["source_exposed"]
		cov.Axes = &CoverageAxes{
			Discovered: ru.Axes["discovered"], SupportedInventory: ru.Axes["supported_inventory"],
			Assigned: ru.Axes["assigned"], Attempted: ru.Axes["attempted"],
			SourceExposed: ru.Axes["source_exposed"], CompletedReview: ru.Axes["completed_review"],
			Verified: ru.Axes["verified"],
		}
	}
	gaps := []ReviewGap{}
	for _, g := range ru.Gaps {
		gaps = append(gaps, ReviewGap{RouteID: g.RouteID, Reason: g.Reason})
	}

	var failures *FailureAggregates
	if raw, err := os.ReadFile(filepath.Join(dir, "verification_metrics.json")); err == nil {
		var vm struct {
			Agg *FailureAggregates `json:"session_aggregates"`
		}
		if json.Unmarshal(raw, &vm) == nil && vm.Agg != nil && vm.Agg.Sessions > 0 {
			failures = vm.Agg
		}
	}

	label := "read-overlap evidence (v1)"
	if cov.SemanticsVersion >= 2 {
		label = "validated handler dispositions (v2)"
	}
	return Input{
		Target: "vc-claude-code-seeded-v2-logistics-dispatch-fastapi", Model: meta.Model, Host: meta.Host,
		StartedAt: isoFromUnix(meta.StartedAt), FinishedAt: isoFromUnix(meta.FinishedAt),
		Duration: "unrecorded", Doc: doc,
		CodeExecuted: meta.BashEnabled, VerifyModelUsed: meta.VerifyModel != nil && *meta.VerifyModel != "",
		ReviewGaps: gaps, ScanID: "report016-fixture", Repo: filepath.Join(dir, "target"),
		GitCommit: meta.GitCommit, GitBranch: meta.GitBranch,
		Coverage: cov, CoverageLabel: label,
		Groups:   GroupsFromConsolidate(fixture016Groups(t)),
		Failures: failures,
	}
}

// isoFromUnix renders a recorded epoch seconds value as UTC RFC 3339, or "unrecorded"
// when the record has none. It never substitutes "now" for a missing timestamp.
func isoFromUnix(u float64) string {
	if u <= 0 {
		return "unrecorded"
	}
	return time.Unix(int64(u), 0).UTC().Format(time.RFC3339)
}

// readFixtureFile reads one fixture record as text.
func readFixtureFile(t *testing.T, dir, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return string(b)
}

// fileExistsIn reports whether a name is present in the fixture directory.
func fileExistsIn(dir, name string) bool {
	_, err := os.Stat(filepath.Join(dir, name))
	return err == nil
}

// itoa016 renders an int without pulling strconv into the fixture helpers' imports.
func itoa016(n int) string { return fmt.Sprintf("%d", n) }

// uniqueStrings returns the distinct values of s, preserving no order.
func uniqueStrings(s []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(s))
	for _, v := range s {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}
