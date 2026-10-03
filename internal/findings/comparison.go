package findings

import (
	"encoding/json"
	"os"
	"path/filepath"

	"vhlocal/internal/reports"
)

// Comparison is the baseline-diff view for a scan against an operator-selected
// comparable baseline (feature 010, US2). It is honest about the limits of the
// comparison: an absent finding is only "fixed" when the current scan's coverage
// is complete — otherwise it is unknown/incomparable, never auto-fixed
// (FR-023/FR-024). No rescans are triggered.
type Comparison struct {
	Comparable       bool     `json:"comparable"`
	Reason           string   `json:"reason"` // "" | no-baseline | baseline-not-found | current-not-found
	CurrentScan      string   `json:"current_scan"`
	BaselineScan     string   `json:"baseline_scan"`
	CoverageComplete bool     `json:"coverage_complete"`
	New              []string `json:"new"`                  // stable ids present now, absent in baseline
	Recurring        []string `json:"recurring"`            // stable ids in both
	Regressed        []string `json:"regressed"`            // engine-labeled regressed/reappeared now
	Fixed            []string `json:"fixed"`                // absent now, present in baseline, when coverage complete
	UnknownFixed     []string `json:"unknown_incomparable"` // absent now but coverage not complete → not fixed
	Uncomparable     int      `json:"uncomparable"`         // current findings lacking a stable identity
}

// Compare builds the comparison for currentScan against baselineScan. A baseline
// of "" or "none" yields Comparable=false with reason "no-baseline".
func Compare(reportsDir, currentScan, baselineScan string, extraDirs ...string) Comparison {
	c := Comparison{CurrentScan: currentScan, BaselineScan: baselineScan}
	if baselineScan == "" || baselineScan == "none" {
		c.Reason = "no-baseline"
		return c
	}
	idx, _ := reports.Index(reportsDir, extraDirs...)
	var curDir, baseDir string
	for _, r := range idx {
		if r.ID == currentScan {
			curDir = r.Path
		}
		if r.ID == baselineScan {
			baseDir = r.Path
		}
	}
	if curDir == "" {
		c.Reason = "current-not-found"
		return c
	}
	if baseDir == "" {
		c.Reason = "baseline-not-found"
		return c
	}

	curFindings, curCoverage := loadForCompare(curDir)
	baseFindings, _ := loadForCompare(baseDir)

	curSet := map[string]bool{}
	for _, f := range curFindings {
		sid := StableID(f)
		if sid == "" {
			c.Uncomparable++
			continue
		}
		curSet[sid] = true
		if lc := str(f["finding_lifecycle"]); lc == "regressed" || lc == "reappeared" {
			c.Regressed = append(c.Regressed, sid)
		}
	}
	baseSet := map[string]bool{}
	for _, f := range baseFindings {
		if sid := StableID(f); sid != "" {
			baseSet[sid] = true
		}
	}

	for sid := range curSet {
		if baseSet[sid] {
			c.Recurring = append(c.Recurring, sid)
		} else {
			c.New = append(c.New, sid)
		}
	}
	c.CoverageComplete = curCoverage == "complete"
	for sid := range baseSet {
		if curSet[sid] {
			continue
		}
		// Absent now. Only "fixed" when the current scan actually covered the
		// ground; otherwise the absence is uninformative (FR-024).
		if c.CoverageComplete {
			c.Fixed = append(c.Fixed, sid)
		} else {
			c.UnknownFixed = append(c.UnknownFixed, sid)
		}
	}

	c.Comparable = true
	nilToEmpty(&c.New, &c.Recurring, &c.Regressed, &c.Fixed, &c.UnknownFixed)
	return c
}

// loadForCompare returns a scan dir's findings and its coverage_status.
func loadForCompare(dir string) ([]map[string]any, string) {
	b, err := os.ReadFile(filepath.Join(dir, "findings.json"))
	if err != nil {
		return nil, ""
	}
	var raw struct {
		Findings  []map[string]any `json:"findings"`
		RunStatus struct {
			CoverageStatus string `json:"coverage_status"`
		} `json:"run_status"`
	}
	if json.Unmarshal(b, &raw) != nil {
		return nil, ""
	}
	return raw.Findings, raw.RunStatus.CoverageStatus
}

func nilToEmpty(ss ...*[]string) {
	for _, s := range ss {
		if *s == nil {
			*s = []string{}
		}
	}
}
