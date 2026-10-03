package report

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"vhlocal/internal/consolidate"
)

// replayDir locates testdata/replay-171 from the package directory.
func replayDir(t *testing.T) string {
	t.Helper()
	wd, _ := os.Getwd()
	for d := wd; d != "/" && d != ""; d = filepath.Dir(d) {
		if _, err := os.Stat(filepath.Join(d, "go.mod")); err == nil {
			return filepath.Join(d, "testdata", "replay-171")
		}
	}
	t.Fatal("repo root not found")
	return ""
}

// replayInput builds a report Input from the sanitized live records (T002) the
// same way finalize would — from records only.
func replayInput(t *testing.T) Input {
	t.Helper()
	dir := replayDir(t)
	var doc consolidate.Doc
	b, err := os.ReadFile(filepath.Join(dir, "findings.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	repro := map[string]map[string]any{}
	if ab, err := os.ReadFile(filepath.Join(dir, "artifact_manifest.json")); err == nil {
		var entries []map[string]any
		_ = json.Unmarshal(ab, &entries)
		for _, e := range entries {
			if id, _ := e["candidate_id"].(string); id != "" {
				repro[id] = e
			}
		}
	}
	var ru struct {
		Counts struct {
			Total, ReviewedWithFindings, ReviewedNoIssue int
		} `json:"counts"`
		Gaps []struct{ RouteID, Reason string } `json:"gaps"`
	}
	if rb, err := os.ReadFile(filepath.Join(dir, "review_units.json")); err == nil {
		_ = json.Unmarshal(rb, &ru)
	}
	gaps := []ReviewGap{}
	for _, g := range ru.Gaps {
		gaps = append(gaps, ReviewGap{RouteID: g.RouteID, Reason: g.Reason})
	}
	return Input{
		Target: "logistics-dispatch", Model: "gpt-oss:120b", Host: "http://127.0.0.1:11434",
		StartedAt: "2026-09-28T22:17:35Z", FinishedAt: "2026-09-29T01:16:04Z", Duration: "10708.8s",
		Doc: doc, CodeExecuted: false, VerifyModelUsed: false,
		Repro: repro, ReviewGaps: gaps, ScanID: "replay-171", Repo: dir + "/target", GitCommit: "0123456789abcdef",
		Coverage:      &CoverageView{Completed: ru.Counts.ReviewedWithFindings + ru.Counts.ReviewedNoIssue, Exposed: ru.Counts.Total, Total: ru.Counts.Total, SemanticsVersion: 1},
		CoverageLabel: "read-overlap evidence (v1)",
	}
}
