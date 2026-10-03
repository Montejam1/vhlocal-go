// Package testsupport builds seeded on-disk state (reports, registry, ledgers,
// material artifacts) for offline feature-007 tests. It writes raw files only —
// no engine, no model, no network — so tests exercise the read/aggregation and
// serving paths against realistic data. It imports no first-party packages that
// would create a test import cycle.
package testsupport

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// ReportSeed describes one results directory to write.
type ReportSeed struct {
	Name    string // application/base name (dir prefix)
	Model   string // e.g. "gptoss120b"
	Stamp   string // "YYYY-MM-DD-HHMMSS"
	Repo    string // absolute target path (drives the slug)
	Created time.Time

	Findings        []map[string]any // each: severity, classification, optional duplicate_of
	CoverageStatus  string           // "complete" | "degraded" | "partial"
	ExecutionStatus string           // "complete" | "partial" | ...
	ValidationMode  string           // default "static_reasoning"
	PhasesRequested []string
	PhasesCompleted []string
	PhasesSkipped   []string // feature 014: e.g. "1t" when threat_model=false
	GitCommit       string   // feature 014: scanned revision

	ThreatModel    string // "" none | "ok" writes threat_model.md | "empty"
	Sbom           string // "" none | "ok" writes valid sbom.cdx.json | "malformed" | "empty"
	SbomTotal      int    // components (findings.json application_intelligence.sbom.total)
	Readme         bool   // writes README.md (has_report)
	ArtifactErrors []string

	// Per-run usage + timing (feature 008): written into scan_meta.json so the
	// Dashboard metrics aggregate has real data. Zero values are omitted.
	PromptTokens     int
	CompletionTokens int
	StartedAt        float64
	FinishedAt       float64
}

// SeedReport writes a results dir under reportsDir and returns its path.
func SeedReport(t *testing.T, reportsDir string, rs ReportSeed) string {
	t.Helper()
	if rs.Stamp == "" {
		rs.Stamp = "2026-09-17-000000"
	}
	if rs.Model == "" {
		rs.Model = "gptoss120b"
	}
	dir := filepath.Join(reportsDir, rs.Name+"_VULNHUNT_RESULTS_"+rs.Model+"_"+rs.Stamp)
	mustMkdir(t, dir)

	meta := map[string]any{
		"repo": rs.Repo, "model": rs.Model,
		"phases_requested": toAny(rs.PhasesRequested), "phases_completed": toAny(rs.PhasesCompleted),
	}
	if len(rs.PhasesSkipped) > 0 {
		meta["phases_skipped"] = toAny(rs.PhasesSkipped)
	}
	if rs.GitCommit != "" {
		meta["git_commit"] = rs.GitCommit
	}
	if rs.PromptTokens > 0 || rs.CompletionTokens > 0 {
		meta["usage"] = map[string]any{
			"prompt_tokens": rs.PromptTokens, "completion_tokens": rs.CompletionTokens,
		}
	}
	if rs.StartedAt > 0 {
		meta["started_at"] = rs.StartedAt
	}
	if rs.FinishedAt > 0 {
		meta["finished_at"] = rs.FinishedAt
	}
	writeJSON(t, filepath.Join(dir, "scan_meta.json"), meta)

	rs2 := rs.CoverageStatus
	if rs2 == "" {
		rs2 = "complete"
	}
	vm := rs.ValidationMode
	if vm == "" {
		vm = "static_reasoning"
	}
	findings := rs.Findings
	if findings == nil {
		findings = []map[string]any{}
	}
	doc := map[string]any{
		"findings": toAnySlice(findings),
		"run_status": map[string]any{
			"execution_status": orDefault(rs.ExecutionStatus, "complete"),
			"coverage_status":  rs2, "validation_mode": vm,
			"coverage_degraded_reasons": []any{},
		},
	}
	if rs.SbomTotal > 0 {
		doc["application_intelligence"] = map[string]any{"sbom": map[string]any{"total": rs.SbomTotal}}
	}
	if len(rs.ArtifactErrors) > 0 {
		doc["artifact_errors"] = toAny(rs.ArtifactErrors)
	}
	writeJSON(t, filepath.Join(dir, "findings.json"), doc)

	switch rs.ThreatModel {
	case "ok":
		writeFile(t, filepath.Join(dir, "threat_model.md"), "# Threat model\n\nPASTA analysis.\n")
	case "empty":
		writeFile(t, filepath.Join(dir, "threat_model.md"), "")
	}
	switch rs.Sbom {
	case "ok":
		writeFile(t, filepath.Join(dir, "sbom.cdx.json"), `{"bomFormat":"CycloneDX","specVersion":"1.5","components":[]}`)
	case "malformed":
		writeFile(t, filepath.Join(dir, "sbom.cdx.json"), `{not valid json`)
	case "empty":
		writeFile(t, filepath.Join(dir, "sbom.cdx.json"), "")
	}
	if rs.Readme {
		writeFile(t, filepath.Join(dir, "README.md"), "# Report\n")
	}
	if !rs.Created.IsZero() {
		_ = os.Chtimes(dir, rs.Created, rs.Created)
	}
	return dir
}

// SeedStrayDir writes a subdirectory under reportsDir that holds NO recognized
// deliverable — the phantom-application source (feature 008, US2). A correct report
// index must NOT treat it as a report.
func SeedStrayDir(t *testing.T, reportsDir, name string) string {
	t.Helper()
	dir := filepath.Join(reportsDir, name)
	mustMkdir(t, dir)
	writeFile(t, filepath.Join(dir, "notes.txt"), "not a scan\n")
	return dir
}

// SeedLedger writes a minimal ledger `<ledgerDir>/<slug>.json` with `open` open
// findings so aggregation reports a non-null open/total for that slug.
func SeedLedger(t *testing.T, ledgerDir, slug, target string, open int) {
	t.Helper()
	mustMkdir(t, ledgerDir)
	var findings []map[string]any
	for i := 0; i < open; i++ {
		findings = append(findings, map[string]any{"status": "open", "severity": "High", "confidence": "reliable"})
	}
	lg := map[string]any{"target": target, "updated": float64(time.Now().Unix()),
		"runs_recorded": []any{"run1"}, "findings": toAnySlice(findings)}
	writeJSON(t, filepath.Join(ledgerDir, slug+".json"), lg)
}

// SeedRegistry writes applications.json (which lives beside the ledger dir).
func SeedRegistry(t *testing.T, ledgerDir string, entries map[string]map[string]any) {
	t.Helper()
	parent := filepath.Dir(ledgerDir)
	mustMkdir(t, parent)
	writeJSON(t, filepath.Join(parent, "applications.json"), entries)
}

// helpers -------------------------------------------------------------------

func mustMkdir(t *testing.T, d string) {
	t.Helper()
	if err := os.MkdirAll(d, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", d, err)
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func writeJSON(t *testing.T, path string, v any) {
	t.Helper()
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatalf("marshal %s: %v", path, err)
	}
	writeFile(t, path, string(b))
}

func toAny(ss []string) []any {
	out := make([]any, len(ss))
	for i, s := range ss {
		out[i] = s
	}
	return out
}

func toAnySlice(ms []map[string]any) []any {
	out := make([]any, len(ms))
	for i, m := range ms {
		out[i] = m
	}
	return out
}

func orDefault(v, d string) string {
	if v == "" {
		return d
	}
	return v
}
