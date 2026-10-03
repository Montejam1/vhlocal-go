package engine

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"vhlocal/internal/inventory"
)

// Regenerate rebuilds the consolidated artifacts (findings.json, findings.sarif,
// run_manifest.json, coverage_ledger.json, SCAN_REPORT.md/.html, verification
// manifests) for an existing results directory — deterministically, from the
// engine-written scan_meta.json and the raw phase outputs. No model is called
// (constitution Principle I / FR-014). Used by `vhlocal report`.
func Regenerate(resultsDir string) error {
	metaB, err := os.ReadFile(filepath.Join(resultsDir, ScanMetaFile))
	if err != nil {
		return fmt.Errorf("not a results directory (no %s): %w", ScanMetaFile, err)
	}
	var rec RunRecord
	if err := json.Unmarshal(metaB, &rec); err != nil {
		return fmt.Errorf("invalid scan_meta.json: %w", err)
	}
	if rec.Schema == "partial" {
		return fmt.Errorf("cannot regenerate an unfinished scan (%s)", rec.Status)
	}
	rec.ResultsDir = resultsDir
	spec := ScanSpec{
		// FR-C6: restore the real backend from the record; never fabricate "ollama".
		// Empty stays empty (honest) for pre-feature-005 runs that did not persist it.
		Repo: rec.Repo, ResultsDir: resultsDir, Model: rec.Model, Host: rec.Host,
		Backend: rec.Backend, NumCtx: rec.NumCtx, Phases: rec.PhasesRequested,
		MaxPartitions: rec.MaxPartitions, QualityStrictness: rec.QualityStrictness, Phase2Mode: rec.Phase2Mode,
		ThreatModel: len(rec.ThreatModelPartitions) > 0 || fileExists(filepath.Join(resultsDir, "threat_model.md")),
		Ledger:      rec.Ledger, Redact: rec.Redact, Remediate: rec.Remediate,
		EngineVersion: rec.EngineVersion,
	}
	if rec.VerifyModel != nil {
		spec.VerifyModel = *rec.VerifyModel
	}
	var routes []inventory.Route
	if rec.Repo != "" {
		routes, rec.excludedRoutes, _ = inventory.EnumerateRoutesDetailed(rec.Repo)
	}
	if err := finalize(spec, &rec, routes, nil); err != nil {
		return err
	}
	_, err = rec.Write(resultsDir)
	return err
}

func fileExists(p string) bool { _, err := os.Stat(p); return err == nil }
