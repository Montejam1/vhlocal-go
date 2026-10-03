// Package manifest writes run_manifest.json — a compact, machine-readable record
// of one run's tool, target, models, transport, config (hashed), cost, timing,
// and outcome. Mirrors the Python manifest.py shape.
package manifest

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

const File = "run_manifest.json"

// Input carries everything the manifest records.
type Input struct {
	EngineVersion string
	RunID         string
	Repo          string
	GitCommit     string
	GitBranch     string

	HuntModel      string
	VerifyModel    string
	ReconModel     string
	ReproduceModel string
	Backend        string
	Host           string

	NumCtx            int
	MaxPartitions     int
	Phase2Mode        string
	QualityStrictness string
	PhasesRequested   []string
	SeedPrior         bool
	Ledger            bool
	Redact            bool
	HuntSamples       int
	ReasoningEffort   string
	MaxOutputTokens   int
	MaxBudgetUSD      float64

	SpentUSD       float64
	CapUSD         float64
	HaltedOnBudget bool

	StartedAt    float64
	FinishedAt   float64
	PhaseTimings map[string]float64

	ExecutionStatus         string
	CoverageStatus          string
	CoverageDegradedReasons []string
	HuntHalted              bool
	AgentsTotal             int
	AgentsIncomplete        int

	SeverityCounts map[string]int
	FindingsTotal  int

	RedactionEnabled bool
	RedactionMasked  int
}

func orModel(v, hunt string) string {
	if v == "" {
		return hunt
	}
	return v
}

// configHash is sha256 of a sorted subset of config keys (parity: sha256:<16hex>).
func (in Input) configHash() string {
	subset := map[string]any{
		"model": in.HuntModel, "verify_model": in.VerifyModel,
		"recon_model": in.ReconModel, "reproduce_model": in.ReproduceModel,
		"backend": in.Backend, "num_ctx": in.NumCtx, "max_partitions": in.MaxPartitions,
		"phase2_mode": in.Phase2Mode, "phases_requested": in.PhasesRequested,
		"seed_prior": in.SeedPrior, "ledger": in.Ledger, "redact": in.Redact,
		"reasoning_effort": in.ReasoningEffort, "max_output_tokens": in.MaxOutputTokens,
		"hunt_samples": in.HuntSamples, "max_budget_usd": in.MaxBudgetUSD,
		"quality_strictness": in.QualityStrictness,
	}
	// Marshal with sorted keys (encoding/json sorts map keys by default).
	b, _ := json.Marshal(subset)
	sum := sha256.Sum256(b)
	return "sha256:" + fmt.Sprintf("%x", sum)[:16]
}

// Build returns the run_manifest document.
func (in Input) Build() map[string]any {
	var dur any
	if in.FinishedAt > 0 && in.StartedAt > 0 {
		dur = round1(in.FinishedAt - in.StartedAt)
	} else {
		dur = nil
	}
	strictness := in.QualityStrictness
	if strictness == "" {
		strictness = "balanced"
	}
	samples := in.HuntSamples
	if samples == 0 {
		samples = 1
	}
	m := map[string]any{
		"tool":   map[string]any{"name": "vhlocal", "version": in.EngineVersion},
		"run_id": in.RunID,
		"target": map[string]any{"repo": in.Repo, "git_commit": in.GitCommit, "git_branch": in.GitBranch},
		"models": map[string]any{
			"hunt": in.HuntModel, "verify": orModel(in.VerifyModel, in.HuntModel),
			"recon": orModel(in.ReconModel, in.HuntModel), "reproduce": orModel(in.ReproduceModel, in.HuntModel),
		},
		"transport": map[string]any{"backend": in.Backend, "host": in.Host},
		"config": map[string]any{
			"hash": in.configHash(), "num_ctx": in.NumCtx, "max_partitions": in.MaxPartitions,
			"phase2_mode": in.Phase2Mode, "quality_strictness": strictness,
			"phases_requested": nonNilStr(in.PhasesRequested), "seed_prior": in.SeedPrior,
			"ledger": in.Ledger, "redact": in.Redact, "hunt_samples": samples,
		},
		"cost": map[string]any{"spent_usd": in.SpentUSD, "cap_usd": in.CapUSD, "halted_on_budget": in.HaltedOnBudget},
		"timing": map[string]any{
			"started_at": in.StartedAt, "finished_at": in.FinishedAt,
			"duration_seconds": dur, "phase_timings": nonNilTimings(in.PhaseTimings),
		},
		"outcome": map[string]any{
			"execution_status": in.ExecutionStatus, "coverage_status": in.CoverageStatus,
			"coverage_degraded_reasons": nonNilStr(in.CoverageDegradedReasons),
			"hunt_halted":               in.HuntHalted, "agents_total": in.AgentsTotal,
			"agents_incomplete": in.AgentsIncomplete,
		},
		"findings": map[string]any{"counts": nonNilCounts(in.SeverityCounts), "total": in.FindingsTotal},
	}
	if in.RedactionEnabled {
		m["redaction"] = map[string]any{"enabled": true, "masked": in.RedactionMasked}
	}
	return m
}

// Write emits run_manifest.json into resultsDir.
func (in Input) Write(resultsDir string) (string, error) {
	b, err := json.MarshalIndent(in.Build(), "", "  ")
	if err != nil {
		return "", err
	}
	out := filepath.Join(resultsDir, File)
	return out, os.WriteFile(out, b, 0o644)
}

func round1(f float64) float64 {
	return float64(int(f*10+0.5)) / 10
}
func nonNilStr(s []string) []string {
	if s == nil {
		return []string{}
	}
	sort.Strings(append([]string{}, s...)) // stable, no mutation of caller
	return s
}
func nonNilCounts(m map[string]int) map[string]int {
	if m == nil {
		return map[string]int{}
	}
	return m
}
func nonNilTimings(m map[string]float64) map[string]float64 {
	if m == nil {
		return map[string]float64{}
	}
	return m
}
