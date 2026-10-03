// Package engine is the scan pipeline as a library call: execute_scan runs the
// phases and writes the artifact set. The CLI and the HTTP server both call it,
// so behavior cannot diverge (FR-012).
package engine

import (
	"encoding/json"
	"os"
	"path/filepath"

	"vhlocal/internal/inventory"
	"vhlocal/internal/phases"
)

const ScanMetaFile = "scan_meta.json"

// AgentRecord is one agent's engine-observed facts (scan_meta agents[]).
// prompt_tokens/completion_tokens make token usage attributable per phase/agent
// (FR-011 clause b); repair counters aid diagnosability (FR-014).
type AgentRecord struct {
	Label            string `json:"label"`
	Phase            string `json:"phase"`
	Model            string `json:"model"`
	Turns            int    `json:"turns"`
	StoppedReason    string `json:"stopped_reason"`
	PromptTokens     int    `json:"prompt_tokens"`
	CompletionTokens int    `json:"completion_tokens"`
	RepairAttempts   int    `json:"repair_attempts,omitempty"`
	RepairSuccesses  int    `json:"repair_successes,omitempty"`

	// Per-unit attribution (feature 005, FR-029/030): which partition + vulnerability
	// class a hunt unit covered, so partial hunt evidence is attributable. Additive.
	Partition string `json:"partition,omitempty"`
	VulnClass string `json:"vuln_class,omitempty"`
	// CandidateID (feature 015, C-C12): the candidate a 2b session verified.
	CandidateID string `json:"candidate_id,omitempty"`

	// Produced records whether the agent actually wrote its deliverable (feature 014,
	// FR-017). A normal stop (`stopped_reason: complete`) with produced=false is a
	// FAILED assignment, never a pass — agent stop and assignment success are separate.
	Produced bool `json:"produced"`
}

// RunRecord is scan_meta.json — engine-observed fact, authoritative over any
// model prose about its own run (constitution Principle I). Field order/defaults
// mirror the Python RunRecord.
type RunRecord struct {
	Schema      string  `json:"schema,omitempty"`
	Status      string  `json:"status,omitempty"`
	AppSlug     string  `json:"app_slug,omitempty"`
	AppName     string  `json:"app_name,omitempty"`
	StartedAt   float64 `json:"started_at"`
	FinishedAt  float64 `json:"finished_at"`
	Repo        string  `json:"repo"`
	ResultsDir  string  `json:"results_dir"`
	Model       string  `json:"model"`
	VerifyModel *string `json:"verify_model"`
	// Feature 015 (C-C7 resume): the verify role's backend/host and the diagnostic
	// capture mode, persisted so a changed verifier invalidates saved 2b work.
	VerifyBackend     string `json:"verify_backend,omitempty"`
	VerifyHost        string `json:"verify_host,omitempty"`
	DiagnosticCapture string `json:"diagnostic_capture,omitempty"`
	Host              string `json:"host"`
	NumCtx            int    `json:"num_ctx"`
	MaxPartitions     int    `json:"max_partitions"`

	PhasesRequested []string           `json:"phases_requested"`
	PhasesCompleted []string           `json:"phases_completed"`
	PhasesSkipped   []string           `json:"phases_skipped"`
	PhaseTimings    map[string]float64 `json:"phase_timings"`

	Partitions                 []string `json:"partitions"`
	PartitionSource            string   `json:"partition_source"`
	PartitionFallback          bool     `json:"partition_fallback"`
	PartitionParseError        string   `json:"partition_parse_error"`
	PartitionCollapsed         bool     `json:"partition_collapsed"`
	CoveragePartitionsAdded    []string `json:"coverage_partitions_added"`
	CoverageFilesAdded         []string `json:"coverage_files_added"`
	CoverageUncoveredRemaining []string `json:"coverage_uncovered_remaining"`
	ThreatModelPartitions      []string `json:"threat_model_partitions"`
	// CoverageEnforced records whether coverage-driven augmentation was applied
	// (feature 013, FR-012). When false, augmentation was disabled by the operator;
	// coverage was still measured and uncovered scope disclosed above.
	CoverageEnforced bool `json:"coverage_enforced"`

	VulnClasses   []string       `json:"vuln_classes"`
	Agents        []AgentRecord  `json:"agents"`
	Usage         map[string]any `json:"usage"`
	Cancelled     bool           `json:"cancelled"`
	EngineVersion string         `json:"engine_version"`
	ToolEnvelope  []string       `json:"tool_envelope"`
	BashEnabled   bool           `json:"bash_enabled"`

	GitCommit string `json:"git_commit"`
	GitBranch string `json:"git_branch"`
	GitDirty  bool   `json:"git_dirty"`

	SeededFromPrior string `json:"seeded_from_prior"`

	// Route/prior seeding provenance (feature 013, FR-008/009/010/011). Requested vs
	// applied are distinct so an accepted-but-inapplicable seed reads honestly (e.g.
	// seed requested with no recon phase). SeededOrCorrelated marks a run that used
	// prior findings, so it is not treated as an independent benchmark sample.
	SeedRoutesRequested   bool   `json:"seed_routes_requested"`
	SeedRoutesApplied     bool   `json:"seed_routes_applied"`
	SeedRoutesCount       int    `json:"seed_routes_count,omitempty"`
	SeedRoutesTruncated   bool   `json:"seed_routes_truncated,omitempty"`
	SeedRoutesUnavailable string `json:"seed_routes_unavailable,omitempty"`
	SeedPriorRequested    bool   `json:"seed_prior_requested"`
	SeedPriorApplied      bool   `json:"seed_prior_applied"`
	SeedPriorReport       string `json:"seed_prior_report,omitempty"`
	SeedPriorReason       string `json:"seed_prior_reason,omitempty"`
	SeededOrCorrelated    bool   `json:"seeded_or_correlated,omitempty"`

	// EffectiveConfig is the requested-vs-applied option summary (feature 013, FR-005).
	EffectiveConfig *EffectiveConfig `json:"effective_config,omitempty"`

	// Concurrency provenance (feature 013, FR-013): requested vs the effective bounded
	// worker count actually used (1 = serial).
	ConcurrencyRequested int `json:"concurrency_requested,omitempty"`
	ConcurrencyEffective int `json:"concurrency_effective,omitempty"`

	// ResumeInvalidated explains why a resume discarded prior saved work because the
	// current effective config was incompatible with the config that produced it
	// (feature 013, FR-022). Empty when resume reused compatible work or was not a resume.
	ResumeInvalidated string `json:"resume_invalidated,omitempty"`

	// PromptCaptureVersion marks that prompt records were captured by this engine
	// version (feature 014, FR-005/009). Absent → "not recorded by this version".
	PromptCaptureVersion int `json:"prompt_capture_version,omitempty"`
	// PromptHashes / ToolSchemaHashes: per-phase sha256 of the system prompt text
	// and tool envelope actually sent (feature 015, FR-027/029) — the identity a
	// comparison or replay must hold constant.
	PromptHashes     map[string]string `json:"prompt_hashes,omitempty"`
	ToolSchemaHashes map[string]string `json:"tool_schema_hashes,omitempty"`

	// Outcome is the honest completion summary (feature 014, FR-021/022): distinct
	// counts for review units, candidates, failed assignments/candidates, missing
	// artifacts, disabled optional phases, and deterministic recovery steps.
	Outcome *OutcomeSummary `json:"outcome,omitempty"`

	Aborted        string `json:"aborted"`
	ScanTag        string `json:"scan_tag"`
	ReconModel     string `json:"recon_model"`
	ReproduceModel string `json:"reproduce_model"`

	// Backend is the real provider backend (feature 005, FR-C6/FR-035): persisted so
	// deterministic regeneration restores true provenance instead of fabricating one.
	Backend string `json:"backend"`

	// Phase2Mode is the hunt dispatch mode actually executed ("split" | "combined"),
	// persisted so the manifest reflects the executed mode and regeneration restores
	// it (feature 005, FR-017).
	Phase2Mode string `json:"phase2_mode,omitempty"`

	Ledger    bool `json:"ledger"`
	Redact    bool `json:"redact"`
	Remediate bool `json:"remediate"`

	MaxBudgetUSD       float64 `json:"max_budget_usd"`
	HuntSamples        int     `json:"hunt_samples"`
	IaCLens            bool    `json:"iac_lens"`
	BudgetSpentUSD     float64 `json:"budget_spent_usd"`
	BudgetHaltedReason string  `json:"budget_halted_reason"`

	// Budget accounting provenance (feature 013, FR-021): honest disclosure of
	// whether spend could be priced. BudgetPriced is false once any call ran on a
	// backend/model with no reviewed price; BudgetUnpricedCalls counts them and
	// BudgetDisclosure explains the limitation. Additive; never report a false $0
	// cost or a false monetary ceiling. Local (ollama) inference is a real $0.
	BudgetPriced        bool   `json:"budget_priced"`
	BudgetUnpricedCalls int    `json:"budget_unpriced_calls,omitempty"`
	BudgetDisclosure    string `json:"budget_disclosure,omitempty"`

	// budget is the live, thread-safe accountant (feature 013). Unexported so it is
	// not serialized; the exported Budget* fields above carry its snapshot to disk.
	budget *BudgetAccount
	// prompts / scanlog are the live evidence sinks (feature 014); not serialized.
	prompts *promptSink
	scanlog *scanLog
	// Feature 014 US2 review-unit evidence collected during the hunt (not serialized;
	// persisted as review_units.json by finalize): the resolved partitions, the
	// inventory routes, per-unit evidence, and whether follow-up units ran.
	parts             []phases.Partition
	routes            []inventory.Route
	excludedRoutes    []inventory.ExcludedRoute // feature 015 (FR-030): ambiguous constructs, disclosed
	units             []unitEvidence
	followUpRan       bool
	HuntHaltedReason  string `json:"hunt_halted_reason"`
	QualityStrictness string `json:"quality_strictness"`

	// EndpointFailures holds per-phase endpoint-failure degradation reasons.
	// Feature 005 (FR-C6/FR-035) serializes it (was feature-004 `json:"-"`) so the
	// reasons survive deterministic regeneration; additive schema (FR-043).
	EndpointFailures []string `json:"endpoint_failures,omitempty"`

	// ArtifactErrors holds artifact-manifest validation problems (feature 006,
	// FR-013) when a real artifact_manifest.json is present; additive schema.
	ArtifactErrors []string `json:"artifact_errors,omitempty"`
}

// ToMap marshals the record to a generic map (for embedding under findings.json
// "meta") via a JSON round-trip so field names/values match scan_meta exactly.
func (r *RunRecord) ToMap() map[string]any {
	b, _ := json.Marshal(r)
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	return m
}

// Write emits scan_meta.json atomically (temp file + rename).
func (r *RunRecord) Write(resultsDir string) (string, error) {
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return "", err
	}
	out := filepath.Join(resultsDir, ScanMetaFile)
	tmp := out + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return "", err
	}
	return out, os.Rename(tmp, out)
}
