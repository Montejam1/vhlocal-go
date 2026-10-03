package engine

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"encoding/json"

	"vhlocal/internal/agent"
	"vhlocal/internal/apps"
	"vhlocal/internal/authz"
	"vhlocal/internal/client"
	"vhlocal/internal/consolidate"
	"vhlocal/internal/inventory"
	"vhlocal/internal/lifecycle"
	"vhlocal/internal/manifest"
	"vhlocal/internal/membank"
	"vhlocal/internal/phases"
	"vhlocal/internal/redact"
	"vhlocal/internal/remediation"
	"vhlocal/internal/report"
	"vhlocal/internal/sarif"
	"vhlocal/internal/sbom"
	"vhlocal/internal/threatmodel"
	"vhlocal/internal/tools"
	"vhlocal/internal/verification"
)

const baseSystem = `You are VulnHunter, an expert security auditor analysing a codebase.
You work by calling tools: Grep and Read to locate and understand code, then Grep
again to follow the data. Never answer from assumption — cite file:line for every
claim. Your deliverable is the output file: call Write with the exact path given.
Do not summarise in chat. Trace data flows to a conclusion across files.`

// ScanSpec is the resolved set of scan options (subset the engine uses).
type ScanSpec struct {
	Repo           string
	ResultsDir     string // resolved absolute results dir
	SkillDir       string
	Model          string
	Host           string
	Backend        string
	NumCtx         int
	Phases         []string // resolved, ordered phase keys
	MaxPartitions  int
	VerifyModel    string
	ReconModel     string
	ReproduceModel string
	// Per-role provider overrides (feature 013, FR-017). Blank inherits the Hunt
	// provider; when set they build a distinct provider for that role's phases so a
	// per-role backend/host actually reaches its calls (no silent switch, only
	// operator-configured endpoints).
	VerifyBackend     string
	VerifyHost        string
	ReconBackend      string
	ReconHost         string
	ReproduceBackend  string
	ReproduceHost     string
	Temperature       *float64
	MaxOutputTokens   int
	ReasoningEffort   string
	QualityStrictness string
	Phase2Mode        string // "split" (default) | "combined" (FR-017)
	ThreatModel       bool
	Ledger            bool
	Redact            bool
	Remediate         bool
	Resume            bool
	HuntSamples       int
	IaCLens           bool
	MaxBudgetUSD      float64 // paid-backend ceiling; 0 = no cap (feature 007, US7)
	AppName           string  // operator-supplied application name (honored at registration)
	EngineVersion     string
	ScanTag           string
	// EnforceCoverage gates coverage-driven hunt-plan augmentation (feature 013,
	// FR-012). A nil pointer means the default (enabled), so specs built without it
	// keep the historical augment-always behavior; an explicit false disables
	// augmentation while STILL measuring and disclosing unassigned/unreviewed scope
	// (disabling never manufactures complete coverage).
	EnforceCoverage *bool
	// Concurrency bounds overlapping hunt units (feature 013, FR-013). <=1 is strictly
	// serial (unchanged historical behavior); >1 permits bounded overlap within the
	// validated range. Zero value (0) means serial.
	Concurrency int
	// SeedRoutes injects the deterministic multi-language entry-point inventory
	// (feature 012) into Phase-1 recon as bounded, source-grounded context (feature
	// 013, FR-008). It controls recon CONTEXT only — not coverage measurement or
	// eligibility. Not applicable when no recon phase is selected.
	SeedRoutes bool
	// SeedPrior injects an eligible prior report's findings as recon leads (FR-010).
	SeedPrior bool
	// DiagnosticCapture (feature 015, FR-029): "bounded" (default) keeps failing
	// submissions + exact feedback; "full" also stores the sanitized session context
	// deduplicated by prompt hash. Never credentials, never hidden reasoning.
	DiagnosticCapture string
	// ReportsDir is the directory of prior reports, consulted for prior-report seeding
	// (feature 013, FR-010). Empty disables prior-report selection.
	ReportsDir string
	// EffectiveConfig is the requested-vs-applied option summary (feature 013,
	// FR-005), assembled by the launcher (server/CLI) and persisted verbatim into the
	// run record. The engine may append runtime non-applicability to it.
	EffectiveConfig *EffectiveConfig
	// LogTag tags this run's lines in the central log (feature 014, FR-006): the
	// server passes the job id (so the Log endpoint's tag filter finds them); the CLI
	// passes the scan tag. Empty falls back to ScanTag.
	LogTag string
}

// enforceCoverage reports whether coverage-driven augmentation is enabled (default
// true when unset, FR-012).
func (s ScanSpec) enforceCoverage() bool { return s.EnforceCoverage == nil || *s.EnforceCoverage }

// concurrency returns the effective bounded worker count (>=1); 0/negative means
// serial (FR-013).
func (s ScanSpec) concurrency() int {
	if s.Concurrency < 1 {
		return 1
	}
	return s.Concurrency
}

// SkillSource loads the methodology (preamble + phase prompts).
type SkillSource interface {
	Preamble() string
	Prompt(file string) (string, error)
}

// Providers routes phases to backends. Verify/Recon/Reproduce fall back to Hunt.
type Providers struct {
	Hunt      client.Provider
	Verify    client.Provider
	Recon     client.Provider
	Reproduce client.Provider
}

func (p Providers) forPhase(key string) client.Provider {
	switch key {
	case "1", "1t":
		if p.Recon != nil {
			return p.Recon
		}
	case "2b":
		if p.Verify != nil {
			return p.Verify
		}
	case "3", "3d", "4":
		if p.Reproduce != nil {
			return p.Reproduce
		}
	}
	return p.Hunt
}

// Emit is an optional progress callback (drives SSE / logs).
type Emit func(event string, payload map[string]any)

func (e Emit) emit(event string, payload map[string]any) {
	if e != nil {
		e(event, payload)
	}
}

const stateFile = ".vhlocal_state.json"

// Execute runs the pipeline and writes the artifact set. It returns the
// engine-observed RunRecord.
func Execute(ctx context.Context, spec ScanSpec, prov Providers, skill SkillSource, emit Emit) (*RunRecord, error) {
	if err := os.MkdirAll(spec.ResultsDir, 0o755); err != nil {
		return nil, err
	}
	rec := &RunRecord{
		StartedAt: nowUnix(), Repo: spec.Repo, ResultsDir: spec.ResultsDir,
		Model: spec.Model, Host: spec.Host, NumCtx: spec.NumCtx, MaxPartitions: spec.MaxPartitions,
		PhasesRequested: spec.Phases, PhaseTimings: map[string]float64{}, Usage: map[string]any{},
		EngineVersion: spec.EngineVersion, ToolEnvelope: agent.ToolNames(), BashEnabled: false,
		ScanTag: spec.ScanTag, ReconModel: spec.ReconModel, ReproduceModel: spec.ReproduceModel,
		Ledger: spec.Ledger, Redact: spec.Redact, Remediate: spec.Remediate,
		HuntSamples: spec.HuntSamples, IaCLens: spec.IaCLens,
		QualityStrictness: spec.QualityStrictness, VulnClasses: classCodes(),
		Backend:      spec.Backend, // FR-C6: persist the real backend for deterministic regeneration
		MaxBudgetUSD: spec.MaxBudgetUSD,
	}
	// Feature 014 (FR-005/006): open the prompt-record sink and the scan-tagged log
	// before any model call, and route every engine event through the log.
	if sink, serr := newPromptSink(spec.ResultsDir); serr == nil {
		rec.prompts = sink
		rec.PromptCaptureVersion = PromptCaptureVersion
		defer sink.Close()
	}
	rec.scanlog = newScanLog(logTag(spec))
	defer rec.scanlog.close()
	emit = withScanLog(emit, rec.scanlog)

	rec.Phase2Mode = "split" // FR-017: record the mode actually executed
	if strings.EqualFold(spec.Phase2Mode, "combined") {
		rec.Phase2Mode = "combined"
	}
	if spec.VerifyModel != "" {
		vm := spec.VerifyModel
		rec.VerifyModel = &vm
	}
	rec.VerifyBackend, rec.VerifyHost, rec.DiagnosticCapture = spec.VerifyBackend, spec.VerifyHost, spec.DiagnosticCapture
	git := client.Git(spec.Repo)
	rec.GitCommit, rec.GitBranch, rec.GitDirty = git.Commit, git.Branch, git.Dirty

	sb, err := tools.NewSandbox(spec.Repo, spec.SkillDir, spec.ResultsDir)
	if err != nil {
		return rec, err
	}

	// Deterministic entry-point inventory → partitions + coverage denominator.
	// Over-cap scope is recorded as uncovered_remaining, never silently dropped (FR-012).
	routes, excludedRoutes, _ := inventory.EnumerateRoutesDetailed(spec.Repo)
	rec.excludedRoutes = excludedRoutes
	parts, uncovered := inventory.FallbackPartitions(routes, spec.MaxPartitions)
	rec.CoverageUncoveredRemaining = uncovered
	if len(parts) == 0 {
		parts = []string{"whole-repo"}
		rec.PartitionSource = "fallback_single"
		rec.PartitionCollapsed = true
	} else {
		rec.PartitionSource = "deterministic_coverage"
	}
	rec.Partitions = parts

	// Feature 013 (FR-005): persist the requested-vs-applied effective config.
	rec.EffectiveConfig = spec.EffectiveConfig
	// Feature 013 (FR-013): concurrency provenance (requested vs effective).
	rec.ConcurrencyRequested = spec.Concurrency
	rec.ConcurrencyEffective = spec.concurrency()

	// Feature 013 (FR-009): route/prior seeding is only applicable when a recon phase
	// runs. Record a requested-but-inapplicable seed honestly rather than silently
	// launching an extra phase.
	if !reconSelected(spec.Phases) {
		if spec.SeedRoutes {
			rec.SeedRoutesRequested = true
			rec.SeedRoutesApplied = false
			rec.SeedRoutesUnavailable = "recon phase not selected"
			rec.EffectiveConfig.addNotApplicable("seed_routes", "recon phase not selected")
		}
		if spec.SeedPrior {
			rec.SeedPriorRequested = true
			rec.SeedPriorApplied = false
			rec.SeedPriorReason = "recon phase not selected"
			rec.EffectiveConfig.addNotApplicable("seed_prior", "recon phase not selected")
		}
	}

	completed := loadState(spec.ResultsDir)
	// Feature 013 (FR-022): a resume must use a COMPATIBLE effective config. If a
	// setting that invalidates saved deliverables changed since the prior run,
	// discard the stale completed state and replan (re-execute) rather than silently
	// reuse incompatible work; record the reason explicitly.
	if spec.Resume {
		if reason := resumeCompatibility(spec); reason != "" {
			rec.ResumeInvalidated = reason
			completed = map[string]bool{}
			saveState(spec.ResultsDir, completed)
			emit.emit("resume_invalidated", map[string]any{"reason": reason})
		}
	}
	// Persist identity before announcing any live artifact, but only after resume
	// compatibility has inspected the previous run's metadata.
	rec.AppSlug, rec.AppName = apps.SlugFor(spec.Repo), spec.AppName
	rec.Schema, rec.Status = "partial", "running"
	if spec.AppName != "" {
		_, err = apps.SetName(rec.AppSlug, spec.AppName, spec.Repo)
	} else {
		_, err = apps.Register(spec.Repo)
	}
	if err != nil {
		return rec, fmt.Errorf("register application: %w", err)
	}
	if _, err = rec.Write(spec.ResultsDir); err != nil {
		return rec, err
	}
	emit.emit("scan_start", map[string]any{
		"repo": spec.Repo, "results_dir": spec.ResultsDir, "model": spec.Model,
		"app_slug": rec.AppSlug, "app_name": rec.AppName,
		"verify_model": spec.VerifyModel, "phases": spec.Phases, "num_ctx": spec.NumCtx,
	})
	system := baseSystem
	if pre := skill.Preamble(); pre != "" {
		system += "\n\n" + pre
	}

	for _, key := range spec.Phases {
		spec2, ok := phases.PhasesByKey[key]
		if !ok {
			continue
		}
		if key == "1t" && !spec.ThreatModel {
			rec.PhasesSkipped = append(rec.PhasesSkipped, key)
			continue
		}
		deliverable := filepath.Join(spec.ResultsDir, spec2.OutputFile)
		if spec.Resume && completed[key] && phaseValid(spec, key, deliverable) {
			// FR-033: valid resumed work counts toward effective completion, so a
			// fully-resumed run is not reported incomplete. It is both skipped (not
			// re-run) and completed (its deliverable is present and valid).
			rec.PhasesSkipped = append(rec.PhasesSkipped, key)
			rec.PhasesCompleted = append(rec.PhasesCompleted, key)
			emit.emit("phase_skip", map[string]any{"key": key, "reason": "resume"})
			continue
		}
		// Re-running an upstream phase invalidates saved downstream work.
		invalidating := false
		for _, dependent := range []string{"1", "1t", "2", "2b", "3", "3d", "4"} {
			if dependent == key {
				invalidating = true
			}
			if invalidating {
				delete(completed, dependent)
			}
		}
		saveState(spec.ResultsDir, completed)
		emit.emit("phase_start", map[string]any{"key": key, "title": spec2.Title})
		start := time.Now()
		if err := ctx.Err(); err != nil {
			// FR-C5: cancellation is distinct from abort — set Cancelled only (never
			// Aborted), so ComputeRunStatus yields execution_status=cancelled.
			rec.Cancelled = true
			break
		}

		var prompt string
		var perr error
		if key != "3" && key != "3d" && key != "4" {
			prompt, perr = skill.Prompt(spec2.PromptFile)
		}
		if perr != nil {
			// FR-009: a missing/unreadable required methodology file is an explicit
			// configuration failure — surface + record it and skip the phase; never
			// run an agent on a placeholder prompt (which burns budget and fabricates
			// output). The phase is not marked produced, so status degrades honestly.
			rec.EndpointFailures = append(rec.EndpointFailures, fmt.Sprintf("phase %s configuration error: prompt %q unavailable: %v", key, spec2.PromptFile, perr))
			emit.emit("error", map[string]any{"phase": key, "message": "prompt unavailable: " + perr.Error(), "kind": "config"})
			continue
		}
		p := prov.forPhase(key)
		produced := false
		if spec2.FanOut {
			// US1: resolve partitions from the model's Phase-1 plan (with corrective
			// retry + augmentation), recording source/fallback/uncovered, then hunt
			// over them — not a single collapsed deterministic partition.
			parts := resolveHuntPartitions(ctx, rec, p, spec, routes)
			rec.parts, rec.routes = parts, routes // feature 014: review-unit assignments
			produced = runHunt(ctx, rec, p, sb, spec, skill, system, parts, emit)
		} else if key == "2b" {
			// Phase 2b is the adversarial, candidate-bound verification session (US3),
			// not a generic agent: it builds the candidate manifest, verifies each
			// candidate with evidence, reconciles dispositions, and writes the handoff.
			// Feature 015 (C-C5): the tested worked examples ride in the system prompt.
			sessionPrompt, _ := skill.Prompt("phase2b_session.md")
			produced = runVerificationWith(ctx, rec, recordPrompts(p, rec.prompts, promptMeta{scanTag: spec.ScanTag, phase: "2b", label: "verify", role: "verify", model: roleModel(spec, "2b")}), sb, spec, system,
				verifyOptions{sessionPrompt: sessionPrompt, diagnosticCapture: spec.DiagnosticCapture}, emit)
		} else if key == "3" {
			produced = runReproduction(ctx, rec, recordPrompts(p, rec.prompts, promptMeta{scanTag: spec.ScanTag, phase: "3", label: "reproduce", role: "reproduce", model: roleModel(spec, "3")}), sb, spec, system, emit)
		} else if key == "3d" {
			fs, _ := loadVerifiedFindings(spec.ResultsDir, spec.Repo)
			err := writeSweep(spec.Repo, spec.ResultsDir, supportedOnly(fs))
			produced = err == nil
			if err != nil {
				markPhaseFailed(rec, key, err)
			}
			rec.Agents = append(rec.Agents, AgentRecord{Label: "3d", Phase: "3d", Model: "deterministic", StoppedReason: "complete"})
		} else if key == "4" {
			// Canonical rendering follows finalization; the model cannot invent
			// a second finding list or claim artifact execution in README.md.
			err := os.WriteFile(deliverable, []byte("# Scan report\n\nCanonical rendering follows scan finalization.\n"), 0644)
			produced = err == nil
			if err != nil {
				markPhaseFailed(rec, key, err)
			}
			rec.Agents = append(rec.Agents, AgentRecord{Label: "4", Phase: "4", Model: "deterministic", StoppedReason: "complete"})
		} else {
			cfg := agent.Config{Model: roleModel(spec, key), NumCtx: spec.NumCtx, MaxTurns: spec2.MaxTurns,
				Temperature: spec.Temperature, MaxOutputTokens: spec.MaxOutputTokens, ReasoningEffort: spec.ReasoningEffort,
				DeliverablePath: deliverable} // FR-005: nudge to write before max_turns
			task := buildTask(prompt, spec2, spec.ResultsDir, spec.Repo)
			if key == "1" || key == "1t" {
				task = applyRouteSeed(rec, spec, task) // feature 013 FR-008: recon context only
				task = applyPriorSeed(rec, spec, task) // feature 013 FR-010: prior findings as leads
			}
			pp := recordPrompts(p, rec.prompts, promptMeta{scanTag: spec.ScanTag, phase: key, label: key, role: roleFor(key), model: roleModel(spec, key)})
			res, aerr := agent.Run(ctx, pp, sb, cfg, system, task)
			recordAgent(rec, key, roleModel(spec, key), res)
			pt, ct := usageTiles(rec)
			emit.emit("agent_done", map[string]any{"label": key, "turns": res.Turns, "stopped_reason": res.StoppedReason, "prompt_tokens": pt, "completion_tokens": ct})
			if aerr != nil && (errors.Is(aerr, context.Canceled) || errors.Is(aerr, context.DeadlineExceeded)) {
				// FR-C5: a cancelled in-flight agent is NOT an endpoint failure — record
				// cancellation and stop; artifacts still finalize after the loop.
				rec.Cancelled = true
				break
			}
			if aerr != nil {
				// Per-phase endpoint failure degrades THIS phase; the scan continues to
				// the remaining requested phases and still finalizes the artifact set
				// (FR-006/007; C-E1/E3). rec.Aborted stays reserved for cancellation — a
				// single phase's endpoint failure never aborts the whole run.
				markPhaseFailed(rec, key, aerr)
				emit.emit("error", map[string]any{"message": aerr.Error(), "phase": key})
			} else {
				produced = deliverableValid(deliverable)
				if produced { // feature 014 (FR-006): output writes are logged events
					emit.emit("output_written", map[string]any{"label": key, "path": deliverable})
				} else {
					emit.emit("validation_failure", map[string]any{"label": key, "path": deliverable, "reason": "deliverable missing or empty after agent stopped"})
				}
				// 1t also builds the SBOM (deterministic). A write failure is
				// surfaced as a degraded reason, not silently discarded (FR-018).
				if key == "1t" {
					if _, serr := sbom.Write(spec.Repo, spec.ResultsDir, isoNow()); serr != nil {
						rec.EndpointFailures = append(rec.EndpointFailures, "sbom generation failed: "+serr.Error())
						emit.emit("error", map[string]any{"message": "sbom generation failed: " + serr.Error(), "phase": key})
					}
					// Feature 015 (FR-011): the diagram is a validated artifact — write
					// threat_model_diagram.json now so the live view can show its state.
					if art, ok, derr := threatmodel.WriteArtifact(spec.ResultsDir); derr != nil {
						emit.emit("error", map[string]any{"message": "diagram validation failed: " + derr.Error(), "phase": key})
					} else if ok {
						emit.emit("diagram", map[string]any{"label": key, "summary": art.Summary()})
					}
				}
			}
		}
		rec.PhaseTimings[key] = round1(time.Since(start).Seconds())
		if produced {
			rec.PhasesCompleted = append(rec.PhasesCompleted, key)
			completed[key] = true
		} else {
			delete(completed, key)
		}
		saveState(spec.ResultsDir, completed)
		emit.emit("phase_done", map[string]any{"key": key, "seconds": rec.PhaseTimings[key], "produced": produced})
	}

	rec.FinishedAt = nowUnix()
	if err := finalize(spec, rec, routes, emit); err != nil {
		return rec, err
	}
	// Feature 015 (FR-027/029): persist the exact prompt/tool-schema identity used.
	rec.PromptHashes, rec.ToolSchemaHashes = rec.prompts.Hashes()
	rec.Schema, rec.Status = "final", "done"
	if rec.Cancelled {
		rec.Status = "cancelled"
	} else if rec.Aborted != "" {
		rec.Status = "failed"
	}
	if _, err := rec.Write(spec.ResultsDir); err != nil {
		return rec, err
	}
	emit.emit("scan_done", map[string]any{
		"seconds": round1(rec.FinishedAt - rec.StartedAt), "cancelled": rec.Cancelled,
		"aborted": nilIfEmpty(rec.Aborted), "results_dir": spec.ResultsDir,
	})
	return rec, nil
}

// finalize extracts findings, consolidates, and writes the artifact set.
func finalize(spec ScanSpec, rec *RunRecord, routes []inventory.Route, emit Emit) error {
	// Findings come from the verification layer (candidate manifest + reconciled
	// decisions) when it ran — every candidate carries its supported/rejected/
	// unresolved disposition and FromConfirmed=supported only (US3; FR-C1/C2).
	// Falling back to collectFindings (phase2b_output.md) only when no manifest
	// exists; that path never resurrects raw hunt output.
	// Refresh persisted verification before publication, including report-only
	// regeneration. Old Markdown and malformed manifests cannot confer support.
	if data, err := os.ReadFile(filepath.Join(spec.ResultsDir, verification.CandidateManifestFile)); err == nil {
		var m verification.Manifest
		if json.Unmarshal(data, &m) == nil {
			var ds []verification.Decision
			if data, err := os.ReadFile(filepath.Join(spec.ResultsDir, verification.DecisionsFile)); err == nil {
				_ = json.Unmarshal(data, &ds)
			}
			rcF := verification.Reconcile(&m, ds, spec.Repo)
			// Feature 014 (FR-018): re-rendering at finalize must keep the per-class,
			// per-operation reasons — never overwrite them with the generic one.
			verification.EnrichReasons(rcF, verification.LoadSessions(spec.ResultsDir))
			if err := verification.Render(spec.ResultsDir, &m, rcF); err != nil {
				return err
			}
		}
	}
	if containsStr(rec.PhasesCompleted, "2b") && !phaseValid(spec, "2b", filepath.Join(spec.ResultsDir, "phase2b_output.md")) {
		var complete []string
		for _, key := range rec.PhasesCompleted {
			if key != "2b" {
				complete = append(complete, key)
			}
		}
		rec.PhasesCompleted = complete
		state := loadState(spec.ResultsDir)
		delete(state, "2b")
		saveState(spec.ResultsDir, state)
	}
	findings, verified := loadVerifiedFindings(spec.ResultsDir, spec.Repo)
	if !verified {
		findings, _ = collectFindings(spec.ResultsDir)
		for i := range findings {
			findings[i].FromConfirmed = false
			findings[i].VerificationStatus = "unresolved"
			findings[i].VerificationReason = "no structured verification decision is available"
		}
	}
	findings = consolidate.Prepare(findings)
	// Deterministic pre-report quality battery sets classification/assessment.
	for i := range findings {
		consolidate.ApplyQuality(&findings[i], spec.QualityStrictness, spec.Repo)
	}
	emit.emit("findings", map[string]any{"count": countNonDup(findings), "stage": "final"})

	// Validate even an empty manifest, before computing status or publishing any
	// report. Missing artifacts must not be hidden by an empty placeholder.
	if !fileExists(filepath.Join(spec.ResultsDir, verification.ArtifactManifestFile)) {
		if err := verification.WriteArtifactManifestPlaceholder(spec.ResultsDir); err != nil {
			return err
		}
	}
	rec.ArtifactErrors = nil
	if containsStr(rec.PhasesRequested, "3") || artifactManifestPresent(spec.ResultsDir) {
		rec.ArtifactErrors = verification.ValidateArtifacts(spec.ResultsDir, findings)
		if len(rec.ArtifactErrors) > 0 {
			var complete []string
			for _, key := range rec.PhasesCompleted {
				if key != "3" {
					complete = append(complete, key)
				}
			}
			rec.PhasesCompleted = complete
			state := loadState(spec.ResultsDir)
			delete(state, "3")
			saveState(spec.ResultsDir, state)
			emit.emit("artifacts", map[string]any{"errors": len(rec.ArtifactErrors), "stage": "final"})
		}
	}

	// Coverage ledger from inventory + resolved finding locations (feature 012,
	// T048): a route is finding_emitted only when a finding falls inside its handler
	// span; a bare filename/path mention no longer marks a route reviewed (FR-025/026).
	var findingLocs []inventory.FindingLoc
	// Feature 014 (FR-013): when verification (2b) was part of this run, an UNRESOLVED
	// candidate is not evidence that its handler was reviewed — its verification never
	// completed. Supported and rejected findings were checked against source (the
	// handler was examined). When 2b was not requested, consolidation stamps every
	// hunt finding "unresolved" fail-closed, so the hunt's candidate remains the only
	// (historical) coverage evidence and is kept. This is what the Go e2e fixture
	// always intended (LOG-003 unresolved at `health` must not mark it reviewed).
	verificationRan := containsStr(rec.PhasesRequested, "2b")
	for _, f := range findings {
		if verificationRan && f.VerificationStatus == "unresolved" {
			continue
		}
		file, line := splitLocation(f.Location)
		if file != "" {
			findingLocs = append(findingLocs, inventory.FindingLoc{File: file, Line: line})
		}
	}
	// Feature 014 (FR-010..016): review units — evidence-backed dispositions. A live
	// run derives them from the hunt's unit evidence and persists them; regeneration
	// (no in-memory evidence) reloads the persisted record and never invents any.
	var ru *ReviewUnits
	if rec.parts != nil || rec.units != nil {
		ru = buildReviewUnits(spec, rec, routes, findingLocs)
		if err := writeReviewUnits(spec.ResultsDir, ru); err != nil {
			return err
		}
		if err := annotateHuntExecution(spec.ResultsDir, ru); err != nil {
			return err
		}
	} else {
		ru, _ = loadReviewUnits(spec.ResultsDir)
	}
	cl := inventory.BuildLedgerWithEvidence(routes, findingLocs, spec.Repo, ledgerEvidence(ru, rec.GitCommit))
	// Feature 015 (FR-019): the ledger names the evidence standard it was built from
	// and carries the exposure axis (never derived from the reviewed count).
	if ru != nil {
		cl.SemanticsVersion = ru.SemanticsVersion
		cl.Counts["source_exposed"] = ru.Counts.SourceExposed
	}
	cl.AddExcluded(rec.excludedRoutes) // feature 015 (FR-030): outside Total, with reasons
	if _, err := writeJSON(filepath.Join(spec.ResultsDir, "coverage_ledger.json"), cl); err != nil {
		return err
	}
	// Feature 015: (re)validate the threat-model diagram from the file on disk — the
	// same at finalize and at regeneration (records only, never the model).
	diagramSummary := ""
	if art, ok, derr := threatmodel.WriteArtifact(spec.ResultsDir); derr != nil {
		rec.EndpointFailures = append(rec.EndpointFailures, "diagram validation failed: "+derr.Error())
	} else if ok {
		diagramSummary = art.Summary()
	}
	// Authorization map (deterministic; cross-endpoint auth gaps).
	if spec.Repo != "" {
		_, _ = authz.Write(spec.Repo, spec.ResultsDir)
	}

	// [FR-009/010/012] Degradation reasons from engine facts + the strict
	// reliability predicate. reliable = execution complete AND (recon requested ⇒
	// map produced) AND (hunt requested ⇒ hunt produced output).
	reconRequested := containsStr(rec.PhasesRequested, "1")
	huntRequested := containsStr(rec.PhasesRequested, "2")
	reconMap := deliverableValid(filepath.Join(spec.ResultsDir, "phase1_output.md"))
	huntProduced := deliverableValid(filepath.Join(spec.ResultsDir, "results"))

	var degraded []string
	srcFiles := countPySource(spec.Repo)
	if len(routes) == 0 && srcFiles >= 20 {
		degraded = append(degraded, fmt.Sprintf("recon enumerated no entry points over %d source files", srcFiles))
	}
	if srcFiles >= 150 && len(rec.Partitions) <= 1 {
		degraded = append(degraded, "large codebase hunted in a single partition")
	}
	if reconRequested && !reconMap {
		degraded = append(degraded, "recon produced no attack-surface map")
	}
	if huntRequested && !huntProduced {
		degraded = append(degraded, "hunt produced no candidates (pipeline incomplete, not a clean result)")
	}
	for _, a := range rec.Agents {
		// Phase 2b runs one session PER CANDIDATE; a per-candidate max_turns or
		// tool_repair just means that candidate stays unresolved (captured in the
		// verification reconciliation/metrics), not a run-level coverage degradation.
		// Summarize verification health once (below) instead of flooding one reason
		// per session.
		if a.Phase == "2b" {
			continue
		}
		switch a.StoppedReason {
		case agent.StopToolRepair:
			degraded = append(degraded, fmt.Sprintf("phase %s agent gave up on tool-call errors", a.Phase))
		case agent.StopMaxTurns:
			degraded = append(degraded, fmt.Sprintf("phase %s agent hit max_turns without completing", a.Phase))
		case agent.StopEndpointFailure:
			if len(rec.EndpointFailures) == 0 {
				degraded = append(degraded, fmt.Sprintf("phase %s endpoint failure", a.Phase))
			}
		}
	}
	// Verification health, summarized once (not per candidate): how many candidates
	// were left unresolved.
	if unref := unresolvedCount(spec.ResultsDir); unref > 0 {
		degraded = append(degraded, fmt.Sprintf("verification left %d candidate(s) unresolved", unref))
	}
	// Per-phase endpoint failures (feature 004, FR-006/008; C-E2/E4): explicit,
	// detailed coverage-degradation reasons. Now serialized (FR-C6) so they survive
	// deterministic regeneration.
	degraded = append(degraded, rec.EndpointFailures...)
	for _, err := range rec.ArtifactErrors {
		degraded = append(degraded, "phase 3: "+err)
	}
	degraded = dedupStrings(degraded)

	// Feature 013 (FR-019): the threat-model phase (1t) is OPTIONAL, gated by the
	// threat_model toggle. When it is off, `phases=all` must not read as incomplete
	// merely because the deliberately-disabled optional phase did not run — so it is
	// excluded from the execution-status denominator (the stored phases_requested is
	// unchanged; PhasesSkipped still records it honestly).
	execRequested := rec.PhasesRequested
	if !spec.ThreatModel {
		execRequested = withoutPhase(execRequested, "1t")
	}
	status := consolidate.ComputeRunStatus(consolidate.StatusInput{
		Aborted: rec.Aborted, Cancelled: rec.Cancelled,
		PhasesRequested: execRequested, PhasesCompleted: rec.PhasesCompleted,
		BashEnabled: rec.BashEnabled, CoverageComplete: cl.Complete, CoverageKnown: true,
		NotReviewed: cl.NotReviewed, DegradedReasons: degraded,
	})
	// Feature 014 (FR-021..023): the completion block is assembled from persisted
	// records only, so a live finalize and a report-only regeneration produce the
	// identical block. It rides on the record (scan_meta.json) and on
	// findings.json run_status.outcome; the report renders that same value.
	rec.Outcome = buildOutcome(spec, rec, ru)
	status.Outcome = rec.Outcome

	// [T1] Reliable is STRICTER than coverage_status=="degraded": a reliable run
	// may still be coverage-degraded and MUST still reconcile lifecycle.
	reliable := status.ExecutionStatus == consolidate.ExecComplete &&
		(!reconRequested || reconMap) && (!huntRequested || huntProduced)
	var reliableReason string
	if !reliable {
		reliableReason = "run under-delivered: " + strings.Join(degraded, "; ")
		if reliableReason == "run under-delivered: " {
			reliableReason = "run did not complete all requested phases"
		}
	}

	cov := &consolidate.CoverageInfo{TotalEntryPoints: cl.Total, Reviewed: cl.Reviewed, NotReviewed: cl.NotReviewed, Complete: cl.Complete}
	var sbomSummary any
	if spec.ThreatModel {
		s := sbom.Summarize(spec.Repo)
		sbomSummary = s
	}

	// Cross-run lifecycle reconciliation (Mode A) — deterministic, no model.
	// [T1/FR-007] Suppressed on unreliable runs so a broken run never claims prior
	// findings were "fixed"; a reliable (even coverage-degraded) run reconciles.
	var lifecycleBlock any
	switch {
	case reliable && !cl.Complete && ru != nil && ru.SemanticsVersion >= CoverageSemanticsV2:
		// Feature 015 (C-B8): a reliable run with incomplete v2 source review cannot
		// tell "fixed" from "not looked at" — prior findings stay unknown_incomparable.
		lifecycleBlock = lifecycle.Incomparable(fmt.Sprintf("source review incomplete: %d of %d entry points completed (%s)", ru.Counts.ReviewedWithFindings+ru.Counts.ReviewedNoIssue, ru.Counts.Total, ru.Label()))
	case reliable:
		lifecycleBlock = reconcileLifecycle(spec, rec, findings)
	default:
		lifecycleBlock = lifecycle.Suppressed(reliableReason)
	}

	// Register the scanned repo as an application unconditionally (feature 007,
	// FR-007): discovery MUST NOT depend on opting into vulnerability tracking.
	// Honor an operator-supplied app name (FR-034); a failure is surfaced as a
	// degraded-coverage reason, not swallowed.
	var regErr error
	if strings.TrimSpace(spec.AppName) != "" {
		_, regErr = apps.SetName(apps.SlugFor(spec.Repo), spec.AppName, spec.Repo)
	} else {
		_, regErr = apps.Register(spec.Repo)
	}
	if regErr != nil {
		rec.EndpointFailures = append(rec.EndpointFailures, "application registry: "+regErr.Error())
	}

	// Vulnerability ledger (opt-in) — merge + coverage summary.
	var ledgerBlock any
	if spec.Ledger {
		runID := filepath.Base(spec.ResultsDir)
		_, _ = membank.Update(spec.Repo, runID, spec.Model, rec.FinishedAt, findings)
		ledgerBlock = membank.CoverageSummary(spec.Repo, runID, findings)
	}

	// Remediation DTOs (opt-in, report-only).
	var remediationBlock any
	if spec.Remediate {
		var fvs []remediation.FindingView
		for _, f := range findings {
			fvs = append(fvs, remediation.FindingView{
				ID: f.ID, Title: f.Title, CWE: f.CWE, Location: f.Location,
				Severity: f.Severity, Fix: f.Fix, CanonicalName: f.CanonicalName,
				Duplicate: f.DuplicateOf != nil,
			})
		}
		n, _ := remediation.Write(spec.ResultsDir, fvs)
		remediationBlock = map[string]any{"count": n}
	}

	doc := consolidate.Build(findings, consolidate.Options{
		Meta: rec.ToMap(), EngineVersion: spec.EngineVersion, HuntModel: spec.Model,
		VerifyModel: spec.VerifyModel, Status: status, Coverage: cov, SBOM: sbomSummary,
		Lifecycle: lifecycleBlock, VulnerabilityLedger: ledgerBlock, Remediation: remediationBlock,
	})
	if _, err := doc.Write(spec.ResultsDir); err != nil {
		return err
	}
	if _, err := sarif.Write(findings, status, spec.EngineVersion, spec.Repo, spec.Model, spec.ResultsDir); err != nil {
		return err
	}
	man := manifest.Input{
		EngineVersion: spec.EngineVersion, RunID: filepath.Base(spec.ResultsDir), Repo: spec.Repo,
		GitCommit: rec.GitCommit, GitBranch: rec.GitBranch, HuntModel: spec.Model,
		VerifyModel: spec.VerifyModel, ReconModel: spec.ReconModel, ReproduceModel: spec.ReproduceModel,
		Backend: spec.Backend, Host: spec.Host, NumCtx: spec.NumCtx, MaxPartitions: spec.MaxPartitions,
		Phase2Mode: manifestMode(rec.Phase2Mode), QualityStrictness: spec.QualityStrictness, PhasesRequested: rec.PhasesRequested,
		Ledger: spec.Ledger, Redact: spec.Redact, HuntSamples: spec.HuntSamples,
		StartedAt: rec.StartedAt, FinishedAt: rec.FinishedAt, PhaseTimings: rec.PhaseTimings,
		ExecutionStatus: status.ExecutionStatus, CoverageStatus: status.CoverageStatus,
		CoverageDegradedReasons: status.CoverageDegradedReasons, AgentsTotal: len(rec.Agents),
		AgentsIncomplete: agentsIncomplete(rec), SeverityCounts: doc.Counts, FindingsTotal: countNonDup(findings),
	}
	if _, err := man.Write(spec.ResultsDir); err != nil {
		return err
	}
	// The candidate manifest is built by the verification phase (US3), not here, so
	// finalize never rebuilds/overwrites it. If 2b did not run, ensure one exists so
	// downstream readers/regeneration have a spine.
	if !fileExists(filepath.Join(spec.ResultsDir, verification.CandidateManifestFile)) {
		rev := "tree-sha256:unknown"
		if rec.GitCommit != "" {
			rev = rec.GitCommit
		}
		if _, err := verification.BuildManifest(spec.ResultsDir, spec.Repo, rev, findings); err != nil {
			return err
		}
	}

	groups, gerr := buildRemediationGroups(spec, findings)
	if gerr != nil {
		return gerr
	}
	ri := report.Input{
		Target: filepath.Base(spec.Repo), Model: spec.Model, Host: spec.Host,
		StartedAt: isoFrom(rec.StartedAt), FinishedAt: isoFrom(rec.FinishedAt),
		Duration: fmt.Sprintf("%.1fs", rec.FinishedAt-rec.StartedAt),
		Doc:      doc, CodeExecuted: rec.BashEnabled, VerifyModelUsed: spec.VerifyModel != "",
		Nav: reportNav(spec.ResultsDir), Repro: reproDispositions(spec.ResultsDir),
		ReviewGaps: reportGaps(ru),
		// Feature 015: identity, revision and the coverage view for the report model.
		ScanID: filepath.Base(spec.ResultsDir), Repo: spec.Repo, GitCommit: rec.GitCommit, GitBranch: rec.GitBranch,
		Coverage: coverageView(ru), CoverageLabel: ru.Label(), Diagram: diagramSummary,
		Failures: failureAggregates(spec.ResultsDir),
		Groups:   groups,
	}
	md, _, err := report.Write(ri, spec.ResultsDir)
	if err != nil {
		return err
	}
	if containsStr(rec.PhasesRequested, "4") {
		b, err := os.ReadFile(md)
		if err != nil {
			return err
		}
		if err = os.WriteFile(filepath.Join(spec.ResultsDir, "README.md"), b, 0644); err != nil {
			return err
		}
	}

	// Redaction (opt-in): mask secrets/PII in the written text artifacts.
	if spec.Redact {
		_, _ = redact.MaskFiles(spec.ResultsDir, []string{
			"SCAN_REPORT.md", "SCAN_REPORT.html", "phase1_output.md",
			"phase2b_output.md", "phase3_output.md", "phase3d_output.md", "README.md",
		})
	}
	return nil
}

// reportNav lists the intelligence artifacts present alongside the report so the
// report can link to them (feature 007, US6/FR-032).
func reportNav(resultsDir string) []report.NavLink {
	var nav []report.NavLink
	for _, e := range []report.NavLink{
		{Label: "Threat model", Path: "threat_model.md"},
		{Label: "SBOM", Path: "sbom.cdx.json"},
		{Label: "Coverage ledger", Path: "coverage_ledger.json"},
		{Label: "Sweep leads", Path: "phase3d_output.md"},
		{Label: "Verified handoff", Path: "phase2b_handoff.md"},
	} {
		if fileExists(filepath.Join(resultsDir, e.Path)) {
			nav = append(nav, e)
		}
	}
	return nav
}

// reproDispositions maps each candidate id to its artifact-manifest disposition
// (kind/path/status/reason) for the report's per-finding reproduction line.
func reproDispositions(resultsDir string) map[string]map[string]any {
	out := map[string]map[string]any{}
	b, err := os.ReadFile(filepath.Join(resultsDir, verification.ArtifactManifestFile))
	if err != nil {
		return out
	}
	var entries []map[string]any
	if json.Unmarshal(b, &entries) != nil {
		return out
	}
	for _, e := range entries {
		if id, _ := e["candidate_id"].(string); id != "" {
			out[id] = e
		}
	}
	return out
}

// reconcileLifecycle finds the most recent prior report of the same repo and
// reconciles the current findings against it (Mode A). No prior → baseline.
func reconcileLifecycle(spec ScanSpec, rec *RunRecord, findings []consolidate.Finding) map[string]any {
	prior, priorFixed, priorReport, priorCommit, ok := findPriorReport(spec.ResultsDir, spec.Repo, rec.StartedAt)
	if !ok {
		return lifecycle.NoPrior(findings, rec.GitCommit)
	}
	return lifecycle.Reconcile(findings, prior, priorFixed, priorReport, priorCommit, rec.GitCommit)
}

// findPriorReport scans sibling result directories for the newest scan of the
// same repo started strictly before startedAt, returning its findings and the
// fixed_keys it recorded.
func findPriorReport(resultsDir, repo string, startedAt float64) (prior []consolidate.Finding, priorFixed []string, priorReport, priorCommit string, ok bool) {
	parent := filepath.Dir(resultsDir)
	entries, err := os.ReadDir(parent)
	if err != nil {
		return nil, nil, "", "", false
	}
	repoAbs, _ := filepath.Abs(repo)
	var bestStart float64
	var bestDir string
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		dir := filepath.Join(parent, e.Name())
		if dir == resultsDir {
			continue
		}
		metaB, err := os.ReadFile(filepath.Join(dir, ScanMetaFile))
		if err != nil {
			continue
		}
		var m struct {
			Repo      string  `json:"repo"`
			StartedAt float64 `json:"started_at"`
		}
		if json.Unmarshal(metaB, &m) != nil {
			continue
		}
		mRepoAbs, _ := filepath.Abs(m.Repo)
		if mRepoAbs != repoAbs || m.StartedAt >= startedAt {
			continue
		}
		if m.StartedAt > bestStart {
			bestStart = m.StartedAt
			bestDir = dir
		}
	}
	if bestDir == "" {
		return nil, nil, "", "", false
	}
	fb, err := os.ReadFile(filepath.Join(bestDir, consolidate.FindingsJSONFile))
	if err != nil {
		return nil, nil, "", "", false
	}
	var doc struct {
		Findings  []consolidate.Finding `json:"findings"`
		Lifecycle struct {
			FixedKeys []string `json:"fixed_keys"`
		} `json:"lifecycle"`
		Meta struct {
			GitCommit string `json:"git_commit"`
		} `json:"meta"`
	}
	if json.Unmarshal(fb, &doc) != nil {
		return nil, nil, "", "", false
	}
	return doc.Findings, doc.Lifecycle.FixedKeys, filepath.Base(bestDir), doc.Meta.GitCommit, true
}
