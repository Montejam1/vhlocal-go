package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"vhlocal/internal/agent"
	"vhlocal/internal/client"
	"vhlocal/internal/consolidate"
	"vhlocal/internal/phases"
	"vhlocal/internal/tools"
	"vhlocal/internal/verification"
)

const artifactContract = `Author reproduction material only for the supported candidates listed below.
Read phase2b_handoff.md and verification_decisions.json in the results directory for evidence and preconditions, and inspect the target source.
Keep each CAND-... ID unchanged. Include the exact candidate ID and canonical source location in a header/comment.
Use the actual authentication scheme. Tests must assert the claimed security impact and include a negative control, not merely print responses or accept any HTTP 200.
Write PoCs under poc/ and tests under exploit_tests/. Do not execute exploits, tests, or modify target code.
Write artifact_manifest.json as a JSON array of {"candidate_id":"CAND-...","path":"poc/...","kind":"poc|test","status":"authored"}.
Register every authored file exactly once. For each candidate without reliable reproduction material include
{"candidate_id":"CAND-...","kind":"deferred","reason":"specific limitation"}.
Do not invent PASS, execution results, locations, findings, or renumber candidates.
The harness renders phase3_output.md; do not write that file.
`

func supportedOnly(fs []consolidate.Finding) []consolidate.Finding {
	var out []consolidate.Finding
	for _, f := range fs {
		if f.VerificationStatus == "supported" {
			out = append(out, f)
		}
	}
	return out
}

func renderAssignments(root string, fs []consolidate.Finding) error {
	var b strings.Builder
	b.WriteString("# Reproduction assignments\n\nArtifact status is authored only. No execution is implied.\n\n| Candidate | Title | Source location |\n|---|---|---|\n")
	for _, f := range supportedOnly(fs) {
		fmt.Fprintf(&b, "| %s | %s | %s |\n", f.ID, strings.ReplaceAll(f.Title, "|", "/"), f.Location)
	}
	if len(supportedOnly(fs)) == 0 {
		b.WriteString("\nSkipped: no structurally validated supported candidates.\n")
	}
	return os.WriteFile(filepath.Join(root, "phase3_output.md"), []byte(b.String()), 0644)
}

// reproMaxAttempts bounds the per-candidate authoring+correction loop (FR-026).
const reproMaxAttempts = 2

func runReproduction(ctx context.Context, rec *RunRecord, p client.Provider, sb *tools.Sandbox, spec ScanSpec, system string, emit Emit) bool {
	fs, _ := loadVerifiedFindings(spec.ResultsDir, spec.Repo)
	supported := supportedOnly(fs)
	if len(supported) == 0 {
		if err := verification.WriteArtifactManifestPlaceholder(spec.ResultsDir); err != nil {
			markPhaseFailed(rec, "3", err)
			return false
		}
		rec.PhasesSkipped = append(rec.PhasesSkipped, "3")
		emit.emit("phase_skip", map[string]any{"key": "3", "reason": "zero_verified_candidates"})
		if err := renderAssignments(spec.ResultsDir, fs); err != nil {
			markPhaseFailed(rec, "3", err)
			return false
		}
		rec.ArtifactErrors = verification.ValidateArtifacts(spec.ResultsDir, fs)
		return len(rec.ArtifactErrors) == 0
	}

	// A stale manifest is never evidence that this assignment succeeded.
	if err := os.Remove(filepath.Join(spec.ResultsDir, verification.ArtifactManifestFile)); err != nil && !os.IsNotExist(err) {
		markPhaseFailed(rec, "3", err)
		return false
	}
	// Bind ONLY supported candidates; each gets a bounded authoring+correction loop
	// and ends with registered valid material or an explicit deferral (FR-025/026).
	var entries []verification.ArtifactEntry
	for _, f := range supported {
		if ctx.Err() != nil {
			rec.Cancelled = true
			return false
		}
		// A candidate is registered only with VALID authored material or a MODEL
		// deferral. Exhaustion/silence registers nothing, so ValidateArtifacts flags
		// the missing disposition and phase 3 stays incomplete (audit protection).
		if entry, ok := authorCandidate(ctx, rec, p, sb, spec, system, f, emit); ok {
			entries = append(entries, entry)
		}
	}
	if err := writeArtifactManifest(spec.ResultsDir, entries); err != nil {
		markPhaseFailed(rec, "3", err)
		return false
	}
	if err := renderAssignments(spec.ResultsDir, fs); err != nil {
		markPhaseFailed(rec, "3", err)
		return false
	}
	rec.ArtifactErrors = verification.ValidateArtifacts(spec.ResultsDir, fs)
	return len(rec.ArtifactErrors) == 0
}

// authorCandidate runs the bounded authoring loop for one supported candidate:
// author material, validate it, and on an invalid submission feed the specific
// error back for a retry. On exhaustion it returns an explicit deferral (never a
// fabricated success); candidate IDs are never renumbered. The failing output is
// left on disk for regression analysis.
func authorCandidate(ctx context.Context, rec *RunRecord, p client.Provider, sb *tools.Sandbox, spec ScanSpec, system string, f consolidate.Finding, emit Emit) (verification.ArtifactEntry, bool) {
	phase := phases.PhasesByKey["3"]
	deliverable := filepath.Join(spec.ResultsDir, "repro", f.ID+".json")
	lastErr := ""
	for attempt := 1; attempt <= reproMaxAttempts; attempt++ {
		if ctx.Err() != nil {
			return verification.ArtifactEntry{}, false
		}
		_ = os.Remove(deliverable)
		emit.emit("agent_start", map[string]any{"label": "repro:" + f.ID, "model": roleModel(spec, "3")})
		task := buildReproTask(f, deliverable, lastErr)
		res, err := agent.Run(ctx, p, sb, agent.Config{Model: roleModel(spec, "3"), NumCtx: spec.NumCtx,
			MaxTurns: phase.MaxTurns, Temperature: spec.Temperature, MaxOutputTokens: spec.MaxOutputTokens,
			ReasoningEffort: spec.ReasoningEffort, DeliverablePath: deliverable}, system, task)
		recordAgent(rec, "3", roleModel(spec, "3"), res)
		pt, ct := usageTiles(rec)
		emit.emit("agent_done", map[string]any{"label": "repro:" + f.ID, "turns": res.Turns, "stopped_reason": res.StoppedReason, "attempt": attempt, "prompt_tokens": pt, "completion_tokens": ct})
		if ctx.Err() != nil {
			return verification.ArtifactEntry{}, false
		}
		if err != nil {
			lastErr = "authoring agent failed: " + err.Error()
			continue
		}
		entry, perr := readReproEntry(deliverable, f.ID)
		if perr != "" {
			lastErr = perr
			continue
		}
		if entry.Kind == "deferred" {
			if strings.TrimSpace(entry.Reason) == "" {
				lastErr = "deferred reproduction requires a reason"
				continue
			}
			return entry, true // an explicit, reasoned MODEL deferral is a valid disposition
		}
		if why := verification.ValidateEntry(spec.ResultsDir, entry, f); why != "" {
			lastErr = why // actionable feedback for the next attempt
			continue
		}
		return entry, true
	}
	// Exhausted with no valid material and no explicit deferral: register NOTHING so
	// ValidateArtifacts flags the missing disposition (never a fabricated deferral).
	// The failing repro/<ID>.json and poc/ output stay on disk for regression review.
	emit.emit("error", map[string]any{"phase": "3", "candidate": f.ID,
		"message": fmt.Sprintf("no valid reproduction after %d attempts: %s", reproMaxAttempts, lastErr)})
	return verification.ArtifactEntry{}, false
}

// buildReproTask is the per-candidate authoring contract (one candidate, one
// deliverable). It never permits execution and preserves the candidate ID.
func buildReproTask(f consolidate.Finding, deliverable, lastErr string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Author reproduction material for EXACTLY this supported candidate — keep its ID unchanged:\n")
	fmt.Fprintf(&b, "  %s | %s | %s | %s\n\n", f.ID, f.CWE, f.Location, f.Title)
	b.WriteString("Write a PoC under poc/ (or a test under exploit_tests/) whose header/comment contains the exact candidate ID AND the canonical source location above; a test MUST assert the claimed impact (not merely print). Do NOT execute anything.\n")
	fmt.Fprintf(&b, "Then Write %s as a single JSON object:\n", deliverable)
	fmt.Fprintf(&b, "  {\"candidate_id\":%q,\"kind\":\"poc\"|\"test\",\"path\":\"poc/...\",\"status\":\"authored\"}\n", f.ID)
	fmt.Fprintf(&b, "If you cannot author reliable material, instead Write %s as:\n", deliverable)
	fmt.Fprintf(&b, "  {\"candidate_id\":%q,\"kind\":\"deferred\",\"reason\":\"<specific limitation>\"}\n", f.ID)
	if lastErr != "" {
		fmt.Fprintf(&b, "\nYour previous attempt was REJECTED: %s\nCorrect exactly that and resubmit.\n", lastErr)
	}
	return b.String()
}

// readReproEntry parses the per-candidate deliverable into an ArtifactEntry,
// forcing its candidate_id to the assigned candidate (IDs are never renumbered).
func readReproEntry(path, candidateID string) (verification.ArtifactEntry, string) {
	b, err := os.ReadFile(path)
	if err != nil {
		return verification.ArtifactEntry{}, "no reproduction deliverable was written"
	}
	var e verification.ArtifactEntry
	if json.Unmarshal(b, &e) != nil {
		return verification.ArtifactEntry{}, "reproduction deliverable is not a valid JSON object"
	}
	e.CandidateID = candidateID
	return e, ""
}

// writeArtifactManifest writes the harness-owned artifact_manifest.json atomically.
func writeArtifactManifest(root string, entries []verification.ArtifactEntry) error {
	if entries == nil {
		entries = []verification.ArtifactEntry{}
	}
	b, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		return err
	}
	path := filepath.Join(root, verification.ArtifactManifestFile)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// phaseValid checks semantic contracts before reusing completed work.
func phaseValid(spec ScanSpec, key, deliverable string) bool {
	if !deliverableValid(deliverable) {
		return false
	}
	if key == "2" {
		h, ok := loadHuntExecution(spec.ResultsDir)
		if !ok || !h.Complete {
			return false
		}
		for _, name := range h.Files {
			if !deliverableValid(filepath.Join(spec.ResultsDir, name)) {
				return false
			}
		}
		return true
	}
	if key == "2b" {
		b, err := os.ReadFile(filepath.Join(spec.ResultsDir, verification.CandidateManifestFile))
		if err != nil {
			return false
		}
		var m verification.Manifest
		if json.Unmarshal(b, &m) != nil {
			return false
		}
		b, err = os.ReadFile(filepath.Join(spec.ResultsDir, verification.DecisionsFile))
		if err != nil {
			return false
		}
		var ds []verification.Decision
		if json.Unmarshal(b, &ds) != nil {
			return false
		}
		return verification.Reconcile(&m, ds, spec.Repo).Complete
	}
	if key == "3" {
		fs, ok := loadVerifiedFindings(spec.ResultsDir, spec.Repo)
		return ok && len(verification.ValidateArtifacts(spec.ResultsDir, fs)) == 0
	}
	return true
}
