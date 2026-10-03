package engine

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"vhlocal/internal/agent"
	"vhlocal/internal/consolidate"
	"vhlocal/internal/phases"
	"vhlocal/internal/recognize"
	"vhlocal/internal/tools"
)

func nowUnix() float64 { return float64(time.Now().UnixNano()) / 1e9 }
func isoNow() string   { return time.Now().UTC().Format(time.RFC3339) }
func isoFrom(u float64) string {
	if u <= 0 {
		return ""
	}
	return time.Unix(int64(u), 0).UTC().Format("2006-01-02 15:04:05")
}
func round1(f float64) float64 { return float64(int(f*10+0.5)) / 10 }

func nilIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func classCodes() []string {
	out := make([]string, 0, len(phases.ClassGroups))
	for _, c := range phases.ClassGroups {
		out = append(out, c.Code)
	}
	return out
}

// roleModel returns the model for a phase's role (verify/recon/reproduce fall
// back to the hunt model).
func roleModel(spec ScanSpec, key string) string {
	switch key {
	case "1", "1t":
		if spec.ReconModel != "" {
			return spec.ReconModel
		}
	case "2b":
		if spec.VerifyModel != "" {
			return spec.VerifyModel
		}
	case "3", "3d", "4":
		if spec.ReproduceModel != "" {
			return spec.ReproduceModel
		}
	}
	return spec.Model
}

// buildTask assembles the grounded per-phase agent instruction (FR-001/002): an
// assignment header naming the absolute target repository (read-only), the results
// directory (the agent's only writable location), the assigned scope, the exact
// deliverable, then the phase prompt and the prior-phase inputs to read first.
func buildTask(prompt string, spec phases.PhaseSpec, resultsDir, repo string) string {
	out := filepath.Join(resultsDir, spec.OutputFile)
	var b strings.Builder
	fmt.Fprintf(&b, "# Assignment: Phase %s — %s\n", spec.Key, spec.Title)
	fmt.Fprintf(&b, "**Target repository (read-only):** %s\n", repo)
	fmt.Fprintf(&b, "**Results directory (your only writable location):** %s\n", resultsDir)
	fmt.Fprintf(&b, "**Assigned scope:** the whole target repository at %s\n", repo)
	if strings.HasSuffix(spec.OutputFile, "/") {
		fmt.Fprintf(&b, "**Your deliverable:** write per-unit markdown files under %s\n\n", out)
	} else {
		fmt.Fprintf(&b, "**Your deliverable:** the file %s (write it with the Write tool)\n\n", out)
	}
	b.WriteString(prompt)
	if len(spec.Reads) > 0 {
		b.WriteString("\n\n## Inputs produced by earlier phases — Read these before you begin:\n")
		for _, r := range spec.Reads {
			b.WriteString("  - " + filepath.Join(resultsDir, r) + "\n")
		}
	}
	b.WriteString("\n---\nWrite your complete output to this exact path using the Write tool: " + out + "\n")
	return b.String()
}

func recordAgent(rec *RunRecord, phaseKey, model string, res agent.Result) {
	appendAgent(rec, phaseKey, model, res)
	accrueBudget(rec, model, res)
}

// appendAgent records an agent and its token usage WITHOUT budget accrual. The
// bounded-concurrency merge (US3) uses it because parallel units already accrued
// budget live and thread-safely; folding here in deterministic order must not
// double-count (feature 013, FR-014).
func appendAgent(rec *RunRecord, phaseKey, model string, res agent.Result) {
	rec.Agents = append(rec.Agents, AgentRecord{
		Label: phaseKey, Phase: phaseKey, Model: model,
		Turns: res.Turns, StoppedReason: res.StoppedReason,
		PromptTokens: res.Usage.PromptTokens, CompletionTokens: res.Usage.CompletionTokens,
		RepairAttempts: res.RepairAttempts, RepairSuccesses: res.RepairSuccesses,
	})
	addUsage(rec, res)
}

// syncBudgetSnapshot mirrors the live budget account onto the serialized record
// (feature 013). Used after the parallel merge, where units accrued budget live.
func syncBudgetSnapshot(rec *RunRecord) {
	if rec.budget == nil {
		return
	}
	spent, priced, unpriced := rec.budget.Snapshot()
	rec.BudgetSpentUSD = spent
	rec.BudgetPriced = priced
	rec.BudgetUnpricedCalls = unpriced
	rec.BudgetDisclosure = budgetDisclosure(rec.MaxBudgetUSD, spent, priced, unpriced)
}

// accrueBudget folds one agent's usage into the run's budget account and mirrors
// the honest snapshot onto the serialized record (feature 013, FR-021). Local
// (ollama) inference accrues a real $0; a paid backend/model with no reviewed
// price is disclosed as unpriced, never counted as a false $0 cost.
func accrueBudget(rec *RunRecord, model string, res agent.Result) {
	if rec.budget == nil {
		rec.budget = &BudgetAccount{}
	}
	rec.budget.Accrue(rec.Backend, model, res)
	spent, priced, unpriced := rec.budget.Snapshot()
	rec.BudgetSpentUSD = spent
	rec.BudgetPriced = priced
	rec.BudgetUnpricedCalls = unpriced
	rec.BudgetDisclosure = budgetDisclosure(rec.MaxBudgetUSD, spent, priced, unpriced)
}

// addUsage accumulates run-level usage. `calls` counts real model calls: one per
// agent turn PLUS each repair call (FR-011, C-U1) — never one per agent.
func addUsage(rec *RunRecord, res agent.Result) {
	pt, _ := rec.Usage["prompt_tokens"].(int)
	ct, _ := rec.Usage["completion_tokens"].(int)
	calls, _ := rec.Usage["calls"].(int)
	repairs, _ := rec.Usage["repairs"].(int)
	rec.Usage["prompt_tokens"] = pt + res.Usage.PromptTokens
	rec.Usage["completion_tokens"] = ct + res.Usage.CompletionTokens
	rec.Usage["calls"] = calls + res.Turns + res.RepairAttempts
	rec.Usage["repairs"] = repairs + res.RepairAttempts
}

// usageTiles returns the cumulative prompt/completion token totals for live
// progress tiles (feature 007, T008).
func usageTiles(rec *RunRecord) (int, int) {
	pt, _ := rec.Usage["prompt_tokens"].(int)
	ct, _ := rec.Usage["completion_tokens"].(int)
	return pt, ct
}

func agentsIncomplete(rec *RunRecord) int {
	n := 0
	for _, a := range rec.Agents {
		if a.StoppedReason != agent.StopComplete && a.StoppedReason != "" {
			n++
		}
	}
	return n
}

// markPhaseFailed records a per-phase unrecoverable endpoint failure as coverage
// degradation (feature 004, FR-006/008): the just-recorded agent is marked
// endpoint_failure and a degraded reason naming the phase + short error is
// captured for finalize. It never sets rec.Aborted (reserved for cancellation).
func markPhaseFailed(rec *RunRecord, key string, err error) {
	if n := len(rec.Agents); n > 0 {
		rec.Agents[n-1].StoppedReason = agent.StopEndpointFailure
	}
	rec.EndpointFailures = append(rec.EndpointFailures,
		fmt.Sprintf("phase %s endpoint failure: %s", key, shortErr(err)))
}

func shortErr(err error) string {
	s := err.Error()
	if len(s) > 200 {
		return s[:200] + "…"
	}
	return s
}

// manifestMode returns the executed hunt mode for the manifest, defaulting to
// "split" (feature 005, FR-017).
func manifestMode(m string) string {
	if m == "" {
		return "split"
	}
	return m
}

// unresolvedCount reads the verification reconciliation's unresolved count (0 if
// verification did not run), used to summarize verification health as ONE coverage
// reason instead of one per candidate session.
func unresolvedCount(resultsDir string) int {
	b, err := os.ReadFile(filepath.Join(resultsDir, "verification_reconciliation.json"))
	if err != nil {
		return 0
	}
	var r struct {
		Counts map[string]int `json:"counts"`
	}
	if json.Unmarshal(b, &r) != nil {
		return 0
	}
	return r.Counts["unresolved"]
}

// dedupStrings collapses duplicate coverage reasons while preserving order.
// withoutPhase returns the phase list with the given key removed (feature 013,
// FR-019: exclude a deliberately-disabled optional phase from a denominator).
func withoutPhase(in []string, key string) []string {
	out := make([]string, 0, len(in))
	for _, p := range in {
		if p != key {
			out = append(out, p)
		}
	}
	return out
}

func dedupStrings(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

var reSlug = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

func safeSlug(s string) string {
	s = reSlug.ReplaceAllString(strings.ToLower(s), "-")
	return strings.Trim(s, "-")
}

// deliverableValid reports whether a phase deliverable exists and is non-empty.
// A directory deliverable (results/) is valid if it holds any non-empty file.
func deliverableValid(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	if info.IsDir() {
		entries, _ := os.ReadDir(path)
		for _, e := range entries {
			if fi, err := e.Info(); err == nil && !e.IsDir() && fi.Size() > 0 {
				return true
			}
		}
		return false
	}
	return info.Size() > 0
}

// --- resume state ---

func statePath(resultsDir string) string { return filepath.Join(resultsDir, stateFile) }

func loadState(resultsDir string) map[string]bool {
	out := map[string]bool{}
	b, err := os.ReadFile(statePath(resultsDir))
	if err != nil {
		return out
	}
	var s struct {
		Completed []string `json:"completed"`
	}
	if json.Unmarshal(b, &s) != nil {
		return out
	}
	for _, k := range s.Completed {
		out[k] = true
	}
	return out
}

func saveState(resultsDir string, completed map[string]bool) {
	var keys []string
	for _, ph := range phases.PHASES {
		if completed[ph.Key] {
			keys = append(keys, ph.Key)
		}
	}
	b, _ := json.MarshalIndent(struct {
		Completed []string `json:"completed"`
	}{keys}, "", "  ")
	_ = os.WriteFile(statePath(resultsDir), b, 0o644)
}

// --- findings collection + corpus ---

// collectFindings reads the authoritative findings source: the verification
// output (phase2b_output.md). It NEVER falls back to the raw hunt output.
//
// FR-C1 (fail-closed, no resurrection): a valid zero-survivor verification (all
// candidates rejected → no finding blocks in phase2b_output.md) MUST publish zero
// supported findings, not resurrect the raw results/*.md hunt candidates. An
// absent, empty, or unparseable phase2b_output.md therefore yields NO findings
// (FR-C2, fail-closed) — a missing/broken verification never implies confirmation.
//
// NOTE (US3): the full evidence-gated promotion (structured verification decisions)
// replaces the parseable-2b promotion below; until US3 lands, a parseable 2b still
// sets fromConfirmed, but the raw-resurrection and malformed→confirmed holes are
// closed here.
func collectFindings(resultsDir string) ([]consolidate.Finding, bool) {
	p2b := filepath.Join(resultsDir, "phase2b_output.md")
	b, err := os.ReadFile(p2b)
	if err != nil || len(b) == 0 {
		return nil, false
	}
	if f := consolidate.ExtractFindings(string(b), "phase2b_output.md"); f != nil {
		return f, true
	}
	return nil, false
}

// artifactManifestPresent reports whether a real (non-empty) artifact_manifest.json
// already exists (FR-C3): a placeholder `[]` or missing file returns false so the
// engine may (re)write the placeholder; a manifest with entries returns true so
// finalize/regeneration preserve it.
func artifactManifestPresent(resultsDir string) bool {
	b, err := os.ReadFile(filepath.Join(resultsDir, "artifact_manifest.json"))
	if err != nil {
		return false
	}
	var arr []json.RawMessage
	if json.Unmarshal(b, &arr) != nil {
		// Unparseable but present: preserve it rather than risk clobbering real data.
		return len(b) > 0
	}
	return len(arr) > 0
}

func containsStr(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

// readHuntOutput concatenates only the per-agent hunt output under results/*.md
// (the actual-hunting evidence for coverage dispositions — FR-008), excluding
// threat_model.md / phase*_output.md and other results-dir text.
func readHuntOutput(resultsDir string) string {
	var b strings.Builder
	sub := filepath.Join(resultsDir, "results")
	entries, _ := os.ReadDir(sub)
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".md") {
			continue
		}
		if data, err := os.ReadFile(filepath.Join(sub, e.Name())); err == nil {
			b.Write(data)
			b.WriteByte('\n')
		}
	}
	return b.String()
}

func readCorpus(resultsDir string) string {
	var b strings.Builder
	filepath.WalkDir(resultsDir, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(p, ".md") {
			return nil
		}
		if data, err := os.ReadFile(p); err == nil {
			b.Write(data)
			b.WriteByte('\n')
		}
		return nil
	})
	return b.String()
}

var reFileTok = regexp.MustCompile(`([\w./+\-]+\.[A-Za-z0-9]{1,6})`)

func firstFileToken(s string) string {
	return reFileTok.FindString(s)
}

func countNonDup(findings []consolidate.Finding) int {
	n := 0
	for _, f := range findings {
		if f.DuplicateOf == nil {
			n++
		}
	}
	return n
}

// countPySource counts first-party source files across the recognized baseline
// languages (feature 012, T011) — generalized from the former Python-only counter
// so non-Python scans get equivalent source-size degradation reporting. The name
// is retained for its callers; it is no longer Python-specific.
func countPySource(repo string) int {
	n := 0
	filepath.WalkDir(repo, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if tools.SkipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if _, ok := recognize.LanguageFor(p); ok {
			n++
		}
		return nil
	})
	return n
}

func writeJSON(path string, v any) (string, error) {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return "", err
	}
	return path, os.WriteFile(path, b, 0o644)
}

// splitLocation parses a "file:line" finding location into its parts (feature 012).
// Returns (file, 0) when no numeric line suffix is present.
func splitLocation(loc string) (string, int) {
	i := strings.LastIndexByte(loc, ':')
	if i < 0 {
		return loc, 0
	}
	n := 0
	for _, c := range loc[i+1:] {
		if c < '0' || c > '9' {
			return loc, 0
		}
		n = n*10 + int(c-'0')
	}
	return loc[:i], n
}
