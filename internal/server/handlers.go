package server

import (
	"context"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"vhlocal/internal/activity"
	"vhlocal/internal/apps"
	"vhlocal/internal/client"
	"vhlocal/internal/config"
	"vhlocal/internal/logsetup"
	"vhlocal/internal/membank"
	"vhlocal/internal/phases"
	"vhlocal/internal/profiles"
	"vhlocal/internal/reports"
)

func osUserHomeDir() (string, error) { return os.UserHomeDir() }

// Handler builds the router (Go 1.22 method+wildcard patterns).
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	// Static UI.
	mux.HandleFunc("GET /", s.handleStatic)

	// Config / discovery.
	mux.HandleFunc("GET /api/config", s.handleConfig)
	mux.HandleFunc("GET /api/models", s.handleModels)
	mux.HandleFunc("GET /api/profiles", s.handleProfiles)
	mux.HandleFunc("GET /api/stats", s.handleStats)

	// Scans.
	mux.HandleFunc("POST /api/scans", s.handleCreateScan)
	mux.HandleFunc("GET /api/scans", s.handleListScans)
	mux.HandleFunc("GET /api/scans/{id}", s.handleScan)
	mux.HandleFunc("GET /api/scans/{id}/events", s.handleEvents)
	mux.HandleFunc("GET /api/scans/{id}/log", s.handleScanLog)
	mux.HandleFunc("GET /api/scans/{id}/prompts", s.handleScanPrompts) // feature 014
	mux.HandleFunc("GET /api/scans/{id}/artifacts", s.handleScanArtifacts)
	mux.HandleFunc("GET /api/scans/{id}/file", s.handleScanFile)
	mux.HandleFunc("POST /api/scans/{id}/cancel", s.handleCancel)
	mux.HandleFunc("POST /api/openrouter-key", s.handleOpenRouterKey)

	// Reports.
	mux.HandleFunc("GET /api/reports", s.handleReports)
	mux.HandleFunc("GET /api/reports/{id}/files", s.handleReportFiles)
	mux.HandleFunc("GET /api/reports/{id}/file", s.handleReportFile)
	mux.HandleFunc("DELETE /api/reports/{id}", s.handleDeleteReport)

	// Applications.
	mux.HandleFunc("GET /api/applications", s.handleApplications)
	// Feature 014 (FR-028): literal segment wins over {slug} in the Go 1.22 mux.
	mux.HandleFunc("GET /api/applications/cleanup", s.handleCleanupPreview)
	mux.HandleFunc("POST /api/applications/cleanup", s.handleCleanupApply)
	mux.HandleFunc("GET /api/applications/{slug}", s.handleApplication)
	mux.HandleFunc("POST /api/applications/{slug}", s.handleRenameApp)
	mux.HandleFunc("DELETE /api/applications/{slug}", s.handleForgetApp)

	// Ledgers.
	mux.HandleFunc("GET /api/ledgers", s.handleLedgers)
	mux.HandleFunc("GET /api/ledgers/{slug}", s.handleLedger)
	mux.HandleFunc("DELETE /api/ledgers/{slug}", s.handleClearLedger)
	mux.HandleFunc("DELETE /api/ledgers/{slug}/finding", s.handleRemoveFinding)

	// Activity / log.
	mux.HandleFunc("GET /api/activity", s.handleActivity)
	mux.HandleFunc("GET /api/log", s.handleLog)

	// Analyst workspace — findings queue, review decisions, saved views (feature 010).
	mux.HandleFunc("GET /api/findings", s.handleFindings)
	mux.HandleFunc("GET /api/findings/{occ}", s.handleFinding)
	mux.HandleFunc("GET /api/findings/{occ}/evidence", s.handleEvidence)
	mux.HandleFunc("GET /api/findings/{occ}/comparison", s.handleComparison)
	mux.HandleFunc("GET /api/findings/{stable}/review", s.handleGetReview)
	mux.HandleFunc("POST /api/findings/{stable}/review", s.handleSubmitReview)
	mux.HandleFunc("GET /api/scans/{id}/status", s.handleScanStatus)
	mux.HandleFunc("GET /api/scans/{id}/manifest", s.handleScanManifest)
	mux.HandleFunc("GET /api/attention", s.handleAttention)
	mux.HandleFunc("POST /api/findings/{occ}/assist", s.handleAssist)
	mux.HandleFunc("GET /api/findings/{occ}/assist", s.handleAssistGet)
	mux.HandleFunc("POST /api/findings/{occ}/assist/cancel", s.handleAssistCancel)
	mux.HandleFunc("GET /api/views", s.handleListViews)
	mux.HandleFunc("POST /api/views", s.handleSaveView)
	mux.HandleFunc("DELETE /api/views/{id}", s.handleDeleteView)

	return mux
}

func (s *Server) handleConfig(w http.ResponseWriter, r *http.Request) {
	var phaseDefs []map[string]string
	for _, p := range phases.PHASES {
		phaseDefs = append(phaseDefs, map[string]string{"key": p.Key, "title": p.Title})
	}
	writeJSON(w, 200, map[string]any{
		"skill_dir": s.cfg.SkillDir, "reports_dir": s.cfg.ReportsDir,
		"allow_roots": s.cfg.AllowRoots, "phases": phaseDefs,
		// Feature 014 (SC-012): build identity so a validation run can record exactly
		// which binary + embedded UI it exercised.
		"build": s.buildIdentity(),
		"defaults": map[string]any{
			"model": config.DefaultModel, "num_ctx": config.DefaultNumCtx,
			"ollama_host": s.cfg.OllamaHost, "openai_host": config.OpenAIHost(),
			"openrouter_host":    config.OpenRouterHost,
			"openrouter_key_set": s.orKey != "" || config.OpenRouterKeyFromEnv() != "",
		},
	})
}

func (s *Server) handleModels(w http.ResponseWriter, r *http.Request) {
	backend := strOr(r.URL.Query().Get("backend"), "ollama")
	host := r.URL.Query().Get("host")
	if host == "" {
		host = s.cfg.OllamaHost
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	switch backend {
	case "ollama":
		models, err := client.NewOllama(host).Models(ctx)
		if err != nil {
			writeErr(w, 502, "cannot reach Ollama at "+host+": "+err.Error())
			return
		}
		out := make([]map[string]any, 0, len(models))
		for _, m := range models {
			out = append(out, map[string]any{"name": m.Name, "size": m.Size, "family": m.Family})
		}
		writeJSON(w, 200, map[string]any{"models": out})
	default:
		// openai/openrouter model listing not yet ported; return empty set.
		writeJSON(w, 200, map[string]any{"models": []any{}})
	}
}

func (s *Server) handleProfiles(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{"profiles": profiles.List()})
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	rs, _ := reports.Index(s.cfg.ReportsDir)
	// Aggregate ONLY from recorded per-run data (feature 008, FR-018): tokens and
	// duration come from scan_meta.json via reports.Report. Averages are computed
	// over the runs that actually recorded the datum (FR-005); zero-safe (FR-006).
	type modelAgg struct{ scans, tokens, findings int }
	byModel := map[string]*modelAgg{}
	totalFindings, totalPrompt, totalCompletion := 0, 0, 0
	withUsage, withDuration := 0, 0
	var totalSeconds float64
	for _, rep := range rs {
		totalFindings += rep.Findings
		totalPrompt += rep.PromptTokens
		totalCompletion += rep.CompletionTokens
		if rep.HasUsage {
			withUsage++
		}
		if rep.DurationSeconds > 0 {
			withDuration++
			totalSeconds += rep.DurationSeconds
		}
		m := rep.Model
		if m == "" {
			m = "unknown"
		}
		if byModel[m] == nil {
			byModel[m] = &modelAgg{}
		}
		byModel[m].scans++
		byModel[m].findings += rep.Findings
		byModel[m].tokens += rep.PromptTokens + rep.CompletionTokens
	}
	totalTokens := totalPrompt + totalCompletion

	bm := map[string]any{}
	for k, v := range byModel {
		bm[k] = map[string]any{"scans": v.scans, "tokens": v.tokens, "findings": v.findings}
	}
	stats := map[string]any{
		"scans":                 len(rs),
		"findings":              totalFindings,
		"prompt_tokens":         totalPrompt,
		"completion_tokens":     totalCompletion,
		"total_tokens":          totalTokens,
		"with_usage":            withUsage,
		"total_seconds":         totalSeconds,
		"avg_findings_per_scan": roundDiv(totalFindings, len(rs)), // whole number (FR-004)
		"avg_tokens_per_scan":   roundDiv(totalTokens, withUsage), // over runs with usage (FR-005)
		"avg_seconds_per_scan":  avgFloat(totalSeconds, withDuration),
		"by_model":              bm,
	}
	writeJSON(w, 200, stats)
}

// roundDiv is a zero-safe rounded integer division (FR-004/006).
func roundDiv(total, n int) int {
	if n <= 0 {
		return 0
	}
	return int(math.Round(float64(total) / float64(n)))
}

// avgFloat is a zero-safe float average (FR-006).
func avgFloat(total float64, n int) float64 {
	if n <= 0 {
		return 0
	}
	return total / float64(n)
}

// supportedScanOptions is the allowlist of scan-request keys, derived from the one
// authoritative option contract (feature 013, FR-001: internal/config.Registry) so
// the validator, buildScan, CLI, and profiles cannot diverge. An option outside it
// is rejected explicitly rather than silently ignored.
var supportedScanOptions = config.ScanOptionKeys()

// validateScanOptions rejects unsupported keys and out-of-range/enum/type values so
// no option is silently ignored (CB-19). It delegates to the shared option contract
// (config.ValidateScanOptions), which checks keys in sorted order so multi-field
// errors are deterministic and field-specific (feature 013, FR-003/004).
func validateScanOptions(b map[string]any) string {
	return config.ValidateScanOptions(b)
}

func (s *Server) handleCreateScan(w http.ResponseWriter, r *http.Request) {
	b := body(r)
	if why := validateScanOptions(b); why != "" {
		writeErr(w, 400, why)
		return
	}
	repo := str(b["repo"])
	if strings.TrimSpace(repo) == "" {
		writeErr(w, 400, "repo is required")
		return
	}
	repoAbs, _ := filepath.Abs(repo)
	if resolved, err := filepath.EvalSymlinks(repoAbs); err == nil {
		repoAbs = resolved
	}
	if fi, err := os.Stat(repoAbs); err != nil || !fi.IsDir() {
		writeErr(w, 400, "repo is not a directory: "+repo)
		return
	}
	if !s.allowRootOK(repoAbs) {
		writeErr(w, 403, "repo is outside the allowed roots")
		return
	}
	if out := str(b["out"]); out != "" && !s.allowRootOK(out) {
		writeErr(w, 403, "out is outside the allowed roots")
		return
	}
	if _, err := phases.SelectPhases(strOr(b["phases"], "all")); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if intOr(b["num_ctx"], config.DefaultNumCtx) <= 0 {
		writeErr(w, 400, "num_ctx must be positive")
		return
	}
	if intOr(b["max_partitions"], 8) <= 0 {
		writeErr(w, 400, "max_partitions must be positive")
		return
	}
	b["repo"] = repoAbs
	b["app_slug"] = apps.SlugFor(repoAbs)
	if str(b["app_name"]) == "" {
		b["app_name"] = apps.SummaryFor(repoAbs, s.cfg.ReportsDir).Name
	}
	id := s.store.Submit(b)
	if job, ok := s.store.Get(id); ok {
		writeJSON(w, 201, job)
		return
	}
	writeErr(w, 500, "could not create scan")
}

func (s *Server) handleListScans(w http.ResponseWriter, r *http.Request) {
	list, busy := s.store.List()
	for i := range list {
		list[i] = enrichScan(list[i]) // add truthful engine axes + phase_outcomes (US3)
	}
	writeJSON(w, 200, map[string]any{"jobs": list, "busy": busy})
}

func (s *Server) handleScan(w http.ResponseWriter, r *http.Request) {
	if job, ok := s.store.Get(r.PathValue("id")); ok {
		writeJSON(w, 200, enrichScan(job))
		return
	}
	writeErr(w, 404, "no such job")
}

func (s *Server) handleCancel(w http.ResponseWriter, r *http.Request) {
	if s.store.Cancel(r.PathValue("id")) {
		writeJSON(w, 200, map[string]any{"cancelled": true})
		return
	}
	writeErr(w, 409, "job not cancellable")
}

// handleScanArtifacts / handleScanFile / handleScanLog / handleScanPrompts live in
// evidence.go (feature 014): every evidence endpoint shares one state resolver.

func (s *Server) handleOpenRouterKey(w http.ResponseWriter, r *http.Request) {
	b := body(r)
	s.orKey = str(b["api_key"])
	writeJSON(w, 200, map[string]any{"key_set": s.orKey != ""})
}

func (s *Server) jobResultsDir(id string) string {
	job, ok := s.store.Get(id)
	if !ok {
		return ""
	}
	if rd, ok := job["results_dir"].(string); ok {
		return rd
	}
	return ""
}

// --- reports ---

func (s *Server) handleReports(w http.ResponseWriter, r *http.Request) {
	rs, _ := reports.Index(s.cfg.ReportsDir)
	writeJSON(w, 200, map[string]any{"reports_dir": s.cfg.ReportsDir, "reports": rs})
}

func (s *Server) resolveReport(id string) (string, bool) {
	if !reports.SanitizeID(id) {
		return "", false
	}
	rs, _ := reports.Index(s.cfg.ReportsDir)
	for _, rep := range rs {
		if rep.ID == id {
			return rep.Path, true
		}
	}
	return "", false
}

func (s *Server) handleReportFiles(w http.ResponseWriter, r *http.Request) {
	dir, ok := s.resolveReport(r.PathValue("id"))
	if !ok {
		writeErr(w, 404, "no such report")
		return
	}
	writeJSON(w, 200, listFiles(dir))
}

func (s *Server) handleReportFile(w http.ResponseWriter, r *http.Request) {
	dir, ok := s.resolveReport(r.PathValue("id"))
	if !ok {
		writeErr(w, 404, "no such report")
		return
	}
	serveConfined(w, dir, r.URL.Query().Get("path"))
}

func (s *Server) handleDeleteReport(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	dir, ok := s.resolveReport(id)
	if !ok {
		writeErr(w, 404, "no such report")
		return
	}
	root, _ := filepath.Abs(s.cfg.ReportsDir)
	if da, _ := filepath.Abs(dir); da == root {
		writeErr(w, 403, "refusing to delete the reports directory itself")
		return
	}
	if !within(mustAbs(dir), root) {
		writeErr(w, 403, "refusing to delete a report outside the reports directory ("+root+")")
		return
	}
	if err := os.RemoveAll(dir); err != nil {
		writeErr(w, 500, "delete failed: "+err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"deleted": id})
}

// --- applications ---

func (s *Server) handleApplications(w http.ResponseWriter, r *http.Request) {
	if repo := r.URL.Query().Get("repo"); repo != "" {
		slug := apps.SlugFor(repo)
		writeJSON(w, 200, map[string]any{"slug": slug, "application": apps.SummaryFor(repo, s.cfg.ReportsDir)})
		return
	}
	// Full aggregation: discovery union (registry ∪ reports ∪ ledgers) minus hidden,
	// each carrying the fields the UI renders (feature 007, FR-007..011).
	writeJSON(w, 200, map[string]any{"applications": apps.ListSummaries(s.cfg.ReportsDir)})
}

func (s *Server) handleApplication(w http.ResponseWriter, r *http.Request) {
	slug := r.PathValue("slug")
	if !apps.IsValidSlug(slug) {
		writeErr(w, 400, "bad application id")
		return
	}
	if d, ok := apps.BuildDetail(slug, s.cfg.ReportsDir); ok {
		writeJSON(w, 200, d)
		return
	}
	writeErr(w, 404, "no such application")
}

func (s *Server) handleRenameApp(w http.ResponseWriter, r *http.Request) {
	slug := r.PathValue("slug")
	if !apps.IsValidSlug(slug) {
		writeErr(w, 400, "bad application id")
		return
	}
	name := str(body(r)["name"])
	if strings.TrimSpace(name) == "" {
		writeErr(w, 400, "name is required")
		return
	}
	e, err := apps.SetName(slug, name, "")
	if err != nil {
		writeErr(w, 400, "could not name application")
		return
	}
	writeJSON(w, 200, e)
}

// handleCleanupPreview lists demonstrably synthetic registry entries (feature 014,
// FR-028). Read-only: nothing changes until POST echoes the preview token.
func (s *Server) handleCleanupPreview(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, apps.PreviewSynthetic(s.cfg.ReportsDir))
}

// handleCleanupApply removes exactly the previewed entries after backing the
// registry up; a missing/incorrect token is 400 and changes nothing.
func (s *Server) handleCleanupApply(w http.ResponseWriter, r *http.Request) {
	confirm := str(body(r)["confirm"])
	res, err := apps.Apply(s.cfg.ReportsDir, confirm)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, res)
}

func (s *Server) handleForgetApp(w http.ResponseWriter, r *http.Request) {
	slug := r.PathValue("slug")
	if !apps.IsValidSlug(slug) {
		writeErr(w, 400, "bad application id")
		return
	}
	_ = apps.Forget(slug)
	writeJSON(w, 200, map[string]any{"forgotten": slug})
}

// --- ledgers ---

func (s *Server) handleLedgers(w http.ResponseWriter, r *http.Request) {
	list, _ := membank.List()
	writeJSON(w, 200, map[string]any{"ledgers": list})
}

func (s *Server) handleLedger(w http.ResponseWriter, r *http.Request) {
	if d, ok := membank.LoadDetail(r.PathValue("slug")); ok {
		writeJSON(w, 200, d)
		return
	}
	writeErr(w, 404, "no such ledger")
}

func (s *Server) handleClearLedger(w http.ResponseWriter, r *http.Request) {
	slug := r.PathValue("slug")
	if !apps.IsValidSlug(slug) {
		writeErr(w, 400, "bad ledger id")
		return
	}
	path := filepath.Join(config.LedgerDir(), slug+".json")
	if _, err := os.Stat(path); err != nil {
		writeErr(w, 404, "no such ledger")
		return
	}
	_ = os.Remove(path)
	writeJSON(w, 200, map[string]any{"cleared": slug})
}

func (s *Server) handleRemoveFinding(w http.ResponseWriter, r *http.Request) {
	slug := r.PathValue("slug")
	if !apps.IsValidSlug(slug) {
		writeErr(w, 400, "bad ledger id")
		return
	}
	key := r.URL.Query().Get("key")
	if key == "" {
		writeErr(w, 400, "finding key is required")
		return
	}
	// minimal: not yet mutating individual entries — report not found for now.
	writeErr(w, 404, "no such finding")
}

// --- activity / log ---

func (s *Server) handleActivity(w http.ResponseWriter, r *http.Request) {
	limit := clamp(atoiDefault(r.URL.Query().Get("limit"), 200), 1, 2000)
	evs, _ := activity.New(config.ActivityFile()).Recent(limit, r.URL.Query().Get("type"), r.URL.Query().Get("scan"))
	writeJSON(w, 200, map[string]any{"events": evs})
}

func (s *Server) handleLog(w http.ResponseWriter, r *http.Request) {
	tail := clamp(atoiDefault(r.URL.Query().Get("tail"), 500), 1, 20000)
	level := logsetup.ParseLevel(r.URL.Query().Get("level"))
	text, _ := logsetup.ReadLog(config.LogFile(), tail, r.URL.Query().Get("scan"), level)
	writeJSON(w, 200, map[string]any{"text": text})
}

func atoiDefault(s string, def int) int {
	if n, err := strconv.Atoi(s); err == nil {
		return n
	}
	return def
}
func clamp(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}
func mustAbs(p string) string { a, _ := filepath.Abs(p); return a }
