// Package server is the HTTP engine: REST + SSE + static UI, all served from one
// process over the same execute_scan the CLI uses (FR-012). Security posture
// (constitution Safety & Technical Constraints; FR-024): no auth, loopback bind
// by default (non-loopback needs an explicit unsafe opt-in), allow-listed scan
// roots checked on repo and out, and artifact reads confined to the owning dir.
package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"vhlocal/internal/client"
	"vhlocal/internal/config"
	"vhlocal/internal/engine"
	"vhlocal/internal/jobs"
	"vhlocal/internal/phases"
)

// Config configures the engine server.
type Config struct {
	Host       string
	Port       int
	SkillDir   string
	ReportsDir string
	OllamaHost string
	AllowRoots []string
	StatePath  string
	UnsafeBind bool
	Version    string
	WebFS      fs.FS // embedded UI (may be nil)
	SkillFS    fs.FS // embedded skill (may be nil)
}

// Server holds engine state.
type Server struct {
	cfg   Config
	store *jobs.Store
	// in-memory OpenRouter key (never persisted; FR-009a)
	orKey string
	// assistProvider, when non-nil, is used for contextual-AI calls instead of
	// building one from the request. Prod leaves it nil (a provider is built per
	// request); tests inject a fake so the assist path runs fully offline (feature
	// 010, US5). It is never a silent fallback — when nil and no request provider
	// can be built, the call fails explicitly.
	assistProvider client.Provider
}

// New builds the server and its job store (whose worker runs execute_scan).
func New(cfg Config) (*Server, error) {
	if cfg.OllamaHost == "" {
		cfg.OllamaHost = config.OllamaHost()
	}
	if cfg.ReportsDir == "" {
		cfg.ReportsDir = config.DefaultReportsDir()
	}
	if cfg.StatePath == "" {
		cfg.StatePath = config.StatePath()
	}
	if len(cfg.AllowRoots) == 0 {
		if h, err := homeDir(); err == nil {
			cfg.AllowRoots = []string{h}
		}
	}
	s := &Server{cfg: cfg}
	store, err := jobs.NewStore(cfg.StatePath, s.runScan)
	if err != nil {
		return nil, err
	}
	s.store = store
	// Feature 014 (FR-001): early results-dir binding stays confined to the allowed
	// roots or the reports directory.
	store.SetBindFilter(func(dir string) bool {
		return s.allowRootOK(dir) || strings.HasPrefix(dir, cfg.ReportsDir)
	})
	return s, nil
}

// Serve binds and serves. A non-loopback host requires UnsafeBind.
func (s *Server) Serve() error {
	addr := fmt.Sprintf("%s:%d", s.cfg.Host, s.cfg.Port)
	if !isLoopback(s.cfg.Host) && !s.cfg.UnsafeBind {
		return fmt.Errorf("refusing to bind non-loopback host %q without --unsafe-bind (the server has no authentication)", s.cfg.Host)
	}
	srv := &http.Server{Addr: addr, Handler: s.Handler()}
	return srv.ListenAndServe()
}

func homeDir() (string, error) { return osUserHomeDir() }

func isLoopback(host string) bool {
	if host == "" || host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// runScan is the jobs.RunFunc: build spec/providers/skill from the job spec and
// run execute_scan, forwarding engine events to the job's event ring.
func (s *Server) runScan(ctx context.Context, spec map[string]any, emit func(map[string]any)) (string, error) {
	sc, prov, skill, err := s.buildScan(spec)
	if err != nil {
		return "", err
	}
	// Feature 014 (FR-006): tag this run's log lines with the job id so the Log
	// endpoint's tag filter finds exactly this scan's slice.
	sc.LogTag = jobs.IDFromContext(ctx)
	e := engine.Emit(func(event string, payload map[string]any) {
		if payload == nil {
			payload = map[string]any{}
		}
		payload["type"] = event
		emit(payload)
	})
	rec, err := engine.Execute(ctx, sc, prov, skill, e)
	if err != nil {
		return sc.ResultsDir, err
	}
	if rec.Aborted != "" {
		return sc.ResultsDir, fmt.Errorf("%s", rec.Aborted)
	}
	return sc.ResultsDir, nil
}

var reNonAlnum = regexp.MustCompile(`[^a-z0-9]+`)

func modelTag(m string) string { return reNonAlnum.ReplaceAllString(strings.ToLower(m), "") }

func (s *Server) buildScan(spec map[string]any) (engine.ScanSpec, engine.Providers, engine.SkillSource, error) {
	repo := str(spec["repo"])
	if repo == "" {
		return engine.ScanSpec{}, engine.Providers{}, nil, fmt.Errorf("repo is required")
	}
	repoAbs, _ := filepath.Abs(repo)
	backend := strOr(spec["backend"], "ollama")
	host := str(spec["host"])
	if host == "" {
		switch backend {
		case "openai":
			host = config.OpenAIHost()
		case "openrouter":
			host = config.OpenRouterHost
		default:
			host = s.cfg.OllamaHost
		}
	}
	model := strOr(spec["model"], config.DefaultModel)
	prov, err := s.provider(backend, host)
	if err != nil {
		return engine.ScanSpec{}, engine.Providers{}, nil, err
	}
	phaseList, err := phases.SelectPhases(strOr(spec["phases"], "all"))
	if err != nil {
		return engine.ScanSpec{}, engine.Providers{}, nil, err
	}
	stamp := time.Now().Format("2006-01-02-150405")
	resultsDir := str(spec["out"])
	if resultsDir == "" {
		name := fmt.Sprintf("%s_VULNHUNT_RESULTS_%s_%s", filepath.Base(repoAbs), modelTag(model), stamp)
		resultsDir = filepath.Join(s.cfg.ReportsDir, name)
	}
	resultsDir, _ = filepath.Abs(resultsDir)

	skillDir := s.cfg.SkillDir
	if d := str(spec["skill_dir"]); d != "" {
		skillDir = d
	}
	var skill engine.SkillSource = embeddedSkill{fsys: s.cfg.SkillFS}
	if skillDir != "" {
		skill = engine.DirSkill{Dir: skillDir}
	}

	sc := engine.ScanSpec{
		Repo: repoAbs, ResultsDir: resultsDir, SkillDir: skillDir, Model: model,
		Host: host, Backend: backend, NumCtx: intOr(spec["num_ctx"], config.DefaultNumCtx),
		Phases: phaseList, MaxPartitions: intOr(spec["max_partitions"], 8),
		VerifyModel: str(spec["verify_model"]), ReconModel: str(spec["recon_model"]),
		ReproduceModel: str(spec["reproduce_model"]), MaxOutputTokens: intOr(spec["max_output_tokens"], config.DefaultMaxOutTokens),
		ReasoningEffort: str(spec["reasoning_effort"]), QualityStrictness: strOr(spec["quality_strictness"], "balanced"),
		ThreatModel: boolOr(spec["threat_model"], false), Ledger: boolOr(spec["ledger"], false),
		Redact: boolOr(spec["redact"], false), Remediate: boolOr(spec["remediate"], false),
		Resume: boolOr(spec["resume"], false), HuntSamples: intOr(spec["hunt_samples"], 1),
		IaCLens: boolOr(spec["iac_lens"], true), EngineVersion: s.cfg.Version, ScanTag: stamp,
		MaxBudgetUSD: floatOr(spec["max_budget_usd"], 0), AppName: str(spec["app_name"]),
		// Feature 013 (FR-018): populate the previously-dropped fields. Temperature is
		// a pointer so 0 is distinct from unset and is never replaced by a default.
		Temperature: floatPtr(spec["temperature"]), Phase2Mode: str(spec["phase2_mode"]),
		// Feature 013 (FR-017): per-role provider overrides carried into the spec so the
		// effective configuration records them and the engine builds the right provider.
		VerifyBackend: str(spec["verify_backend"]), VerifyHost: str(spec["verify_host"]),
		ReconBackend: str(spec["recon_backend"]), ReconHost: str(spec["recon_host"]),
		ReproduceBackend: str(spec["reproduce_backend"]), ReproduceHost: str(spec["reproduce_host"]),
		// Feature 013 (FR-012/013): coverage enforcement (nil = default enabled) and
		// bounded concurrency (default 1 = serial).
		EnforceCoverage: boolPtr(spec["enforce_coverage"]), Concurrency: intOr(spec["concurrency"], 1),
		// Feature 013 (FR-008/010): route + prior-report seeding (both implemented).
		SeedRoutes: boolOr(spec["seed_routes"], false), SeedPrior: boolOr(spec["seed_prior"], false),
		DiagnosticCapture: strOr(spec["diagnostic_capture"], "bounded"),
		ReportsDir:        s.cfg.ReportsDir,
	}
	// Feature 013 (FR-017): build per-role providers so a per-role backend/host
	// actually reaches that role's calls. A blank role backend AND host inherits the
	// Hunt provider (documented). No endpoint beyond operator configuration; no
	// silent switch. An invalid role provider fails the launch explicitly.
	providers := engine.Providers{Hunt: prov}
	var perr error
	if providers.Verify, perr = s.roleProvider(spec, "verify", backend); perr != nil {
		return engine.ScanSpec{}, engine.Providers{}, nil, perr
	}
	if providers.Recon, perr = s.roleProvider(spec, "recon", backend); perr != nil {
		return engine.ScanSpec{}, engine.Providers{}, nil, perr
	}
	if providers.Reproduce, perr = s.roleProvider(spec, "reproduce", backend); perr != nil {
		return engine.ScanSpec{}, engine.Providers{}, nil, perr
	}
	// Feature 013 (FR-005): the requested-vs-applied effective config, secrets removed.
	sc.EffectiveConfig = engine.BuildEffectiveConfig(spec, sc)
	return sc, providers, skill, nil
}

// roleProvider builds a provider for a per-role backend/host override. It returns
// (nil, nil) when neither is set so the role inherits the Hunt provider (FR-017).
// A blank per-role host resolves to that backend's default host.
func (s *Server) roleProvider(spec map[string]any, role, defBackend string) (client.Provider, error) {
	rb := str(spec[role+"_backend"])
	rh := str(spec[role+"_host"])
	if rb == "" && rh == "" {
		return nil, nil // inherit Hunt (documented)
	}
	backend := rb
	if backend == "" {
		backend = defBackend
	}
	host := rh
	if host == "" {
		switch backend {
		case "openai":
			host = config.OpenAIHost()
		case "openrouter":
			host = config.OpenRouterHost
		default:
			host = s.cfg.OllamaHost
		}
	}
	return s.provider(backend, host)
}

// boolPtr returns a *bool only when the key was present with a bool value, so an
// explicit false is distinct from an omitted value (FR-003). Used for
// enforce_coverage, where nil means the default (enabled).
func boolPtr(v any) *bool {
	if b, ok := v.(bool); ok {
		return &b
	}
	return nil
}

// floatPtr returns a *float64 only when the key was present with a numeric value,
// so an explicit 0 is distinct from an omitted value (FR-003).
func floatPtr(v any) *float64 {
	switch n := v.(type) {
	case float64:
		return &n
	case int:
		f := float64(n)
		return &f
	default:
		return nil
	}
}

func (s *Server) provider(backend, host string) (client.Provider, error) {
	switch backend {
	case "ollama":
		return client.NewOllama(host), nil
	case "openai":
		return client.NewOpenAI(client.BackendOpenAI, host, config.OpenAIKeyFromEnv()), nil
	case "openrouter":
		key := s.orKey
		if key == "" {
			key = config.OpenRouterKeyFromEnv()
		}
		if key == "" {
			return nil, fmt.Errorf("openrouter backend needs an API key")
		}
		return client.NewOpenAI(client.BackendOpenRouter, "", key), nil
	default:
		return nil, fmt.Errorf("unknown backend %q", backend)
	}
}

// --- HTTP helpers ---

func writeJSON(w http.ResponseWriter, status int, obj any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(obj)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]any{"error": msg})
}

func body(r *http.Request) map[string]any {
	m := map[string]any{}
	_ = json.NewDecoder(r.Body).Decode(&m)
	return m
}

// allowRootOK reports whether target is inside an allow-listed scan root.
func (s *Server) allowRootOK(target string) bool {
	abs, err := filepath.Abs(target)
	if err != nil {
		return false
	}
	if resolved, err := filepath.EvalSymlinks(abs); err == nil {
		abs = resolved
	}
	for _, root := range s.cfg.AllowRoots {
		rabs, _ := filepath.Abs(root)
		if within(abs, rabs) {
			return true
		}
	}
	return false
}

func within(target, root string) bool {
	if target == root {
		return true
	}
	rel, err := filepath.Rel(root, target)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func str(v any) string {
	s, _ := v.(string)
	return s
}
func strOr(v any, def string) string {
	if s, ok := v.(string); ok && s != "" {
		return s
	}
	return def
}
func intOr(v any, def int) int {
	switch n := v.(type) {
	case float64:
		return int(n)
	case int:
		return n
	}
	return def
}
func boolOr(v any, def bool) bool {
	if b, ok := v.(bool); ok {
		return b
	}
	return def
}
func floatOr(v any, def float64) float64 {
	switch n := v.(type) {
	case float64:
		return n
	case int:
		return float64(n)
	}
	return def
}

// embeddedSkill serves the methodology from an embedded FS (may be nil).
type embeddedSkill struct{ fsys fs.FS }

func (e embeddedSkill) Preamble() string {
	if e.fsys == nil {
		return ""
	}
	b, err := fs.ReadFile(e.fsys, "skill/SKILL.md")
	if err != nil {
		return ""
	}
	return phases.LoadPreamble(string(b))
}
func (e embeddedSkill) Prompt(file string) (string, error) {
	if e.fsys == nil {
		return "", fmt.Errorf("no embedded skill")
	}
	b, err := fs.ReadFile(e.fsys, "skill/phases/"+file)
	return string(b), err
}
