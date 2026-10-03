package cli

import (
	"context"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	vhlocal "vhlocal"
	"vhlocal/internal/client"
	"vhlocal/internal/config"
	"vhlocal/internal/engine"
	"vhlocal/internal/phases"
	"vhlocal/internal/profiles"
)

func init() {
	register("run", "Run a scan", runCmd)
}

func runCmd(args []string) int {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	var (
		repo        = fs.String("repo", "", "Target repository to scan (required)")
		backend     = fs.String("backend", "ollama", "Inference backend: ollama|openai|openrouter")
		out         = fs.String("out", "", "Exact results directory (overrides --reports-dir)")
		reportsDir  = fs.String("reports-dir", config.DefaultReportsDir(), "Where reports are written")
		model       = fs.String("model", config.DefaultModel, "Hunt / default model")
		host        = fs.String("host", "", "Endpoint for the hunt model")
		skillDir    = fs.String("skill-dir", "", "vulnhunt skill dir (default: bundled/embedded)")
		phasesFlag  = fs.String("phases", "all", "Comma-separated phase keys: 1,1t,2,2b,3,3d,4")
		numCtx      = fs.Int("num-ctx", config.DefaultNumCtx, "Context window")
		maxParts    = fs.Int("max-partitions", 8, "Caps Phase 2 fan-out")
		verifyModel = fs.String("verify-model", "", "Model for Phase 2b only")
		reconModel  = fs.String("recon-model", "", "Model for Phase 1")
		reproModel  = fs.String("reproduce-model", "", "Model for Phases 3/3d/4")
		maxOut      = fs.Int("max-output-tokens", config.DefaultMaxOutTokens, "Cap completion length; 0=uncapped")
		reasoning   = fs.String("reasoning-effort", "", "low|medium|high")
		strictness  = fs.String("quality-strictness", "balanced", "lenient|balanced|strict")
		phase2Mode  = fs.String("phase2-mode", "split", "Hunt dispatch: split (per class INJ/NAV/LOG) | combined")
		huntSamples = fs.Int("hunt-samples", 1, "Run each hunt agent N times (1-5)")
		threatModel = fs.Bool("threat-model", false, "Run Phase 1t PASTA + SBOM")
		ledger      = fs.Bool("ledger", false, "Merge findings into the per-target ledger")
		redact      = fs.Bool("redact", false, "Mask secrets/PII in artifacts")
		remediate   = fs.Bool("remediate", false, "Write per-finding remediation DTOs")
		iacLens     = fs.Bool("iac-lens", true, "IaC/CI-CD lens")
		resume      = fs.Bool("resume", false, "Skip completed phases")
		profile     = fs.String("profile", "", "Apply a config profile (quick/thorough/share/benchmark or user)")
		// Feature 013: previously-missing CLI flags for cross-surface parity (FR-002).
		concurrency = fs.Int("concurrency", 1, "Bounded parallel hunt units (1-8)")
		seedRoutes  = fs.Bool("seed-routes", false, "Seed Phase-1 recon with the deterministic entry-point inventory")
		seedPrior   = fs.Bool("seed-prior", false, "Seed Phase-1 recon with an eligible prior report's findings (leads)")
		enforceCov  = fs.Bool("enforce-coverage", true, "Coverage-driven hunt-plan augmentation")
		diagCapture = fs.String("diagnostic-capture", "bounded", "Verifier diagnostics: bounded (failing submissions + feedback) | full (sanitized session context)")
		temperature = fs.String("temperature", "", "Sampling temperature (e.g. 0.0); empty = provider default")
		maxBudget   = fs.Float64("max-budget-usd", 0, "Paid-backend cost ceiling; 0 = no cap")
		appName     = fs.String("app-name", "", "Application name (honored at registration)")
		verifyBk    = fs.String("verify-backend", "", "Per-role backend for Phase 2b")
		verifyHost  = fs.String("verify-host", "", "Per-role host for Phase 2b")
		reconBk     = fs.String("recon-backend", "", "Per-role backend for Phase 1")
		reconHost   = fs.String("recon-host", "", "Per-role host for Phase 1")
		reproBk     = fs.String("reproduce-backend", "", "Per-role backend for Phases 3/3d/4")
		reproHost   = fs.String("reproduce-host", "", "Per-role host for Phases 3/3d/4")
	)
	fs.SetOutput(os.Stderr)
	if err := fs.Parse(normalizeLong(args)); err != nil {
		return ExitUsage
	}

	// Precedence: built-in default < profile < explicit flag. Apply profile
	// overrides only to knobs the user did NOT set explicitly.
	if *profile != "" {
		ov := profiles.Load(*profile)
		if ov == nil {
			fmt.Fprintf(os.Stderr, "warning: unknown profile %q — using defaults\n", *profile)
		} else {
			set := map[string]bool{}
			fs.Visit(func(f *flag.Flag) { set[f.Name] = true })
			applyProfile(ov, set, map[string]func(any){
				"num_ctx":            func(v any) { *numCtx = toInt(v, *numCtx) },
				"max_partitions":     func(v any) { *maxParts = toInt(v, *maxParts) },
				"phases":             func(v any) { *phasesFlag = toStr(v, *phasesFlag) },
				"reasoning_effort":   func(v any) { *reasoning = toStr(v, *reasoning) },
				"max_output_tokens":  func(v any) { *maxOut = toInt(v, *maxOut) },
				"quality_strictness": func(v any) { *strictness = toStr(v, *strictness) },
				"phase2_mode":        func(v any) { *phase2Mode = toStr(v, *phase2Mode) },
				"hunt_samples":       func(v any) { *huntSamples = toInt(v, *huntSamples) },
				"iac_lens":           func(v any) { *iacLens = toBool(v, *iacLens) },
				"remediate":          func(v any) { *remediate = toBool(v, *remediate) },
				"redact":             func(v any) { *redact = toBool(v, *redact) },
				"ledger":             func(v any) { *ledger = toBool(v, *ledger) },
				// Feature 013: structural knobs profiles may set (FR-026).
				"concurrency":        func(v any) { *concurrency = toInt(v, *concurrency) },
				"seed_routes":        func(v any) { *seedRoutes = toBool(v, *seedRoutes) },
				"seed_prior":         func(v any) { *seedPrior = toBool(v, *seedPrior) },
				"diagnostic_capture": func(v any) { *diagCapture = toStr(v, *diagCapture) },
				"enforce_coverage":   func(v any) { *enforceCov = toBool(v, *enforceCov) },
				"max_budget_usd":     func(v any) { *maxBudget = toFloat(v, *maxBudget) },
			})
		}
	}
	if *repo == "" {
		fmt.Fprintln(os.Stderr, "run: --repo is required")
		return ExitUsage
	}
	repoAbs, err := filepath.Abs(*repo)
	if err == nil {
		repoAbs, err = filepath.EvalSymlinks(repoAbs)
	}
	if err != nil || !isDir(repoAbs) {
		fmt.Fprintf(os.Stderr, "run: repo is not a directory: %s\n", *repo)
		return ExitUsage
	}

	phaseList, err := phases.SelectPhases(*phasesFlag)
	if err != nil {
		fmt.Fprintf(os.Stderr, "run: %v\n", err)
		return ExitUsage
	}

	// Feature 013 (FR-004/013): validate the new knobs before any model work.
	if *concurrency < 1 || *concurrency > 8 {
		fmt.Fprintln(os.Stderr, "run: --concurrency must be between 1 and 8")
		return ExitUsage
	}
	if *maxBudget < 0 {
		fmt.Fprintln(os.Stderr, "run: --max-budget-usd must be >= 0")
		return ExitUsage
	}
	temp, err := parseTemperature(*temperature)
	if err != nil {
		fmt.Fprintf(os.Stderr, "run: %v\n", err)
		return ExitUsage
	}

	// Resolve endpoint + provider.
	resolvedHost := *host
	if resolvedHost == "" {
		switch *backend {
		case "openai":
			resolvedHost = config.OpenAIHost()
		case "openrouter":
			resolvedHost = config.OpenRouterHost
		default:
			resolvedHost = config.OllamaHost()
		}
	}
	prov, err := buildProvider(*backend, resolvedHost)
	if err != nil {
		fmt.Fprintf(os.Stderr, "run: %v\n", err)
		return ExitUsage
	}

	// Resolve results dir + scan tag.
	stamp := time.Now().Format("2006-01-02-150405")
	resultsDir := *out
	if resultsDir == "" {
		name := fmt.Sprintf("%s_VULNHUNT_RESULTS_%s_%s", filepath.Base(repoAbs), modelTag(*model), stamp)
		resultsDir = filepath.Join(*reportsDir, name)
	}
	resultsDir, _ = filepath.Abs(resultsDir)

	// Skill source: --skill-dir, else on-disk ./skill, else embedded.
	skill := resolveSkill(*skillDir)

	enforce := *enforceCov
	spec := engine.ScanSpec{
		Repo: repoAbs, ResultsDir: resultsDir, SkillDir: skillDirPath(*skillDir),
		Model: *model, Host: resolvedHost, Backend: *backend, NumCtx: *numCtx,
		Phases: phaseList, MaxPartitions: *maxParts, VerifyModel: *verifyModel,
		ReconModel: *reconModel, ReproduceModel: *reproModel, MaxOutputTokens: *maxOut,
		ReasoningEffort: *reasoning, QualityStrictness: *strictness, Phase2Mode: *phase2Mode, ThreatModel: *threatModel,
		Ledger: *ledger, Redact: *redact, Remediate: *remediate, Resume: *resume,
		HuntSamples: *huntSamples, IaCLens: *iacLens, EngineVersion: vhlocal.Version, ScanTag: stamp,
		DiagnosticCapture: *diagCapture,
		// Feature 013: the newly-wired options, resolved identically to the server (FR-002).
		Concurrency: *concurrency, SeedRoutes: *seedRoutes, SeedPrior: *seedPrior,
		EnforceCoverage: &enforce, Temperature: temp, MaxBudgetUSD: *maxBudget, AppName: *appName,
		ReportsDir:       *reportsDir,
		LogTag:           stamp, // feature 014: CLI runs tag their log lines with the scan tag
		VerifyBackend:    *verifyBk,
		VerifyHost:       *verifyHost,
		ReconBackend:     *reconBk,
		ReconHost:        *reconHost,
		ReproduceBackend: *reproBk,
		ReproduceHost:    *reproHost,
	}

	// Feature 013 (FR-017): per-role providers so a per-role backend/host reaches its
	// calls; blank inherits Hunt. Build them the same way the server does (FR-002).
	providers := engine.Providers{Hunt: prov}
	if providers.Verify, err = cliRoleProvider(*verifyBk, *verifyHost, *backend); err != nil {
		fmt.Fprintf(os.Stderr, "run: %v\n", err)
		return ExitUsage
	}
	if providers.Recon, err = cliRoleProvider(*reconBk, *reconHost, *backend); err != nil {
		fmt.Fprintf(os.Stderr, "run: %v\n", err)
		return ExitUsage
	}
	if providers.Reproduce, err = cliRoleProvider(*reproBk, *reproHost, *backend); err != nil {
		fmt.Fprintf(os.Stderr, "run: %v\n", err)
		return ExitUsage
	}
	// Requested map mirrors the server's, so the effective config resolves identically.
	spec.EffectiveConfig = engine.BuildEffectiveConfig(cliRequested(fs), spec)

	emit := engine.Emit(func(event string, payload map[string]any) {
		switch event {
		case "phase_start":
			fmt.Fprintf(os.Stderr, "[phase %v] %v\n", payload["key"], payload["title"])
		case "agent_done":
			fmt.Fprintf(os.Stderr, "  · %v (%v turns, %v)\n", payload["label"], payload["turns"], payload["stopped_reason"])
		case "error":
			fmt.Fprintf(os.Stderr, "  ! %v\n", payload["message"])
		}
	})

	rec, err := engine.Execute(context.Background(), spec, providers, skill, emit)
	if err != nil {
		fmt.Fprintf(os.Stderr, "run: scan failed: %v\n", err)
		return ExitUsage
	}
	fmt.Printf("Results: %s\n", resultsDir)
	fmt.Printf("Open:    %s\n", filepath.Join(resultsDir, "SCAN_REPORT.html"))
	if rec.Aborted != "" {
		fmt.Fprintf(os.Stderr, "note: run aborted: %s\n", rec.Aborted)
	}
	return ExitOK
}

// applyProfile applies each override to its setter, unless the user set that
// flag explicitly (checked by the kebab-case flag name derived from the key).
func applyProfile(ov map[string]any, setFlags map[string]bool, setters map[string]func(any)) {
	for key, set := range setters {
		flagName := strings.ReplaceAll(key, "_", "-")
		if setFlags[flagName] {
			continue // explicit flag wins
		}
		if v, ok := ov[key]; ok {
			set(v)
		}
	}
}

func toInt(v any, def int) int {
	switch n := v.(type) {
	case float64:
		return int(n)
	case int:
		return n
	}
	return def
}
func toStr(v any, def string) string {
	if s, ok := v.(string); ok {
		return s
	}
	return def
}
func toBool(v any, def bool) bool {
	if b, ok := v.(bool); ok {
		return b
	}
	return def
}
func toFloat(v any, def float64) float64 {
	switch n := v.(type) {
	case float64:
		return n
	case int:
		return float64(n)
	}
	return def
}

// parseTemperature parses the --temperature flag into a *float64 so an explicit
// 0.0 is distinct from an omitted value (feature 013, FR-003/018).
func parseTemperature(s string) (*float64, error) {
	if strings.TrimSpace(s) == "" {
		return nil, nil
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return nil, fmt.Errorf("--temperature must be a number, got %q", s)
	}
	return &f, nil
}

// cliRoleProvider builds a per-role provider from a per-role backend/host override,
// or nil when neither is set (inherit Hunt), matching the server (FR-002/017).
func cliRoleProvider(roleBackend, roleHost, defBackend string) (client.Provider, error) {
	if roleBackend == "" && roleHost == "" {
		return nil, nil
	}
	backend := roleBackend
	if backend == "" {
		backend = defBackend
	}
	host := roleHost
	if host == "" {
		switch backend {
		case "openai":
			host = config.OpenAIHost()
		case "openrouter":
			host = config.OpenRouterHost
		default:
			host = config.OllamaHost()
		}
	}
	return buildProvider(backend, host)
}

// cliRequested builds the "requested" option map from the flags the operator set
// explicitly, so the effective config distinguishes requested from applied.
func cliRequested(fs *flag.FlagSet) map[string]any {
	req := map[string]any{}
	fs.Visit(func(f *flag.Flag) {
		key := strings.ReplaceAll(f.Name, "-", "_")
		req[key] = f.Value.String()
	})
	return req
}

func buildProvider(backend, host string) (client.Provider, error) {
	switch backend {
	case "ollama":
		return client.NewOllama(host), nil
	case "openai":
		return client.NewOpenAI(client.BackendOpenAI, host, config.OpenAIKeyFromEnv()), nil
	case "openrouter":
		key := config.OpenRouterKeyFromEnv()
		if key == "" {
			return nil, fmt.Errorf("openrouter backend needs $%s", config.EnvOpenRouterKey)
		}
		return client.NewOpenAI(client.BackendOpenRouter, "", key), nil
	default:
		return nil, fmt.Errorf("unknown backend %q", backend)
	}
}

var reNonAlnum = regexp.MustCompile(`[^a-z0-9]+`)

func modelTag(model string) string {
	return reNonAlnum.ReplaceAllString(strings.ToLower(model), "")
}

func isDir(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.IsDir()
}

// normalizeLong lets Go's flag package accept GNU-style --flag in addition to
// -flag (both --flag=v and --flag v), matching the Python CLI spellings.
func normalizeLong(args []string) []string {
	out := make([]string, 0, len(args))
	for _, a := range args {
		if strings.HasPrefix(a, "--") {
			out = append(out, a[1:]) // Go flag accepts single-dash long names
		} else {
			out = append(out, a)
		}
	}
	return out
}

// skillDirPath returns the sandbox read-root skill dir: the given dir, else the
// on-disk ./skill if present, else "" (embedded — nothing extra to read-allow).
func skillDirPath(flagDir string) string {
	if flagDir != "" {
		return flagDir
	}
	if isDir("skill") {
		abs, _ := filepath.Abs("skill")
		return abs
	}
	return ""
}

func resolveSkill(flagDir string) engine.SkillSource {
	if flagDir != "" {
		return engine.DirSkill{Dir: flagDir}
	}
	if isDir(filepath.Join("skill", "phases")) {
		abs, _ := filepath.Abs("skill")
		return engine.DirSkill{Dir: abs}
	}
	return embeddedSkill{}
}

// embeddedSkill serves the methodology bundled in the binary (assets.SkillFS).
type embeddedSkill struct{}

func (embeddedSkill) Preamble() string {
	b, err := fs.ReadFile(vhlocal.SkillFS, "skill/SKILL.md")
	if err != nil {
		return ""
	}
	return phases.LoadPreamble(string(b))
}

func (embeddedSkill) Prompt(file string) (string, error) {
	b, err := fs.ReadFile(vhlocal.SkillFS, "skill/phases/"+file)
	if err != nil {
		return "", err
	}
	return string(b), nil
}
