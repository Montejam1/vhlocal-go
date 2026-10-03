package engine

import (
	"net/url"
	"strings"
)

// EffectiveConfig is the honest requested-vs-applied summary of a scan's options
// (feature 013, FR-005/SC-010). It distinguishes what the operator ASKED for from
// what the engine APPLIED, and explains any accepted-but-inapplicable option.
// Secrets are removed by the assembler. It lives in the engine package because
// RunRecord persists it and both the server and CLI assemble it (FR-002 parity).
type EffectiveConfig struct {
	Requested     map[string]any        `json:"requested"`
	Applied       map[string]any        `json:"applied"`
	NotApplicable []NotApplicableOption `json:"not_applicable,omitempty"`
}

// NotApplicableOption records an accepted option that did not apply, with why.
type NotApplicableOption struct {
	Option string `json:"option"`
	Reason string `json:"reason"`
}

// addNotApplicable appends an explained non-applicability entry (idempotent).
func (e *EffectiveConfig) addNotApplicable(option, reason string) {
	if e == nil {
		return
	}
	for _, na := range e.NotApplicable {
		if na.Option == option {
			return
		}
	}
	e.NotApplicable = append(e.NotApplicable, NotApplicableOption{Option: option, Reason: reason})
}

// BuildEffectiveConfig assembles the requested-vs-applied summary (FR-005/SC-010).
// `requested` is the operator's raw request (secrets removed here); `sc` is the
// resolved spec, so `applied` reflects what the engine will actually use. The same
// function serves the server and CLI so equivalent inputs resolve identically
// (FR-002). Statically-known non-applicability is recorded; runtime cases are
// appended by Execute.
func BuildEffectiveConfig(requested map[string]any, sc ScanSpec) *EffectiveConfig {
	ec := &EffectiveConfig{
		Requested: RedactSecrets(requested),
		Applied: map[string]any{
			"model":              sc.Model,
			"backend":            sc.Backend,
			"host":               redactURL(sc.Host),
			"phases":             sc.Phases,
			"num_ctx":            sc.NumCtx,
			"max_partitions":     sc.MaxPartitions,
			"max_output_tokens":  sc.MaxOutputTokens,
			"reasoning_effort":   sc.ReasoningEffort,
			"quality_strictness": sc.QualityStrictness,
			"phase2_mode":        appliedPhase2Mode(sc.Phase2Mode),
			"hunt_samples":       sc.HuntSamples,
			"iac_lens":           sc.IaCLens,
			"threat_model":       sc.ThreatModel,
			"ledger":             sc.Ledger,
			"redact":             sc.Redact,
			"remediate":          sc.Remediate,
			"resume":             sc.Resume,
			"concurrency":        sc.concurrency(),
			"enforce_coverage":   sc.enforceCoverage(),
			"seed_routes":        sc.SeedRoutes,
			"seed_prior":         sc.SeedPrior,
			"max_budget_usd":     sc.MaxBudgetUSD,
			"app_name":           sc.AppName,
			"diagnostic_capture": orText(sc.DiagnosticCapture, DiagnosticBounded),
			"temperature":        appliedTemperature(sc.Temperature),
		},
	}
	addRole(ec.Applied, "verify", sc.VerifyModel, sc.VerifyBackend, sc.VerifyHost)
	addRole(ec.Applied, "recon", sc.ReconModel, sc.ReconBackend, sc.ReconHost)
	addRole(ec.Applied, "reproduce", sc.ReproduceModel, sc.ReproduceBackend, sc.ReproduceHost)

	if !reconSelected(sc.Phases) {
		if sc.SeedRoutes {
			ec.addNotApplicable("seed_routes", "recon phase not selected")
		}
		if sc.SeedPrior {
			ec.addNotApplicable("seed_prior", "recon phase not selected")
		}
	}
	return ec
}

func appliedPhase2Mode(m string) string {
	if strings.EqualFold(m, "combined") {
		return "combined"
	}
	return "split"
}

func appliedTemperature(t *float64) any {
	if t == nil {
		return "provider-default"
	}
	return *t
}

func addRole(applied map[string]any, role, model, backend, host string) {
	if model != "" {
		applied[role+"_model"] = model
	}
	if backend != "" {
		applied[role+"_backend"] = backend
	}
	if host != "" {
		applied[role+"_host"] = redactURL(host)
	}
}

// secretKey reports whether a request key names a secret that must never be
// persisted into the effective config (FR-005).
func secretKey(k string) bool {
	k = strings.ToLower(k)
	return strings.Contains(k, "key") || strings.Contains(k, "token") ||
		strings.Contains(k, "secret") || strings.Contains(k, "password") || strings.Contains(k, "passwd")
}

// RedactSecrets returns a copy of the request with secret-bearing keys removed and
// credentialed host URLs redacted.
func RedactSecrets(in map[string]any) map[string]any {
	out := make(map[string]any, len(in))
	for k, v := range in {
		if secretKey(k) {
			out[k] = "[redacted]"
			continue
		}
		if s, ok := v.(string); ok && (k == "host" || strings.HasSuffix(k, "_host")) {
			out[k] = redactURL(s)
			continue
		}
		out[k] = v
	}
	return out
}

// redactURL strips any credentials embedded in a URL's userinfo.
func redactURL(raw string) string {
	if raw == "" {
		return raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.User == nil {
		return raw
	}
	u.User = url.User("[redacted]")
	return u.String()
}
