package server

import (
	"strings"
	"testing"

	"vhlocal/internal/engine"
)

// CB-19 (US7, FR-034): supported options are traced into the effective engine
// configuration — app_name and max_budget_usd (previously silently ignored) are now
// honored, alongside the existing knobs.
func TestBuildScanEffectiveConfig(t *testing.T) {
	s := &Server{cfg: Config{ReportsDir: t.TempDir(), OllamaHost: "http://h", Version: "v"}}
	spec := map[string]any{
		"repo": "/tmp/x", "app_name": "My App", "model": "m", "backend": "ollama",
		"max_budget_usd": 5.0, "hunt_samples": 3.0, "quality_strictness": "strict",
		"threat_model": true, "phases": "all",
	}
	sc, _, _, err := s.buildScan(spec)
	if err != nil {
		t.Fatal(err)
	}
	if sc.AppName != "My App" {
		t.Errorf("app_name not honored: %q", sc.AppName)
	}
	if sc.MaxBudgetUSD != 5.0 {
		t.Errorf("max_budget_usd not honored: %v", sc.MaxBudgetUSD)
	}
	if sc.QualityStrictness != "strict" || sc.HuntSamples != 3 || !sc.ThreatModel {
		t.Errorf("supported options not carried into effective config: %+v", sc)
	}
}

// Feature 013 (FR-005, SC-010): the effective config distinguishes requested from
// applied, explains non-applicability, and removes secrets.
func TestEffectiveConfigRequestedVsApplied(t *testing.T) {
	s := &Server{cfg: Config{ReportsDir: t.TempDir(), OllamaHost: "http://h", Version: "v"}}
	spec := map[string]any{
		"repo": "/tmp/x", "model": "m", "backend": "ollama",
		// concurrency + enforce_coverage omitted → applied defaults (1, true).
		"seed_routes": true, "phases": "4", // seeding requested but no recon phase
		"host": "http://user:sekret@h:11434", // credentials must be redacted
	}
	sc, _, _, err := s.buildScan(spec)
	if err != nil {
		t.Fatal(err)
	}
	ec := sc.EffectiveConfig
	if ec == nil {
		t.Fatal("effective config not assembled")
	}
	// Applied defaults for omitted options.
	if ec.Applied["concurrency"] != 1 {
		t.Errorf("applied concurrency default = %v, want 1", ec.Applied["concurrency"])
	}
	if ec.Applied["enforce_coverage"] != true {
		t.Errorf("applied enforce_coverage default = %v, want true", ec.Applied["enforce_coverage"])
	}
	// Requested carries what was asked (seed_routes true), applied too.
	if ec.Requested["seed_routes"] != true || ec.Applied["seed_routes"] != true {
		t.Errorf("seed_routes requested/applied not recorded: %+v / %+v", ec.Requested, ec.Applied)
	}
	// Not-applicable explained: seeding without a recon phase.
	found := false
	for _, na := range ec.NotApplicable {
		if na.Option == "seed_routes" && na.Reason != "" {
			found = true
		}
	}
	if !found {
		t.Errorf("seed_routes without recon phase must be recorded not-applicable: %+v", ec.NotApplicable)
	}
	// Secrets removed: no credentials in requested or applied host.
	if h, _ := ec.Requested["host"].(string); strings.Contains(h, "sekret") {
		t.Errorf("requested host credentials not redacted: %q", h)
	}
	if h, _ := ec.Applied["host"].(string); strings.Contains(h, "sekret") {
		t.Errorf("applied host credentials not redacted: %q", h)
	}
}

func TestRedactSecretsRemovesKeys(t *testing.T) {
	in := map[string]any{"api_key": "abc", "openrouter_token": "xyz", "model": "m"}
	out := engine.RedactSecrets(in)
	if out["api_key"] == "abc" || out["openrouter_token"] == "xyz" {
		t.Errorf("secret keys not redacted: %+v", out)
	}
	if out["model"] != "m" {
		t.Errorf("non-secret key dropped: %+v", out)
	}
}
