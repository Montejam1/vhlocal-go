package server

import (
	"reflect"
	"testing"
)

// Feature 013 (FR-002, SC-005): equivalent option inputs resolve to the same
// effective configuration — the resolution is deterministic and driven by the one
// shared contract, so different surfaces submitting the same values agree.
func TestEquivalentInputsResolveIdentically(t *testing.T) {
	s := &Server{cfg: Config{ReportsDir: t.TempDir(), OllamaHost: "http://h", Version: "v"}}
	opts := map[string]any{
		"repo": "/tmp/x", "model": "m", "backend": "ollama", "concurrency": 3.0,
		"enforce_coverage": false, "seed_routes": true, "hunt_samples": 2.0, "phase2_mode": "combined",
	}
	// Two independent resolutions of the same option set (as two surfaces would).
	copy1 := map[string]any{}
	copy2 := map[string]any{}
	for k, v := range opts {
		copy1[k] = v
		copy2[k] = v
	}
	a, _, _, err := s.buildScan(copy1)
	if err != nil {
		t.Fatal(err)
	}
	b, _, _, err := s.buildScan(copy2)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(a.EffectiveConfig.Applied, b.EffectiveConfig.Applied) {
		t.Errorf("equivalent inputs produced different applied config:\n%v\n%v", a.EffectiveConfig.Applied, b.EffectiveConfig.Applied)
	}
	// And the applied values reflect the request (not silently defaulted).
	if a.EffectiveConfig.Applied["concurrency"] != 3 || a.EffectiveConfig.Applied["enforce_coverage"] != false {
		t.Errorf("applied config did not reflect the request: %v", a.EffectiveConfig.Applied)
	}
}

// Feature 013 (FR-017): a per-role backend/host builds a DISTINCT provider for
// that role; a blank per-role override inherits the Hunt provider (nil), so
// forPhase falls back. No silent switch, only operator-configured endpoints.
func TestBuildScanPerRoleProviders(t *testing.T) {
	s := &Server{cfg: Config{ReportsDir: t.TempDir(), OllamaHost: "http://hunt-host:11434", Version: "v"}}
	spec := map[string]any{
		"repo": "/tmp/x", "model": "m", "backend": "ollama",
		"verify_host": "http://verify-host:11434", // distinct verify endpoint
		// recon/reproduce left blank → inherit Hunt
	}
	sc, prov, _, err := s.buildScan(spec)
	if err != nil {
		t.Fatal(err)
	}
	if prov.Hunt == nil {
		t.Fatal("hunt provider missing")
	}
	if prov.Verify == nil {
		t.Fatal("verify provider should be built from verify_host")
	}
	if prov.Verify.Endpoint() != "http://verify-host:11434" {
		t.Errorf("verify endpoint = %q, want the operator-configured verify host", prov.Verify.Endpoint())
	}
	if prov.Recon != nil || prov.Reproduce != nil {
		t.Error("blank per-role overrides must inherit Hunt (nil), not build a new provider")
	}
	if sc.VerifyHost != "http://verify-host:11434" {
		t.Errorf("verify host not carried into effective spec: %q", sc.VerifyHost)
	}
}

// Feature 013 (FR-003/FR-018): temperature is a pointer so an explicit 0 is
// distinct from an omitted value and is never replaced by a default.
func TestBuildScanTemperatureDistinctZeroVsUnset(t *testing.T) {
	s := &Server{cfg: Config{ReportsDir: t.TempDir(), OllamaHost: "http://h", Version: "v"}}

	scUnset, _, _, err := s.buildScan(map[string]any{"repo": "/tmp/x", "backend": "ollama"})
	if err != nil {
		t.Fatal(err)
	}
	if scUnset.Temperature != nil {
		t.Errorf("omitted temperature must be nil, got %v", *scUnset.Temperature)
	}

	scZero, _, _, err := s.buildScan(map[string]any{"repo": "/tmp/x", "backend": "ollama", "temperature": 0.0})
	if err != nil {
		t.Fatal(err)
	}
	if scZero.Temperature == nil || *scZero.Temperature != 0 {
		t.Errorf("explicit temperature 0 must be preserved as *0, got %v", scZero.Temperature)
	}

	scHalf, _, _, err := s.buildScan(map[string]any{"repo": "/tmp/x", "backend": "ollama", "temperature": 0.5})
	if err != nil {
		t.Fatal(err)
	}
	if scHalf.Temperature == nil || *scHalf.Temperature != 0.5 {
		t.Errorf("temperature 0.5 not honored, got %v", scHalf.Temperature)
	}
}

// Feature 013 (FR-016): phase2_mode is carried into the spec (was dropped).
func TestBuildScanPhase2ModeCarried(t *testing.T) {
	s := &Server{cfg: Config{ReportsDir: t.TempDir(), OllamaHost: "http://h", Version: "v"}}
	sc, _, _, err := s.buildScan(map[string]any{"repo": "/tmp/x", "backend": "ollama", "phase2_mode": "combined"})
	if err != nil {
		t.Fatal(err)
	}
	if sc.Phase2Mode != "combined" {
		t.Errorf("phase2_mode not carried: %q", sc.Phase2Mode)
	}
}
