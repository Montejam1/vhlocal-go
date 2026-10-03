package server

import (
	"strings"
	"testing"

	"vhlocal/internal/config"
)

// Feature 013 (FR-001/002): the server's allowlist is exactly the shared option
// contract — there is no second, divergent list.
func TestAllowlistIsTheRegistry(t *testing.T) {
	reg := config.ScanOptionKeys()
	if len(supportedScanOptions) != len(reg) {
		t.Fatalf("allowlist size %d != registry size %d", len(supportedScanOptions), len(reg))
	}
	for k := range reg {
		if !supportedScanOptions[k] {
			t.Errorf("registry option %q missing from server allowlist", k)
		}
	}
}

// CB-19 (US7, FR-034): unsupported options and bad enum/range values are rejected
// explicitly; supported options are accepted (never silently ignored).
func TestValidateScanOptions(t *testing.T) {
	cases := []struct {
		name string
		body map[string]any
		want bool // true = expect a rejection reason
	}{
		{"supported set", map[string]any{
			"repo": "/x", "app_name": "My App", "model": "m", "backend": "ollama",
			"phases": "all", "max_partitions": 8.0, "hunt_samples": 3.0,
			"quality_strictness": "balanced", "threat_model": true, "max_budget_usd": 5.0,
			"verify_model": "v", "verify_backend": "ollama", "verify_host": "h",
		}, false},
		{"unknown key", map[string]any{"repo": "/x", "totally_unknown_option": true}, true},
		{"bad backend", map[string]any{"repo": "/x", "backend": "bogus"}, true},
		{"bad strictness", map[string]any{"repo": "/x", "quality_strictness": "extreme"}, true},
		{"hunt_samples too high", map[string]any{"repo": "/x", "hunt_samples": 9.0}, true},
		{"negative budget", map[string]any{"repo": "/x", "max_budget_usd": -1.0}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := validateScanOptions(c.body)
			if (got != "") != c.want {
				t.Errorf("validateScanOptions=%q, want rejection=%v", got, c.want)
			}
		})
	}
}

// Feature 013 (FR-004): with several invalid fields the reported error is
// deterministic (sorted key order), not dependent on random map iteration.
func TestValidateScanOptionsDeterministicMultiError(t *testing.T) {
	body := map[string]any{
		"repo": "/x", "concurrency": 0, "backend": "bogus", "quality_strictness": "extreme",
	}
	first := validateScanOptions(body)
	if first == "" {
		t.Fatal("expected a rejection")
	}
	for i := 0; i < 50; i++ {
		if got := validateScanOptions(body); got != first {
			t.Fatalf("non-deterministic multi-error: %q vs %q", got, first)
		}
	}
	// With the shared registry, checks run in sorted key order, so the reported
	// error is the alphabetically-first invalid field (backend < concurrency <
	// quality_strictness) — deterministic and field-specific.
	if !strings.Contains(first, "backend") {
		t.Errorf("expected the alphabetically-first invalid field (backend), got %q", first)
	}
}
