package config

import (
	"strings"
	"testing"
)

// Feature 013 (FR-003/004): the shared contract validates types/ranges/enums with
// field-specific errors; false / 0 / omitted / null are distinct; fractional
// concurrency is rejected, never rounded.
func TestValidateScanOptionsContract(t *testing.T) {
	cases := []struct {
		name   string
		raw    map[string]any
		reject bool
		substr string // when rejecting, the message must contain this
	}{
		{"valid full", map[string]any{
			"repo": "/x", "backend": "ollama", "concurrency": 4.0, "enforce_coverage": false,
			"seed_routes": true, "hunt_samples": 3.0, "quality_strictness": "strict",
			"phase2_mode": "combined", "max_budget_usd": 5.0,
		}, false, ""},
		{"unknown key", map[string]any{"totally_unknown": true}, true, "totally_unknown"},
		{"concurrency zero", map[string]any{"concurrency": 0.0}, true, "concurrency"},
		{"concurrency over range", map[string]any{"concurrency": 9.0}, true, "concurrency"},
		{"concurrency fractional", map[string]any{"concurrency": 1.5}, true, "whole number"},
		{"concurrency string", map[string]any{"concurrency": "2"}, true, "concurrency"},
		{"concurrency null", map[string]any{"concurrency": nil}, true, "concurrency"},
		{"seed_routes non-bool", map[string]any{"seed_routes": "true"}, true, "seed_routes"},
		{"enforce_coverage null", map[string]any{"enforce_coverage": nil}, true, "enforce_coverage"},
		{"bad backend", map[string]any{"backend": "bogus"}, true, "backend"},
		{"bad strictness", map[string]any{"quality_strictness": "extreme"}, true, "quality_strictness"},
		{"hunt_samples over", map[string]any{"hunt_samples": 9.0}, true, "hunt_samples"},
		{"negative budget", map[string]any{"max_budget_usd": -1.0}, true, "max_budget_usd"},
		// Distinctness: false / 0 (where valid) are accepted as themselves.
		{"enforce false ok", map[string]any{"enforce_coverage": false}, false, ""},
		{"seed false ok", map[string]any{"seed_routes": false}, false, ""},
		// Optional enums/strings may be null (forms send null when unset).
		{"null host ok", map[string]any{"host": nil}, false, ""},
		{"null reasoning ok", map[string]any{"reasoning_effort": nil}, false, ""},
		{"empty enum ok", map[string]any{"quality_strictness": ""}, false, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := ValidateScanOptions(c.raw)
			if (got != "") != c.reject {
				t.Fatalf("reject=%v, got %q", c.reject, got)
			}
			if c.reject && !strings.Contains(got, c.substr) {
				t.Errorf("error %q should contain %q", got, c.substr)
			}
		})
	}
}

// Determinism: multiple invalid fields always yield the same (alphabetically-first)
// error (FR-004).
func TestValidateDeterministic(t *testing.T) {
	raw := map[string]any{"concurrency": 0.0, "backend": "bogus", "quality_strictness": "extreme"}
	first := ValidateScanOptions(raw)
	for i := 0; i < 50; i++ {
		if got := ValidateScanOptions(raw); got != first {
			t.Fatalf("non-deterministic: %q vs %q", got, first)
		}
	}
	if !strings.Contains(first, "backend") {
		t.Errorf("expected alphabetically-first field (backend), got %q", first)
	}
}

// The registry documents a type for every advertised option so the contract stays
// the single source of truth (FR-001).
func TestRegistryEveryEntryTyped(t *testing.T) {
	valid := map[string]bool{"bool": true, "int": true, "float": true, "enum": true, "string": true}
	for k, d := range Registry {
		if d.ID != k {
			t.Errorf("registry key %q has mismatched ID %q", k, d.ID)
		}
		if !valid[d.Type] {
			t.Errorf("option %q has invalid type %q", k, d.Type)
		}
		if d.Type == "enum" && len(d.Enum) == 0 {
			t.Errorf("enum option %q has no enum values", k)
		}
	}
}
