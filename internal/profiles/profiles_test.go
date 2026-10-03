package profiles

import (
	"os"
	"path/filepath"
	"testing"

	"vhlocal/internal/config"
)

// Feature 013 (FR-001/026): every structural key a profile may set is a real option
// in the shared contract — no orphaned keys (the old sweep_mode was removed).
func TestProfileAllowedKeysAreRegistered(t *testing.T) {
	reg := config.Registry
	for k := range allowed {
		if _, ok := reg[k]; !ok {
			t.Errorf("profile allows %q but it is not in the option registry (orphan)", k)
		}
	}
}

func TestBuiltinsAndSanitize(t *testing.T) {
	// Point profiles dir at an empty temp so only built-ins load.
	t.Setenv("VHLOCAL_PROFILES_DIR", t.TempDir())
	got := List()
	if len(got) != 4 {
		t.Fatalf("want 4 built-ins, got %d", len(got))
	}
	if got[0].Name != "quick" || !got[0].Builtin {
		t.Errorf("first = %+v", got[0])
	}
	q := Load("thorough")
	if q["hunt_samples"] != 3 || q["phase2_mode"] != "split" {
		t.Errorf("thorough overrides = %v", q)
	}
}

// Feature 013 (FR-026): the now-functional structural knobs are accepted by a
// profile, and the orphaned sweep_mode is dropped (not silently accepted).
func TestProfileStructuralKnobsAndSweepModeResolved(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("VHLOCAL_PROFILES_DIR", dir)
	os.WriteFile(filepath.Join(dir, "p.json"), []byte(`{"name":"p","overrides":{"concurrency":4,"enforce_coverage":false,"seed_routes":true,"seed_prior":true,"max_budget_usd":2.5,"sweep_mode":"deep"}}`), 0o644)
	ov := Load("p")
	if ov["concurrency"] != float64(4) {
		t.Errorf("concurrency not carried: %v", ov["concurrency"])
	}
	if ov["enforce_coverage"] != false {
		t.Errorf("enforce_coverage=false not carried: %v", ov["enforce_coverage"])
	}
	if ov["seed_routes"] != true || ov["seed_prior"] != true {
		t.Errorf("seed_* not carried: %v", ov)
	}
	if ov["max_budget_usd"] != 2.5 {
		t.Errorf("max_budget_usd not carried: %v", ov["max_budget_usd"])
	}
	if _, ok := ov["sweep_mode"]; ok {
		t.Error("orphaned sweep_mode must be dropped, not accepted")
	}
}

func TestProfileNeverPinsModel(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("VHLOCAL_PROFILES_DIR", dir)
	// A malicious user profile trying to pin model/host/backend must be stripped.
	os.WriteFile(filepath.Join(dir, "sneaky.json"), []byte(`{"name":"sneaky","overrides":{"model":"evil","host":"http://x","backend":"openrouter","max_partitions":2}}`), 0o644)
	ov := Load("sneaky")
	if _, ok := ov["model"]; ok {
		t.Error("profile must not carry model")
	}
	if _, ok := ov["host"]; ok {
		t.Error("profile must not carry host")
	}
	if _, ok := ov["backend"]; ok {
		t.Error("profile must not carry backend")
	}
	if ov["max_partitions"] != float64(2) { // structural key kept (JSON number)
		t.Errorf("structural key dropped: %v", ov)
	}
}

func TestUserProfileOverridesBuiltinName(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("VHLOCAL_PROFILES_DIR", dir)
	os.WriteFile(filepath.Join(dir, "quick.json"), []byte(`{"name":"quick","description":"mine","overrides":{"max_partitions":1}}`), 0o644)
	for _, p := range List() {
		if p.Name == "quick" {
			if p.Description != "mine" || p.Builtin {
				t.Errorf("user profile should override built-in: %+v", p)
			}
			return
		}
	}
	t.Fatal("quick not found")
}
