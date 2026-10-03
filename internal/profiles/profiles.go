// Package profiles applies configuration presets. A profile carries only
// structural, connection-independent knobs — it MUST NOT pin model, host, or
// backend (those come from configured connections). Precedence at the CLI is
// built-in default < profile < explicit flag. Mirrors the Python profiles.py.
package profiles

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"

	"vhlocal/internal/config"
)

// allowed structural keys (a profile never pins model/host/backend). Every key
// here maps to an implemented CLI setter and web control (feature 013, FR-026);
// `sweep_mode` was removed because it had no field/flag/behavior anywhere — an
// orphaned key is dropped by sanitize rather than silently "accepted".
var allowed = map[string]bool{
	"num_ctx": true, "max_partitions": true, "phase2_mode": true, "phases": true,
	"concurrency": true, "reasoning_effort": true, "max_output_tokens": true,
	"quality_strictness": true, "enforce_coverage": true,
	"seed_routes": true, "seed_prior": true, "hunt_samples": true, "iac_lens": true,
	"remediate": true, "redact": true, "ledger": true, "max_budget_usd": true,
}

// Profile is a named preset.
type Profile struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	Overrides   map[string]any `json:"overrides"`
	Builtin     bool           `json:"builtin"`
}

var builtins = []Profile{
	{Name: "quick", Description: "Fast single pass — combined classes, fewer partitions. A first look; lowest cost/time.",
		Overrides: map[string]any{"hunt_samples": 1, "phase2_mode": "combined", "max_partitions": 4, "iac_lens": true}},
	{Name: "thorough", Description: "Best recall — 3× multi-sample voting, split classes, full partitions, IaC + remediation. The variance-beating default.",
		Overrides: map[string]any{"hunt_samples": 3, "phase2_mode": "split", "max_partitions": 8, "iac_lens": true, "remediate": true}},
	{Name: "share", Description: "Thorough, plus redaction + remediation DTOs + ledger — for a report you'll archive or hand off.",
		Overrides: map[string]any{"hunt_samples": 3, "phase2_mode": "split", "max_partitions": 8, "iac_lens": true, "remediate": true, "redact": true, "ledger": true}},
	{Name: "benchmark", Description: "Single independent pass into the ledger — no seeding, split classes — for honest cross-run recall measurement.",
		Overrides: map[string]any{"hunt_samples": 1, "phase2_mode": "split", "max_partitions": 8, "seed_prior": false, "seed_routes": false, "ledger": true}},
}

func sanitize(m map[string]any) map[string]any {
	out := map[string]any{}
	for k, v := range m {
		if allowed[k] {
			out[k] = v
		}
	}
	return out
}

// List returns built-ins first, then user JSON profiles (a user file with a
// built-in name replaces it).
func List() []Profile {
	byName := map[string]Profile{}
	var order []string
	for _, p := range builtins {
		p.Overrides = sanitize(p.Overrides)
		p.Builtin = true
		byName[p.Name] = p
		order = append(order, p.Name)
	}
	dir := config.ProfilesDir()
	if entries, err := os.ReadDir(dir); err == nil {
		var files []string
		for _, e := range entries {
			if !e.IsDir() && filepath.Ext(e.Name()) == ".json" {
				files = append(files, e.Name())
			}
		}
		sort.Strings(files)
		for _, fn := range files {
			b, err := os.ReadFile(filepath.Join(dir, fn))
			if err != nil {
				continue
			}
			var p Profile
			if json.Unmarshal(b, &p) != nil {
				continue
			}
			if p.Name == "" {
				p.Name = fn[:len(fn)-len(".json")]
			}
			if p.Description == "" {
				p.Description = "(user profile)"
			}
			p.Overrides = sanitize(p.Overrides)
			p.Builtin = false
			if _, exists := byName[p.Name]; !exists {
				order = append(order, p.Name)
			}
			byName[p.Name] = p
		}
	}
	out := make([]Profile, 0, len(order))
	for _, n := range order {
		out = append(out, byName[n])
	}
	return out
}

// Load returns a profile's sanitized overrides by name, or nil if unknown.
func Load(name string) map[string]any {
	for _, p := range List() {
		if p.Name == name {
			return p.Overrides
		}
	}
	return nil
}
