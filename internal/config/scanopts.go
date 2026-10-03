package config

import (
	"fmt"
	"math"
	"sort"
	"strings"
)

// ScanOptionDef is the authoritative definition of one scan option (feature 013,
// FR-001): the single source of truth consulted by the request validator,
// buildScan, the CLI, and profiles so surfaces cannot diverge. It documents the
// option's type, default, accepted range/enum, and how omitted/null is handled.
//
// Null/omitted handling by type (matches the shipped forms, which send optional
// string/enum fields as JSON null when unset):
//   - bool / int: an explicit null is INVALID (the functional controls must be a
//     concrete value; the rejection contract depends on this).
//   - float / enum / string: null (and "" for enum) means "not provided" and is
//     accepted — buildScan then applies the default.
type ScanOptionDef struct {
	ID       string
	Type     string // "bool" | "int" | "float" | "enum" | "string"
	Default  any
	Min, Max float64
	HasRange bool
	Enum     []string
}

// Registry is the option contract. Every key here is an accepted request option;
// a key absent from it is rejected as unsupported. Value validation is derived
// from each definition's Type/range/enum (see Check).
var Registry = map[string]ScanOptionDef{
	// Identity / location (free-form strings; resource checks live in the handler).
	"repo": {ID: "repo", Type: "string"}, "out": {ID: "out", Type: "string"},
	"app_name": {ID: "app_name", Type: "string"}, "name": {ID: "name", Type: "string"},
	"skill_dir": {ID: "skill_dir", Type: "string"}, "phases": {ID: "phases", Type: "string"},
	// Provider selection.
	"model":   {ID: "model", Type: "string"},
	"host":    {ID: "host", Type: "string"},
	"backend": {ID: "backend", Type: "enum", Default: "ollama", Enum: []string{"ollama", "openai", "openrouter"}},
	// Per-role provider overrides.
	"verify_model": {ID: "verify_model", Type: "string"}, "verify_host": {ID: "verify_host", Type: "string"},
	"verify_backend": {ID: "verify_backend", Type: "enum", Enum: []string{"ollama", "openai", "openrouter"}},
	"recon_model":    {ID: "recon_model", Type: "string"}, "recon_host": {ID: "recon_host", Type: "string"},
	"recon_backend":   {ID: "recon_backend", Type: "enum", Enum: []string{"ollama", "openai", "openrouter"}},
	"reproduce_model": {ID: "reproduce_model", Type: "string"}, "reproduce_host": {ID: "reproduce_host", Type: "string"},
	"reproduce_backend": {ID: "reproduce_backend", Type: "enum", Enum: []string{"ollama", "openai", "openrouter"}},
	// Numeric knobs (num_ctx/max_partitions positivity is enforced by the handler).
	"num_ctx":           {ID: "num_ctx", Type: "int"},
	"max_partitions":    {ID: "max_partitions", Type: "int"},
	"max_output_tokens": {ID: "max_output_tokens", Type: "int"},
	"hunt_samples":      {ID: "hunt_samples", Type: "int", Default: 1, Min: 1, Max: 5, HasRange: true},
	"concurrency":       {ID: "concurrency", Type: "int", Default: 1, Min: 1, Max: 8, HasRange: true},
	"max_budget_usd":    {ID: "max_budget_usd", Type: "float", Default: 0.0, Min: 0, HasRange: true},
	"temperature":       {ID: "temperature", Type: "float"},
	// Enums.
	"reasoning_effort":   {ID: "reasoning_effort", Type: "enum", Enum: []string{"low", "medium", "high"}},
	"quality_strictness": {ID: "quality_strictness", Type: "enum", Default: "balanced", Enum: []string{"lenient", "balanced", "strict"}},
	"phase2_mode":        {ID: "phase2_mode", Type: "enum", Default: "split", Enum: []string{"split", "combined"}},
	// Booleans.
	"threat_model": {ID: "threat_model", Type: "bool", Default: false},
	"ledger":       {ID: "ledger", Type: "bool", Default: false},
	"redact":       {ID: "redact", Type: "bool", Default: false},
	"remediate":    {ID: "remediate", Type: "bool", Default: false},
	"resume":       {ID: "resume", Type: "bool", Default: false},
	"iac_lens":     {ID: "iac_lens", Type: "bool", Default: true},
	// Feature 013 functional controls.
	"seed_routes":      {ID: "seed_routes", Type: "bool", Default: false},
	"seed_prior":       {ID: "seed_prior", Type: "bool", Default: false},
	"enforce_coverage": {ID: "enforce_coverage", Type: "bool", Default: true},
	// Feature 015 (FR-029): verifier diagnostic capture depth.
	"diagnostic_capture": {ID: "diagnostic_capture", Type: "enum", Default: "bounded", Enum: []string{"bounded", "full"}},
}

// ScanOptionKeys returns the set of accepted option keys (the allowlist derived
// from the registry), for callers that only need membership.
func ScanOptionKeys() map[string]bool {
	out := make(map[string]bool, len(Registry))
	for k := range Registry {
		out[k] = true
	}
	return out
}

// ValidateScanOptions checks a raw request against the registry and returns the
// first error (empty when valid). Keys are checked in sorted order so that, when
// several fields are invalid, the reported error is deterministic (FR-004).
func ValidateScanOptions(raw map[string]any) string {
	keys := make([]string, 0, len(raw))
	for k := range raw {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		def, ok := Registry[k]
		if !ok {
			return "unsupported option: " + k
		}
		if msg := def.Check(raw[k]); msg != "" {
			return msg
		}
	}
	return ""
}

// Check validates one value against this definition, returning a field-specific
// error (containing the option id) or "" when acceptable.
func (d ScanOptionDef) Check(v any) string {
	switch d.Type {
	case "bool":
		if _, ok := v.(bool); !ok {
			return d.ID + " must be true or false"
		}
	case "int":
		n, ok := asWhole(v)
		if !ok {
			if f, isNum := v.(float64); isNum && f != math.Trunc(f) {
				return d.ID + " must be a whole number, not a fraction"
			}
			return d.ID + " must be an integer" + d.rangeSuffix()
		}
		if d.HasRange && (float64(n) < d.Min || float64(n) > d.Max) {
			return fmt.Sprintf("%s must be between %d and %d", d.ID, int(d.Min), int(d.Max))
		}
	case "float":
		if v == nil {
			return ""
		}
		f, ok := asFloat(v)
		if !ok {
			return d.ID + " must be a number"
		}
		if d.HasRange && f < d.Min {
			return fmt.Sprintf("%s must be >= %g", d.ID, d.Min)
		}
	case "enum":
		if v == nil {
			return ""
		}
		s, ok := v.(string)
		if !ok {
			return d.ID + " must be one of: " + strings.Join(d.Enum, ", ")
		}
		if s == "" {
			return "" // empty = default
		}
		for _, e := range d.Enum {
			if s == e {
				return ""
			}
		}
		return "unsupported " + d.ID + ": " + s
	case "string":
		// Any string (or null = absent) is acceptable; resource/format checks, if
		// any, live at the call site (e.g. repo directory, phases parsing).
	}
	return ""
}

func (d ScanOptionDef) rangeSuffix() string {
	if d.HasRange {
		return fmt.Sprintf(" between %d and %d", int(d.Min), int(d.Max))
	}
	return ""
}

// asWhole returns v as an int when it is a whole number (int or integral float64,
// as JSON decodes numbers), else ok=false.
func asWhole(v any) (int, bool) {
	switch n := v.(type) {
	case float64:
		if n == math.Trunc(n) {
			return int(n), true
		}
	case int:
		return n, true
	}
	return 0, false
}

func asFloat(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case int:
		return float64(n), true
	}
	return 0, false
}
