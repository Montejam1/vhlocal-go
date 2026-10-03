// Package phases defines the scan pipeline's phase specs and the parsers over
// model output that drive it. All regex over model output routes through
// NormalizeText first (FR-025).
package phases

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

// PhaseSpec describes one phase (parity with Python phases.PHASES).
type PhaseSpec struct {
	Key        string
	Title      string
	PromptFile string
	OutputFile string
	MaxTurns   int
	Reads      []string
	FanOut     bool // Phase 2 only
}

// PHASES is the ordered pipeline. Keys are the interface contract for --phases.
var PHASES = []PhaseSpec{
	{Key: "1", Title: "Recon — attack surface mapping", PromptFile: "phase1_recon.md", OutputFile: "phase1_output.md", MaxTurns: 90},
	{Key: "1t", Title: "Threat model — PASTA", PromptFile: "phase1t_threat_model.md", OutputFile: "threat_model.md", MaxTurns: 60, Reads: []string{"phase1_output.md"}},
	{Key: "2", Title: "Hunt — forward tracing", PromptFile: "phase2_hunt.md", OutputFile: "results/", MaxTurns: 80, Reads: []string{"phase1_output.md"}, FanOut: true},
	{Key: "2b", Title: "Verify — adversarial falsification", PromptFile: "phase2b_verify.md", OutputFile: "phase2b_output.md", MaxTurns: 70, Reads: []string{"results/"}},
	{Key: "3", Title: "Reproduce, test, fix", PromptFile: "phase3_reproduce_test.md", OutputFile: "phase3_output.md", MaxTurns: 80, Reads: []string{"phase2b_handoff.md"}},
	{Key: "3d", Title: "Sweep — root-cause instances", PromptFile: "phase3d_sweep.md", OutputFile: "phase3d_output.md", MaxTurns: 60, Reads: []string{"phase3_output.md"}},
	{Key: "4", Title: "Report", PromptFile: "phase4_report.md", OutputFile: "README.md", MaxTurns: 50, Reads: []string{"phase1_output.md", "phase2b_output.md", "phase3_output.md", "phase3d_output.md"}},
}

// PhasesByKey indexes PHASES by key.
var PhasesByKey = func() map[string]PhaseSpec {
	m := make(map[string]PhaseSpec, len(PHASES))
	for _, p := range PHASES {
		m[p.Key] = p
	}
	return m
}()

// ClassGroup is a Phase-2 vulnerability class (split mode: one agent per class
// per partition).
type ClassGroup struct {
	Code       string
	PromptFile string
	Blurb      string
}

// ClassGroups mirrors phase2_hunt.md's class-group dispatch.
var ClassGroups = []ClassGroup{
	{"INJ", "phase2_class_inj.md", "injection (SQLi, command, path traversal, SSRF, XSS, XXE, SSTI, upload)"},
	{"NAV", "phase2_class_nav.md", "navigation & access control (authz bypass, IDOR, redirects, deserialization)"},
	{"LOG", "phase2_class_log.md", "logic & crypto (weak crypto, race conditions, business-logic flaws)"},
}

// Preamble markers in SKILL.md.
const (
	preambleStart = "## Operating Principles"
	preambleEnd   = "## Workflow"
)

// LoadPreamble extracts the Operating Principles..Workflow section from SKILL.md
// text (the shared scope/discipline every phase agent inherits). Returns "" if
// the start marker is absent (caller logs a visible warning).
func LoadPreamble(skillMD string) string {
	start := strings.Index(skillMD, preambleStart)
	if start == -1 {
		return ""
	}
	rest := skillMD[start:]
	if end := strings.Index(rest[len(preambleStart):], preambleEnd); end != -1 {
		return strings.TrimSpace(rest[:len(preambleStart)+end])
	}
	return strings.TrimSpace(rest)
}

// validPhaseKeys is the accepted --phases key set.
var validPhaseKeys = func() map[string]bool {
	m := map[string]bool{}
	for _, p := range PHASES {
		m[p.Key] = true
	}
	return m
}()

// SelectPhases resolves a --phases spec ("all" or a comma list) to an ordered,
// validated phase-key slice, preserving PHASES order. Unknown keys error with
// the same message shape as the Python select_phases.
func SelectPhases(spec string) ([]string, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" || strings.EqualFold(spec, "all") {
		out := make([]string, len(PHASES))
		for i, p := range PHASES {
			out[i] = p.Key
		}
		return out, nil
	}
	want := map[string]bool{}
	var unknown []string
	for _, tok := range strings.Split(spec, ",") {
		k := strings.TrimSpace(tok)
		if k == "" {
			continue
		}
		if !validPhaseKeys[k] {
			unknown = append(unknown, k)
			continue
		}
		want[k] = true
	}
	if len(unknown) > 0 {
		valid := make([]string, 0, len(PHASES))
		for _, p := range PHASES {
			valid = append(valid, p.Key)
		}
		return nil, fmt.Errorf("unknown phase(s) %s. Valid: %s",
			strings.Join(unknown, ", "), strings.Join(valid, ", "))
	}
	var out []string
	for _, p := range PHASES {
		if want[p.Key] {
			out = append(out, p.Key)
		}
	}
	return out, nil
}

// HuntTarget is one parsed entry from a threat model's "Hunt targets" block.
type HuntTarget struct {
	ID        string   `json:"id"`
	Subsystem string   `json:"subsystem"`
	Paths     []string `json:"paths"`
	Threat    string   `json:"threat"`
	CWEClass  string   `json:"cwe_class"`
	Priority  string   `json:"priority"`
}

var jsonFence = regexp.MustCompile("(?s)```json\\s*(.*?)```")
var jsonArray = regexp.MustCompile(`(?s)\[\s*\{.*\}\s*\]`)

// ParseHuntTargets extracts the Hunt-targets JSON array from threat_model.md
// text. It tries a ```json fence first, then a greedy [ ... ] array; an object
// must carry "paths" or "subsystem" to count. Parse failure returns nil (the
// caller falls back to recon partitions — degrade visibly, never crash).
func ParseHuntTargets(text string) []HuntTarget {
	text = NormalizeText(text)
	candidates := []string{}
	if m := jsonFence.FindStringSubmatch(text); m != nil {
		candidates = append(candidates, m[1])
	}
	if m := jsonArray.FindString(text); m != "" {
		candidates = append(candidates, m)
	}
	for _, c := range candidates {
		var raw []map[string]json.RawMessage
		if err := json.Unmarshal([]byte(strings.TrimSpace(c)), &raw); err != nil {
			continue
		}
		var out []HuntTarget
		for _, obj := range raw {
			_, hasPaths := obj["paths"]
			_, hasSub := obj["subsystem"]
			if !hasPaths && !hasSub {
				continue
			}
			var ht HuntTarget
			b, _ := json.Marshal(obj)
			_ = json.Unmarshal(b, &ht)
			out = append(out, ht)
		}
		if len(out) > 0 {
			return out
		}
	}
	return nil
}
