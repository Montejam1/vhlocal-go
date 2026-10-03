package reports

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
)

// Additional manifest states (feature 010, US3). The finished-report material
// states in material.go (available/missing/unreadable/malformed/generation_failed/
// not_requested) are reused; these two extend the set the workspace manifest needs.
const (
	// MatUnknownHistorical: an older report that did not record which phases were
	// requested, so we cannot say whether a missing artifact was expected.
	MatUnknownHistorical = "unknown_historical"
	// MatPending is reserved for a live, still-running scan; a finished dir never
	// reports pending (kept here so the state vocabulary is complete).
	MatPending = "pending"
)

// ManifestEntry is one expected artifact's validated availability (FR-027/028).
// "available" means the file exists AND its content validated for its kind — not
// merely that a filename is present.
type ManifestEntry struct {
	Key   string `json:"key"`
	Label string `json:"label"`
	Phase string `json:"phase"`
	State string `json:"state"`
	Path  string `json:"path,omitempty"`
}

type artifactSpec struct {
	key, label, file, phase, kind string // kind: "text" | "json"
}

// manifestArtifacts is the set surfaced from scans/reports/application history,
// each gated on the phase that produces it.
var manifestArtifacts = []artifactSpec{
	{"findings_report", "Findings report", "SCAN_REPORT.md", "4", "text"},
	{"readme", "README", "README.md", "4", "text"},
	{"threat_model", "Threat model", "threat_model.md", "1t", "text"},
	{"sbom", "SBOM", "sbom.cdx.json", "1t", "json"},
	{"verification", "Verification record", "verification_decisions.json", "2b", "json"},
	{"reproduction", "Reproduction material", "phase3_output.md", "3", "text"},
}

// Manifest returns the validated availability of each expected artifact for a
// results dir (feature 010, US3). Availability requires validated content; a
// requested-but-absent artifact is "missing", an unrequested one "not_requested",
// and an artifact whose requested-ness is unrecorded is "unknown_historical".
// Missing optional artifacts never hide the others (FR-029).
func Manifest(dir string) []ManifestEntry {
	requested, known := requestedPhaseSet(dir)
	out := make([]ManifestEntry, 0, len(manifestArtifacts))
	for _, a := range manifestArtifacts {
		st := classifyArtifact(dir, a, requested[a.phase], known)
		out = append(out, ManifestEntry{Key: a.key, Label: a.label, Phase: a.phase, State: st.State, Path: st.Path})
	}
	return out
}

// requestedPhaseSet reads scan_meta.json's phases_requested. known is false when
// the file or the field is absent (an older report), so callers can report
// unknown_historical rather than guessing.
func requestedPhaseSet(dir string) (set map[string]bool, known bool) {
	set = map[string]bool{}
	b, err := os.ReadFile(filepath.Join(dir, "scan_meta.json"))
	if err != nil {
		return set, false
	}
	var meta map[string]any
	if json.Unmarshal(b, &meta) != nil {
		return set, false
	}
	raw, ok := meta["phases_requested"].([]any)
	if !ok {
		return set, false
	}
	for _, p := range raw {
		if s, ok := p.(string); ok {
			set[s] = true
		}
	}
	return set, true
}

func classifyArtifact(dir string, a artifactSpec, requested, requestedKnown bool) Material {
	path := filepath.Join(dir, a.file)
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			switch {
			case !requestedKnown:
				return Material{State: MatUnknownHistorical}
			case requested:
				return Material{State: MatMissing}
			default:
				return Material{State: MatNotRequested}
			}
		}
		return Material{State: MatUnreadable}
	}
	if len(strings.TrimSpace(string(b))) == 0 {
		return Material{State: MatGenerationFailed}
	}
	if a.kind == "json" {
		var v any
		if json.Unmarshal(b, &v) != nil {
			return Material{State: MatMalformed}
		}
	}
	return Material{State: MatAvailable, Path: a.file}
}
