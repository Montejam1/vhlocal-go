package reports

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"vhlocal/internal/threatmodel"
)

// Material availability states (feature 007, FR-018). A finished results dir has
// no "pending" state; that is a live-run concern.
const (
	MatNotRequested     = "not_requested"
	MatAvailable        = "available"
	MatMissing          = "missing"
	MatUnreadable       = "unreadable"
	MatMalformed        = "malformed"
	MatGenerationFailed = "generation_failed"
)

// Material is one artifact's availability, with a relative path when available.
type Material struct {
	State string `json:"state"`
	Path  string `json:"path,omitempty"`
	// Diagram is the validated-diagram sub-state of threat_model.md (feature 015,
	// C-A14): narrative availability and diagram validity are separate facts.
	Diagram *DiagramState `json:"diagram,omitempty"`
}

// MaterialFor returns the availability of a named artifact in a results dir.
// Supported artifacts: "threat_model.md" (text) and "sbom.cdx.json" (JSON).
func MaterialFor(dir, artifact string, requested bool) Material {
	if artifact == "sbom.cdx.json" {
		return sbomState(dir, requested)
	}
	if artifact == "threat_model.md" {
		return threatModelState(dir, requested)
	}
	return classifyText(filepath.Join(dir, artifact), artifact, requested)
}

// threatModelState classifies threat_model.md. `requested` says whether Phase 1t
// was requested (so a missing file reads as missing, not not_requested).
func threatModelState(dir string, requested bool) Material {
	m := classifyText(filepath.Join(dir, "threat_model.md"), "threat_model.md", requested)
	if m.State == MatAvailable {
		m.Diagram = diagramState(dir)
	}
	return m
}

// sbomState classifies sbom.cdx.json (SBOM is produced within Phase 1t, so it
// shares the 1t "requested" signal — research R2).
func sbomState(dir string, requested bool) Material {
	path := filepath.Join(dir, "sbom.cdx.json")
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return notRequestedOrMissing(requested)
		}
		return Material{State: MatUnreadable}
	}
	if len(strings.TrimSpace(string(b))) == 0 {
		return Material{State: MatGenerationFailed}
	}
	var v any
	if json.Unmarshal(b, &v) != nil {
		return Material{State: MatMalformed}
	}
	return Material{State: MatAvailable, Path: "sbom.cdx.json"}
}

func classifyText(path, rel string, requested bool) Material {
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return notRequestedOrMissing(requested)
		}
		return Material{State: MatUnreadable}
	}
	if len(strings.TrimSpace(string(b))) == 0 {
		return Material{State: MatGenerationFailed}
	}
	return Material{State: MatAvailable, Path: rel}
}

func notRequestedOrMissing(requested bool) Material {
	if requested {
		return Material{State: MatMissing}
	}
	return Material{State: MatNotRequested}
}

// Diagram states surfaced with a threat model (mirrors threatmodel.State*; "unknown"
// when the run predates the artifact).
const (
	DiagramUnknown = "unknown"
)

// DiagramState summarizes threat_model_diagram.json for a results dir.
type DiagramState struct {
	State   string   `json:"state"`             // valid | repaired | invalid | unsupported | missing | unknown
	Errors  []string `json:"errors,omitempty"`  // "line N: CODE message" of the worst diagram
	Summary string   `json:"summary,omitempty"` // one-line operator statement
	Count   int      `json:"count,omitempty"`   // diagrams found
}

// diagramState reads the artifact written by the engine; absent ⇒ unknown.
func diagramState(dir string) *DiagramState {
	art, err := threatmodel.Load(dir)
	if err != nil {
		return &DiagramState{State: DiagramUnknown}
	}
	ds := &DiagramState{State: threatmodel.StateValid, Summary: art.Summary(), Count: len(art.Diagrams)}
	rank := map[string]int{threatmodel.StateValid: 0, threatmodel.StateRepaired: 1, threatmodel.StateMissing: 2, threatmodel.StateUnsupported: 3, threatmodel.StateInvalid: 4}
	for _, d := range art.Diagrams {
		if rank[d.State] > rank[ds.State] {
			ds.State = d.State
		}
		for _, e := range d.Errors {
			ds.Errors = append(ds.Errors, fmt.Sprintf("line %d: %s %s", e.Line, e.Code, e.Message))
		}
	}
	return ds
}
