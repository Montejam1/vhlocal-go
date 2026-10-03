package apps

import (
	"fmt"

	"vhlocal/internal/reports"
)

// Selection is one artifact kind's chosen material for an application (feature
// 014, FR-025/026; data-model "ApplicationArtifactSelection"): the newest VALID
// artifact of that kind from this application's own history — never another
// application's — with its originating scan, time and revision, and an explicit
// disclosure when it is older than the latest scan. When nothing valid exists,
// Valid is false and Reason explains why (disabled toggle, malformed file, none).
type Selection struct {
	ScanID          string  `json:"scan_id,omitempty"`
	Created         float64 `json:"created,omitempty"`
	Revision        string  `json:"revision,omitempty"`
	Path            string  `json:"path,omitempty"`
	Valid           bool    `json:"valid"`
	OlderThanLatest bool    `json:"older_than_latest"`
	Reason          string  `json:"reason,omitempty"`
}

// AppArtifacts is the per-kind selection exposed on /api/applications/{slug}.
type AppArtifacts struct {
	ThreatModel Selection `json:"threat_model"`
	Sbom        Selection `json:"sbom"`
	// ThreatModelDiagram (feature 015, C-A14): the newest scan whose threat-model
	// DIAGRAM validates (valid/repaired); independent of the narrative selection.
	ThreatModelDiagram Selection `json:"threat_model_diagram"`
}

// ReasonThreatModelDisabled is the explained absence when the latest scan ran with
// the threat model deliberately off (feature 013 contract).
const ReasonThreatModelDisabled = "threat model disabled for the latest scan"

// selectArtifacts picks, per kind, the newest scan (scans are newest-first and all
// belong to ONE application) whose artifact validates. Invalid material is skipped
// with its state named in the reason rather than substituted or hidden.
func selectArtifacts(scans []reports.Report) AppArtifacts {
	return AppArtifacts{
		ThreatModel:        selectKind(scans, "threat model", func(r reports.Report) reports.Material { return r.ThreatModel }),
		Sbom:               selectKind(scans, "SBOM", func(r reports.Report) reports.Material { return r.Sbom }),
		ThreatModelDiagram: selectKind(scans, "threat model diagram", diagramMaterial),
	}
}

func selectKind(scans []reports.Report, label string, mat func(reports.Report) reports.Material) Selection {
	if len(scans) == 0 {
		return Selection{Reason: "no scans for this application"}
	}
	latest := scans[0]
	var firstBad string // the newest non-valid state seen, for the reason
	for _, r := range scans {
		m := mat(r)
		switch m.State {
		case reports.MatAvailable:
			return Selection{
				ScanID: r.ID, Created: r.Created, Revision: r.GitCommit, Path: m.Path, Valid: true,
				OlderThanLatest: r.ID != latest.ID,
			}
		case reports.MatMalformed, reports.MatGenerationFailed, reports.MatUnreadable, reports.MatMissing:
			if firstBad == "" {
				firstBad = fmt.Sprintf("newest %s in %s is %s", label, r.ID, m.State)
			}
		}
	}
	sel := Selection{}
	switch {
	case latest.ThreatModelDisabled:
		sel.Reason = ReasonThreatModelDisabled
		if firstBad != "" {
			sel.Reason += "; " + firstBad + "; no valid " + label + " in this application's history"
		}
	case firstBad != "":
		sel.Reason = firstBad + "; no valid " + label + " in this application's history"
	default:
		sel.Reason = "no " + label + " in this application's history"
	}
	return sel
}

// diagramMaterial projects the diagram sub-state as a Material so the same
// newest-valid rule applies: valid/repaired ⇒ available; invalid/unsupported ⇒
// malformed (skipped, named); unknown (pre-015) ⇒ missing; no narrative ⇒ as is.
func diagramMaterial(r reports.Report) reports.Material {
	m := r.ThreatModel
	if m.State != reports.MatAvailable || m.Diagram == nil {
		return m
	}
	switch m.Diagram.State {
	case "valid", "repaired":
		return reports.Material{State: reports.MatAvailable, Path: "threat_model_diagram.json", Diagram: m.Diagram}
	case "invalid", "unsupported":
		return reports.Material{State: reports.MatMalformed, Diagram: m.Diagram}
	}
	return reports.Material{State: reports.MatMissing, Diagram: m.Diagram}
}
