// Package remediation writes per-finding remediation DTOs (report-only) when
// --remediate is set: remediation/<VULN>/{remediate.json,summary.md} plus an
// index.json. Deterministic, derived from the engine-built findings.
//
// The advice itself comes from internal/guidance, the same reviewed table the report
// renders from, so a remediation record and the report cannot disagree about what to do
// (feature 016, T050, C-R13).
package remediation

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"vhlocal/internal/guidance"
)

// DTO is one finding's remediation record.
type DTO struct {
	ID       string `json:"id"`
	Title    string `json:"title"`
	CWE      string `json:"cwe"`
	Location string `json:"location"`
	Severity string `json:"severity"`
	Fix      string `json:"fix"`
	Guidance string `json:"guidance"`
	// GuidanceProvenance is recorded | general | investigate (feature 016, FR-014).
	GuidanceProvenance string `json:"guidance_provenance"`
	// RequiresDecision names the policy or invariant the records cannot establish.
	RequiresDecision string `json:"requires_decision,omitempty"`
}

// FindingView is the minimal finding data remediation needs (avoids importing
// consolidate to keep this leaf-package dependency-light).
type FindingView struct {
	ID, Title, CWE, Location, Severity, Fix, CanonicalName string
	Duplicate                                              bool
}

// Write emits the remediation tree into resultsDir and returns the count written.
func Write(resultsDir string, findings []FindingView) (int, error) {
	root := filepath.Join(resultsDir, "remediation")
	if err := os.MkdirAll(root, 0o755); err != nil {
		return 0, err
	}
	var index []map[string]string
	n := 0
	for _, f := range findings {
		if f.Duplicate {
			continue
		}
		dir := filepath.Join(root, f.ID)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return n, err
		}
		rec := resolve(f)
		dto := DTO{
			ID: f.ID, Title: f.Title, CWE: f.CWE, Location: f.Location, Severity: f.Severity,
			Fix: f.Fix, Guidance: guidanceText(rec), GuidanceProvenance: rec.Provenance,
			RequiresDecision: rec.MissingDecision,
		}
		b, _ := json.MarshalIndent(dto, "", "  ")
		if err := os.WriteFile(filepath.Join(dir, "remediate.json"), b, 0o644); err != nil {
			return n, err
		}
		summary := fmt.Sprintf("# Remediation — %s\n\n**%s** (%s) at `%s`\n\n%s\n",
			f.ID, f.Title, f.Severity, f.Location, dto.Guidance)
		if err := os.WriteFile(filepath.Join(dir, "summary.md"), []byte(summary), 0o644); err != nil {
			return n, err
		}
		index = append(index, map[string]string{"id": f.ID, "path": filepath.Join("remediation", f.ID)})
		n++
	}
	ib, _ := json.MarshalIndent(map[string]any{"count": n, "entries": index}, "", "  ")
	if err := os.WriteFile(filepath.Join(root, "index.json"), ib, 0o644); err != nil {
		return n, err
	}
	return n, nil
}

// resolve asks the reviewed guidance table what to do about this finding. The previous
// implementation answered "validate/encode untrusted input at the sink" for every weakness,
// which is wrong for most of them (C-R5, C-R13).
func resolve(f FindingView) guidance.Recommendation {
	return guidance.Resolve(guidance.Request{
		CWE: f.CWE, CanonicalName: f.CanonicalName, RecordedFix: f.Fix,
	})
}

// guidanceText renders one resolved recommendation as the DTO's guidance prose. It always
// discloses where the advice came from and that nothing has been implemented or tested.
func guidanceText(rec guidance.Recommendation) string {
	var b strings.Builder
	b.WriteString(rec.Label + "\n")
	for i, s := range rec.Steps {
		fmt.Fprintf(&b, "\n%d. %s", i+1, s)
	}
	if rec.MissingDecision != "" {
		fmt.Fprintf(&b, "\n\nDecision this needs from the application owner: %s.", rec.MissingDecision)
	}
	if rec.RecordedNote != "" {
		fmt.Fprintf(&b, "\n\nRecorded recommendation, kept for reference: %s", rec.RecordedNote)
	}
	if len(rec.Checks) > 0 {
		b.WriteString("\n\nSuggested checks (none has been run):")
		for _, c := range rec.Checks {
			fmt.Fprintf(&b, "\n- %s", c)
		}
	}
	return b.String()
}
