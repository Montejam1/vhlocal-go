package server

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"vhlocal/internal/reports"
)

// phaseLabels maps phase keys to human labels for the step tracker.
var phaseLabels = map[string]string{
	"1": "Recon", "1t": "Threat model", "2": "Hunt", "2b": "Verify",
	"3": "Reproduce", "3d": "Sweep", "4": "Report",
}

// scanStatus reads a results dir and returns the truthful engine status axes and
// per-phase outcomes (feature 007, US3). These are DISTINCT from the queue job
// status: a terminated job may still be execution=partial. Returns nil when the
// results dir has no readable status yet (queue-only view).
func scanStatus(resultsDir string) map[string]any {
	if resultsDir == "" {
		return nil
	}
	meta := readJSONMap(filepath.Join(resultsDir, "scan_meta.json"))
	doc := readJSONMap(filepath.Join(resultsDir, "findings.json"))
	if meta == nil && doc == nil {
		return nil
	}
	out := map[string]any{}
	var reasons []string
	if rs, ok := doc["run_status"].(map[string]any); ok {
		out["execution_status"] = rs["execution_status"]
		out["coverage_status"] = rs["coverage_status"]
		out["validation_mode"] = rs["validation_mode"]
		out["coverage_degraded_reasons"] = rs["coverage_degraded_reasons"]
		reasons = toStrings(rs["coverage_degraded_reasons"])
		// Feature 014 (FR-021): the same completion block the report renders —
		// read from the record, never recomputed here. Absent for older runs.
		if oc, ok := rs["outcome"]; ok && oc != nil {
			out["outcome"] = oc
		}
	}
	// Feature 014 (FR-016): unreviewed units and their reasons, from review_units.json.
	if rv := reviewGaps(resultsDir); rv != nil {
		out["review_units"] = rv
	}
	// Feature 015: additive record presence/state so viewers can pick the model-driven
	// path (report_model.json), show the diagram state and the coverage semantics
	// label without recomputing anything.
	out["report_model_present"] = fileExists(filepath.Join(resultsDir, "report_model.json"))
	// Feature 016 (FR-021, T076): the reader-facing separation, passed through verbatim
	// from the persisted projection so the scan view can distinguish issues to fix, items
	// that need review and scanner diagnostics. Nothing here is recomputed: a count the
	// projection does not carry is simply absent.
	if ps := presentationSummary(resultsDir); ps != nil {
		out["presentation"] = ps
	}
	if dg := readJSONMap(filepath.Join(resultsDir, "threat_model_diagram.json")); dg != nil {
		out["diagram"] = diagramSummary(dg)
	}
	if g := readJSONMap(filepath.Join(resultsDir, "remediation_groups.json")); g != nil {
		out["remediation_groups"] = map[string]any{"grouped": g["grouped"], "raw_supported": g["raw_supported"]}
	}
	if ru := readJSONMap(filepath.Join(resultsDir, "review_units.json")); ru != nil {
		v, _ := ru["semantics_version"].(float64)
		if v == 0 {
			v = 1
		}
		out["coverage_semantics"] = int(v)
	}
	out["phase_outcomes"] = phaseOutcomes(meta, reasons)
	// Explicit material availability for the scan view (FR-017/018). Threat/SBOM
	// are gated on Phase 1t; a missing artifact reads as "missing" only if requested.
	req1t := toStringSet(meta["phases_requested"])["1t"]
	out["threat_model"] = reports.MaterialFor(resultsDir, "threat_model.md", req1t)
	out["sbom"] = reports.MaterialFor(resultsDir, "sbom.cdx.json", req1t)
	return out
}

// presentationSummary reads the persisted presentation projection and returns its counts
// unchanged, plus the length of the two separated lists. It returns nil for a report saved
// before feature 016, which carries no projection.
func presentationSummary(resultsDir string) map[string]any {
	rm := readJSONMap(filepath.Join(resultsDir, "report_model.json"))
	if rm == nil {
		return nil
	}
	pres, ok := rm["presentation"].(map[string]any)
	if !ok || pres == nil {
		return nil
	}
	out := map[string]any{"version": pres["version"]}
	if c, ok := pres["counts"].(map[string]any); ok {
		// Verbatim: the same keys the projection wrote, with no arithmetic applied.
		out["counts"] = c
	}
	if items, ok := pres["review_items"].([]any); ok {
		out["review_items"] = len(items)
	}
	if items, ok := pres["dismissed"].([]any); ok {
		out["dismissed"] = len(items)
	}
	if items, ok := pres["issues"].([]any); ok {
		out["issues"] = len(items)
	}
	if notes, ok := pres["grouping_notes"].([]any); ok && len(notes) > 0 {
		out["grouping_notes"] = len(notes)
	}
	return out
}

// phaseOutcomes derives one row per requested phase from engine facts — never from
// the queue status or the current phase index (constitution II; CB-1/CB-2).
func phaseOutcomes(meta map[string]any, reasons []string) []map[string]any {
	requested := toStrings(meta["phases_requested"])
	completed := toStringSet(meta["phases_completed"])
	skipped := toStringSet(meta["phases_skipped"])
	reasonByPhase := phaseReasons(reasons)
	var out []map[string]any
	for _, p := range requested {
		row := map[string]any{
			"phase": p, "label": labelFor(p), "requested": true,
			"completed": completed[p], "produced": completed[p],
		}
		if !completed[p] {
			switch {
			case skipped[p]:
				row["reason"] = "skipped"
			case reasonByPhase[p] != "":
				row["reason"] = reasonByPhase[p]
			default:
				row["reason"] = "did not complete"
			}
		}
		out = append(out, row)
	}
	return out
}

// phaseReasons extracts per-phase reasons from coverage_degraded_reasons entries
// shaped like "phase 3: <reason>" — keeps the first reason seen per phase key.
func phaseReasons(reasons []string) map[string]string {
	out := map[string]string{}
	for _, r := range reasons {
		if !strings.HasPrefix(r, "phase ") {
			continue
		}
		rest := r[len("phase "):]
		i := strings.IndexByte(rest, ':')
		if i <= 0 {
			continue
		}
		key := strings.TrimSpace(rest[:i])
		if _, seen := out[key]; !seen {
			out[key] = strings.TrimSpace(rest[i+1:])
		}
	}
	return out
}

func labelFor(p string) string {
	if l, ok := phaseLabels[p]; ok {
		return l
	}
	return p
}

func readJSONMap(path string) map[string]any {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var m map[string]any
	if json.Unmarshal(b, &m) != nil {
		return nil
	}
	return m
}

func toStrings(v any) []string {
	arr, _ := v.([]any)
	var out []string
	for _, e := range arr {
		if s, ok := e.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func toStringSet(v any) map[string]bool {
	out := map[string]bool{}
	for _, s := range toStrings(v) {
		out[s] = true
	}
	return out
}

// enrichScan augments a job's public map with the engine status axes + phase
// outcomes read from its results dir, keeping queue `status` intact and distinct.
func enrichScan(m map[string]any) map[string]any {
	dir, _ := m["results_dir"].(string)
	if st := scanStatus(dir); st != nil {
		for k, v := range st {
			m[k] = v
		}
	}
	return m
}

// reviewGaps summarizes review_units.json for the scan view (feature 014, FR-016):
// the disposition counts plus every unreviewed entry point with its reason. It reads
// the persisted record only — the dashboard's existing metrics are untouched.
// Returns nil when the run has no review-unit record (pre-014 scans).
func reviewGaps(resultsDir string) map[string]any {
	ru := readJSONMap(filepath.Join(resultsDir, "review_units.json"))
	if ru == nil {
		return nil
	}
	v, _ := ru["semantics_version"].(float64)
	if v == 0 {
		v = 1
	}
	label := "read-overlap evidence (v1)"
	if v >= 2 {
		label = "validated handler dispositions (v2)"
	}
	out := map[string]any{
		"revision":      ru["revision"],
		"counts":        ru["counts"],
		"follow_up_ran": ru["follow_up_ran"],
		// Feature 015 (FR-019): the evidence standard and the independent axes
		// (absent for v1 records) — copied, never recomputed.
		"semantics_version": int(v),
		"semantics_label":   label,
	}
	if axes, ok := ru["axes"].(map[string]any); ok {
		out["axes"] = axes
	}
	gaps, _ := ru["gaps"].([]any)
	if gaps == nil {
		gaps = []any{}
	}
	out["unreviewed"] = gaps
	return out
}

// diagramSummary reduces threat_model_diagram.json to what the scan view needs:
// per-diagram state plus the first error, never the full structure.
func diagramSummary(dg map[string]any) map[string]any {
	out := map[string]any{"renderer_version": dg["renderer_version"]}
	var states []any
	for _, d := range toAnySlice(dg["diagrams"]) {
		m, _ := d.(map[string]any)
		if m == nil {
			continue
		}
		s := map[string]any{"index": m["index"], "state": m["state"]}
		if errs := toAnySlice(m["errors"]); len(errs) > 0 {
			s["error"] = errs[0]
		}
		states = append(states, s)
	}
	if states == nil {
		states = []any{}
	}
	out["diagrams"] = states
	return out
}

func toAnySlice(v any) []any {
	s, _ := v.([]any)
	return s
}

func fileExists(p string) bool { _, err := os.Stat(p); return err == nil }
