package engine

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// resumeCompatibility compares the current scan spec against the config recorded by
// the prior run in this results directory (feature 013, FR-022). It returns a
// non-empty reason when a changed setting would invalidate the saved deliverables,
// so the caller can discard stale work and replan rather than silently reuse it.
//
// Only settings that change WHAT a deliverable would contain are invalidating:
// model/backend (provenance + content), phase2_mode and max_partitions and
// hunt_samples (hunt plan shape), threat_model (whether 1t exists), and
// quality_strictness (verification gate). Changing the requested phase SET is not
// invalidating on its own — resume may legitimately add phases.
func resumeCompatibility(spec ScanSpec) string {
	b, err := os.ReadFile(filepath.Join(spec.ResultsDir, ScanMetaFile))
	if err != nil {
		return "" // no prior run to be incompatible with
	}
	var prior map[string]any
	if json.Unmarshal(b, &prior) != nil {
		return "" // unreadable prior meta — treat as no constraint (fresh run proceeds)
	}
	var diffs []string
	check := func(field, was, now string) {
		if was != "" && was != now {
			diffs = append(diffs, fmt.Sprintf("%s (was %q, now %q)", field, was, now))
		}
	}
	str := func(k string) string { s, _ := prior[k].(string); return s }
	num := func(k string) float64 { f, _ := prior[k].(float64); return f }
	boolOf := func(k string) bool { v, _ := prior[k].(bool); return v }

	check("model", str("model"), spec.Model)
	check("backend", str("backend"), spec.Backend)
	priorMode := str("phase2_mode")
	nowMode := "split"
	if strings.EqualFold(spec.Phase2Mode, "combined") {
		nowMode = "combined"
	}
	check("phase2_mode", priorMode, nowMode)
	check("quality_strictness", str("quality_strictness"), spec.QualityStrictness)
	// Feature 015 (C-C7): a different verifier invalidates saved 2b decisions.
	check("verify_model", str("verify_model"), spec.VerifyModel)
	check("verify_backend", str("verify_backend"), spec.VerifyBackend)
	check("verify_host", str("verify_host"), spec.VerifyHost)
	if mp := int(num("max_partitions")); mp != 0 && mp != spec.MaxPartitions {
		diffs = append(diffs, fmt.Sprintf("max_partitions (was %d, now %d)", mp, spec.MaxPartitions))
	}
	if hs := int(num("hunt_samples")); hs != 0 && hs != spec.HuntSamples {
		diffs = append(diffs, fmt.Sprintf("hunt_samples (was %d, now %d)", hs, spec.HuntSamples))
	}
	if _, ok := prior["threat_model"]; ok && boolOf("threat_model") != spec.ThreatModel {
		diffs = append(diffs, fmt.Sprintf("threat_model (was %v, now %v)", boolOf("threat_model"), spec.ThreatModel))
	}
	if len(diffs) == 0 {
		return ""
	}
	return "incompatible settings changed since the prior run: " + strings.Join(diffs, "; ")
}
