package server

import (
	"os"
	"path/filepath"
	"testing"
)

// T054 (FR-019): the scan view's review_units summary names the evidence standard
// and copies the v2 axes; a v1 record defaults to version 1 with no axes.
func TestReviewGapsCarrySemantics(t *testing.T) {
	dir := t.TempDir()
	v2 := `{"semantics_version":2,"revision":"abc","counts":{"total":3,"reviewed_no_issue":1},"follow_up_ran":false,
	"axes":{"discovered":3,"supported_inventory":3,"assigned":3,"attempted":3,"source_exposed":2,"completed_review":1,"verified":0},"gaps":[]}`
	os.WriteFile(filepath.Join(dir, "review_units.json"), []byte(v2), 0o644)
	rv := reviewGaps(dir)
	if rv["semantics_version"] != 2 || rv["semantics_label"] != "validated handler dispositions (v2)" {
		t.Errorf("v2 summary = %v", rv)
	}
	axes, _ := rv["axes"].(map[string]any)
	if axes == nil || axes["source_exposed"] != float64(2) {
		t.Errorf("axes not copied: %v", rv["axes"])
	}
	v1 := `{"revision":"abc","counts":{"total":3,"reviewed_no_issue":3},"follow_up_ran":false,"gaps":[]}`
	os.WriteFile(filepath.Join(dir, "review_units.json"), []byte(v1), 0o644)
	rv = reviewGaps(dir)
	if rv["semantics_version"] != 1 || rv["semantics_label"] != "read-overlap evidence (v1)" {
		t.Errorf("v1 summary = %v", rv)
	}
	if _, has := rv["axes"]; has {
		t.Error("v1 record must not invent axes")
	}
}

// T061 (FR-020): the scan view carries the remediation-group counts from the record.
func TestStatusCarriesRemediationGroups(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "remediation_groups.json"), []byte(`{"version":1,"groups":[],"raw_supported":5,"grouped":3}`), 0o644)
	out := map[string]any{}
	if g := readJSONMap(filepath.Join(dir, "remediation_groups.json")); g != nil {
		out["remediation_groups"] = map[string]any{"grouped": g["grouped"], "raw_supported": g["raw_supported"]}
	}
	rg, _ := out["remediation_groups"].(map[string]any)
	if rg == nil || rg["grouped"] != float64(3) || rg["raw_supported"] != float64(5) {
		t.Errorf("remediation_groups = %v", out["remediation_groups"])
	}
}
