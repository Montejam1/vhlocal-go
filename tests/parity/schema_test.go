package parity

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// C-X1 (feature 006, FR additive schema): scan_meta.json keeps every declared
// top-level key (nothing removed or renamed), and the feature-006 fields are
// populated/serialized additively.
func TestScanMetaAdditiveSchema(t *testing.T) {
	results, _ := runTranscript(t)
	b, err := os.ReadFile(filepath.Join(results, "scan_meta.json"))
	if err != nil {
		t.Fatalf("read scan_meta.json: %v", err)
	}
	var m map[string]any
	if json.Unmarshal(b, &m) != nil {
		t.Fatal("scan_meta.json invalid")
	}
	// Stable, pre-006 keys that must never be removed or renamed.
	core := []string{
		"repo", "model", "host", "backend", "engine_version",
		"phases_requested", "phases_completed", "agents", "usage",
		"started_at", "finished_at", "scan_tag", "quality_strictness",
		"max_partitions", "git_commit",
	}
	for _, k := range core {
		if _, ok := m[k]; !ok {
			t.Errorf("scan_meta.json is missing declared key %q (schema must be additive)", k)
		}
	}
	// Feature 006 additive fields: US1 partition resolution is always recorded.
	for _, k := range []string{"partition_source", "partitions"} {
		if _, ok := m[k]; !ok {
			t.Errorf("scan_meta.json missing feature-006 partition field %q", k)
		}
	}
	// omitempty additive fields must, when present, carry the right shape.
	for _, k := range []string{"artifact_errors", "endpoint_failures", "coverage_uncovered_remaining"} {
		if v, ok := m[k]; ok && v != nil {
			if _, isArr := v.([]any); !isArr {
				t.Errorf("additive field %q must be a JSON array when present, got %T", k, v)
			}
		}
	}
}
