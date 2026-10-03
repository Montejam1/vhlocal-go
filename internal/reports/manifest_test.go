package reports

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// writeScan writes a minimal results dir with the given scan_meta and files.
func writeScan(t *testing.T, meta map[string]any, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	mb, _ := json.MarshalIndent(meta, "", "  ")
	if err := os.WriteFile(filepath.Join(dir, "scan_meta.json"), mb, 0o644); err != nil {
		t.Fatal(err)
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func entry(m []ManifestEntry, key string) ManifestEntry {
	for _, e := range m {
		if e.Key == key {
			return e
		}
	}
	return ManifestEntry{}
}

// T024 (FR-027/028): availability requires validated content; requested-but-absent
// is missing; unrequested is not_requested; missing optional artifacts don't hide others.
func TestManifestValidatedStates(t *testing.T) {
	dir := writeScan(t, map[string]any{
		"phases_requested": []any{"1", "1t", "2", "4"}, // note: 2b, 3 NOT requested
	}, map[string]string{
		"SCAN_REPORT.md":  "# Report\n", // available
		"threat_model.md": "",           // requested (1t) but empty → generation_failed
		"sbom.cdx.json":   "{not json",  // malformed
		// README.md (phase 4) requested but absent → missing
		// verification_decisions.json (2b) not requested → not_requested
		// phase3_output.md (3) not requested → not_requested
	})
	m := Manifest(dir)
	if got := entry(m, "findings_report").State; got != MatAvailable {
		t.Errorf("findings_report=%s want available", got)
	}
	if got := entry(m, "threat_model").State; got != MatGenerationFailed {
		t.Errorf("threat_model=%s want generation_failed", got)
	}
	if got := entry(m, "sbom").State; got != MatMalformed {
		t.Errorf("sbom=%s want malformed", got)
	}
	if got := entry(m, "readme").State; got != MatMissing {
		t.Errorf("readme=%s want missing (phase 4 requested, file absent)", got)
	}
	if got := entry(m, "verification").State; got != MatNotRequested {
		t.Errorf("verification=%s want not_requested", got)
	}
	if got := entry(m, "reproduction").State; got != MatNotRequested {
		t.Errorf("reproduction=%s want not_requested", got)
	}
}

// T024: an older report without phases_requested reports unknown_historical for
// absent artifacts rather than guessing.
func TestManifestUnknownHistorical(t *testing.T) {
	dir := writeScan(t, map[string]any{"repo": "/r/x"}, map[string]string{
		"SCAN_REPORT.md": "# Report\n",
	})
	m := Manifest(dir)
	if got := entry(m, "findings_report").State; got != MatAvailable {
		t.Errorf("present artifact should still be available: %s", got)
	}
	if got := entry(m, "sbom").State; got != MatUnknownHistorical {
		t.Errorf("absent artifact with no phases_requested = %s, want unknown_historical", got)
	}
}
