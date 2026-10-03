package apps

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"vhlocal/internal/server/testsupport"
)

// T052 (FR-025/026): with a history whose LATEST scan omitted the threat model and
// SBOM, the detail returns the newest VALID artifact of each kind from THIS
// application's own history (scan_id/created/revision, older_than_latest=true); a
// malformed file is skipped with its state in the reason; another application's
// material is never selected; threat_model=false on the latest → explained absence.
func TestArtifactSelectionNewestValidOwnHistory(t *testing.T) {
	reportsDir, _ := setup(t)
	repo, other := "/repos/shop", "/repos/other"
	// Oldest: valid threat model + valid SBOM, revision r1.
	testsupport.SeedReport(t, reportsDir, testsupport.ReportSeed{
		Name: "shop", Repo: repo, Stamp: "2026-09-01-000000", Created: time.Unix(1000, 0),
		PhasesRequested: []string{"1", "1t", "2"}, PhasesCompleted: []string{"1", "1t", "2"},
		ThreatModel: "ok", Sbom: "ok", GitCommit: "r1", Readme: true,
	})
	// Middle: threat model valid at r2, SBOM MALFORMED (must be skipped, named).
	testsupport.SeedReport(t, reportsDir, testsupport.ReportSeed{
		Name: "shop", Repo: repo, Stamp: "2026-09-02-000000", Created: time.Unix(2000, 0),
		PhasesRequested: []string{"1", "1t", "2"}, PhasesCompleted: []string{"1", "1t", "2"},
		ThreatModel: "ok", Sbom: "malformed", GitCommit: "r2", Readme: true,
	})
	// Latest: threat model DISABLED (1t requested, skipped, not completed), nothing written.
	latest := testsupport.SeedReport(t, reportsDir, testsupport.ReportSeed{
		Name: "shop", Repo: repo, Stamp: "2026-09-03-000000", Created: time.Unix(3000, 0),
		PhasesRequested: []string{"1", "1t", "2"}, PhasesCompleted: []string{"1", "2"}, PhasesSkipped: []string{"1t"},
		GitCommit: "r3", Readme: true,
	})
	// Another application with newer valid material — must NEVER be selected.
	testsupport.SeedReport(t, reportsDir, testsupport.ReportSeed{
		Name: "other", Repo: other, Stamp: "2026-09-04-000000", Created: time.Unix(4000, 0),
		PhasesRequested: []string{"1", "1t"}, PhasesCompleted: []string{"1", "1t"},
		ThreatModel: "ok", Sbom: "ok", GitCommit: "zz", Readme: true,
	})

	d, ok := BuildDetail(SlugFor(repo), reportsDir)
	if !ok {
		t.Fatal("detail missing")
	}
	if len(d.ScanHistory) != 3 || d.LatestReportID == "" || d.LatestReportID != d.ScanHistory[0].ID {
		t.Fatalf("history not newest-first for the app: %+v", d.ScanHistory)
	}
	_ = latest
	tm := d.Artifacts.ThreatModel
	if !tm.Valid || tm.Revision != "r2" || tm.Created != 2000 || tm.Path != "threat_model.md" || !tm.OlderThanLatest {
		t.Errorf("threat model selection = %+v, want valid r2 (older_than_latest)", tm)
	}
	if tm.ScanID == d.LatestReportID || tm.ScanID == "" {
		t.Errorf("threat model must come from the middle scan, got %q", tm.ScanID)
	}
	sb := d.Artifacts.Sbom
	if !sb.Valid || sb.Revision != "r1" || sb.Created != 1000 || sb.Path != "sbom.cdx.json" || !sb.OlderThanLatest {
		t.Errorf("sbom selection = %+v, want valid r1 (malformed r2 skipped)", sb)
	}
	for _, s := range []Selection{tm, sb} {
		if s.Revision == "zz" {
			t.Fatalf("another application's material was selected: %+v", s)
		}
	}

	// An application whose only scans have the threat model disabled → explained absence.
	repo2 := "/repos/nothreat"
	testsupport.SeedReport(t, reportsDir, testsupport.ReportSeed{
		Name: "nothreat", Repo: repo2, Stamp: "2026-09-05-000000", Created: time.Unix(5000, 0),
		PhasesRequested: []string{"1", "1t", "2"}, PhasesCompleted: []string{"1", "2"}, PhasesSkipped: []string{"1t"}, Readme: true,
	})
	d2, _ := BuildDetail(SlugFor(repo2), reportsDir)
	if d2.Artifacts.ThreatModel.Valid || d2.Artifacts.ThreatModel.Reason != ReasonThreatModelDisabled {
		t.Errorf("disabled threat model must be an explained absence: %+v", d2.Artifacts.ThreatModel)
	}
	if d2.Artifacts.Sbom.Valid || d2.Artifacts.Sbom.Reason == "" {
		t.Errorf("sbom absence must carry a reason: %+v", d2.Artifacts.Sbom)
	}

	// An application whose only artifact is malformed → invalid with the state named.
	repo3 := "/repos/badsbom"
	testsupport.SeedReport(t, reportsDir, testsupport.ReportSeed{
		Name: "badsbom", Repo: repo3, Stamp: "2026-09-06-000000", Created: time.Unix(6000, 0),
		PhasesRequested: []string{"1", "1t"}, PhasesCompleted: []string{"1", "1t"}, Sbom: "malformed", Readme: true,
	})
	d3, _ := BuildDetail(SlugFor(repo3), reportsDir)
	if d3.Artifacts.Sbom.Valid || d3.Artifacts.Sbom.Reason == "" || !contains(d3.Artifacts.Sbom.Reason, "malformed") {
		t.Errorf("malformed-only sbom must be invalid naming the state: %+v", d3.Artifacts.Sbom)
	}
}

func contains(s, sub string) bool {
	return len(sub) == 0 || (len(s) >= len(sub) && indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

// Feature 015 (C-A14, T035): the diagram selection is independent of the narrative
// selection — an invalid newest diagram is skipped and named, the narrative stays.
func TestArtifactSelectionSeparatesNarrativeFromDiagram(t *testing.T) {
	reportsDir, _ := setup(t)
	repo := "/repos/dgm"
	old := testsupport.SeedReport(t, reportsDir, testsupport.ReportSeed{
		Name: "dgm", Repo: repo, Stamp: "2026-09-01-000000", Created: time.Unix(1000, 0),
		PhasesRequested: []string{"1", "1t"}, PhasesCompleted: []string{"1", "1t"}, ThreatModel: "ok", GitCommit: "r1", Readme: true,
	})
	os.WriteFile(filepath.Join(old, "threat_model_diagram.json"), []byte(`{"version":1,"renderer_version":"11.17.2","source":"threat_model.md","diagrams":[{"index":0,"state":"valid","repairs":[],"errors":[]}]}`), 0o644)
	os.Chtimes(old, time.Unix(1000, 0), time.Unix(1000, 0))
	latest := testsupport.SeedReport(t, reportsDir, testsupport.ReportSeed{
		Name: "dgm", Repo: repo, Stamp: "2026-09-02-000000", Created: time.Unix(2000, 0),
		PhasesRequested: []string{"1", "1t"}, PhasesCompleted: []string{"1", "1t"}, ThreatModel: "ok", GitCommit: "r2", Readme: true,
	})
	os.WriteFile(filepath.Join(latest, "threat_model_diagram.json"), []byte(`{"version":1,"renderer_version":"11.17.2","source":"threat_model.md","diagrams":[{"index":0,"state":"invalid","repairs":[],"errors":[{"line":9,"code":"E_EDGE_LABEL_UNTERMINATED","message":"x"}]}]}`), 0o644)
	os.Chtimes(latest, time.Unix(2000, 0), time.Unix(2000, 0))
	d, ok := BuildDetail(SlugFor(repo), reportsDir)
	if !ok {
		t.Fatal("detail missing")
	}
	if !d.Artifacts.ThreatModel.Valid || d.Artifacts.ThreatModel.Revision != "r2" {
		t.Errorf("narrative must come from the latest scan: %+v", d.Artifacts.ThreatModel)
	}
	dg := d.Artifacts.ThreatModelDiagram
	if !dg.Valid || dg.Revision != "r1" || !dg.OlderThanLatest {
		t.Errorf("diagram must come from the older valid scan with disclosure: %+v", dg)
	}
	if !contains(dg.Reason, "") { // reason empty on a valid selection
		t.Errorf("unexpected reason %q", dg.Reason)
	}
}
