package apps

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"vhlocal/internal/server/testsupport"
)

// setup points the registry/ledger dir at a temp location and returns a temp
// reports dir; both are isolated per test.
func setup(t *testing.T) (reportsDir, ledgerDir string) {
	t.Helper()
	base := t.TempDir()
	ledgerDir = filepath.Join(base, "ledger")
	t.Setenv("VHLOCAL_LEDGER_DIR", ledgerDir)
	reportsDir = filepath.Join(base, "reports")
	if err := os.MkdirAll(reportsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	return reportsDir, ledgerDir
}

// CA-1 (FR-007..011): discovery union incl. ledger-disabled + report-only apps;
// full AppSummary fields; open_findings/ledger_total null when no ledger.
func TestListSummariesDiscoveryUnion(t *testing.T) {
	reportsDir, ledgerDir := setup(t)
	repoA := "/repos/alpha" // ledger-disabled, registered, one report
	repoB := "/repos/bravo" // registered, two reports, has a ledger
	repoC := "/repos/gamma" // report-only, never registered

	// registry: A and B registered (no ledger for A); C intentionally absent.
	if _, err := Register(repoA); err != nil {
		t.Fatal(err)
	}
	if _, err := Register(repoB); err != nil {
		t.Fatal(err)
	}
	testsupport.SeedReport(t, reportsDir, testsupport.ReportSeed{
		Name: "alpha", Repo: repoA, Created: time.Unix(1000, 0),
		Findings:       []map[string]any{{"severity": "High", "classification": "statically_supported"}},
		CoverageStatus: "complete", ThreatModel: "ok", Sbom: "ok", SbomTotal: 21, Readme: true,
	})
	testsupport.SeedReport(t, reportsDir, testsupport.ReportSeed{
		Name: "bravo", Repo: repoB, Stamp: "2026-09-10-000000", Created: time.Unix(2000, 0),
		Findings: []map[string]any{{"severity": "Medium", "classification": "hypothesis"}}, CoverageStatus: "degraded",
	})
	testsupport.SeedReport(t, reportsDir, testsupport.ReportSeed{
		Name: "bravo", Repo: repoB, Stamp: "2026-09-15-000000", Created: time.Unix(3000, 0),
		Findings: []map[string]any{{"severity": "Critical", "classification": "reviewed"}}, CoverageStatus: "complete", Readme: true,
	})
	testsupport.SeedReport(t, reportsDir, testsupport.ReportSeed{
		Name: "gamma", Repo: repoC, Created: time.Unix(1500, 0),
		Findings: []map[string]any{}, CoverageStatus: "complete",
	})
	testsupport.SeedLedger(t, ledgerDir, SlugFor(repoB), repoB, 3)

	list := ListSummaries(reportsDir)
	got := map[string]AppSummary{}
	for _, s := range list {
		got[s.Slug] = s
	}
	for _, repo := range []string{repoA, repoB, repoC} {
		if _, ok := got[SlugFor(repo)]; !ok {
			t.Errorf("app for %s not discovered; got slugs %v", repo, keysOf(got))
		}
	}
	// A: ledger-disabled → open_findings null; has_threat_model/has_sbom true; named.
	a := got[SlugFor(repoA)]
	if a.OpenFindings != nil || a.LedgerTotal != nil {
		t.Errorf("ledger-less app must have null open_findings/ledger_total, got %v/%v", a.OpenFindings, a.LedgerTotal)
	}
	if !a.HasThreatModel || !a.HasSbom || !a.Named || a.Scans != 1 {
		t.Errorf("alpha summary wrong: %+v", a)
	}
	// B: has a ledger → non-null; latest is the newest report (Critical).
	b := got[SlugFor(repoB)]
	if b.OpenFindings == nil || *b.OpenFindings != 3 || b.LedgerTotal == nil || *b.LedgerTotal != 3 {
		t.Errorf("bravo ledger counts wrong: open=%v total=%v", b.OpenFindings, b.LedgerTotal)
	}
	if b.Scans != 2 || b.LatestCoverage != "complete" || b.LatestSeverities["Critical"] != 1 {
		t.Errorf("bravo latest/scan-count wrong: %+v", b)
	}
	// C: report-only, not named.
	c := got[SlugFor(repoC)]
	if c.Named {
		t.Errorf("gamma is report-only and must not be 'named'")
	}
	// Sorted newest-scanned first (B newest report created=3000).
	if len(list) < 1 || list[0].Slug != SlugFor(repoB) {
		t.Errorf("expected bravo first (newest last_scanned), got %v", func() []string { return keysOfList(list) }())
	}
}

// CA-2/CA-3 (FR-010): detail carries scan_history + has_ledger; forget removes
// from the list but preserves reports and detail; re-register un-hides.
func TestDetailAndForget(t *testing.T) {
	reportsDir, ledgerDir := setup(t)
	repo := "/repos/delta"
	if _, err := Register(repo); err != nil {
		t.Fatal(err)
	}
	testsupport.SeedReport(t, reportsDir, testsupport.ReportSeed{
		Name: "delta", Repo: repo, Stamp: "2026-09-01-000000", Created: time.Unix(1000, 0),
		Findings: []map[string]any{{"severity": "High", "classification": "statically_supported"}}, CoverageStatus: "complete", Readme: true,
	})
	testsupport.SeedReport(t, reportsDir, testsupport.ReportSeed{
		Name: "delta", Repo: repo, Stamp: "2026-09-16-000000", Created: time.Unix(2000, 0),
		Findings: []map[string]any{{"severity": "Low", "classification": "hypothesis"}}, CoverageStatus: "degraded", ThreatModel: "ok",
	})
	_ = ledgerDir

	d, ok := BuildDetail(SlugFor(repo), reportsDir)
	if !ok {
		t.Fatal("detail not found")
	}
	if len(d.ScanHistory) != 2 {
		t.Fatalf("expected 2 scan_history rows, got %d", len(d.ScanHistory))
	}
	if d.ScanHistory[0].Created < d.ScanHistory[1].Created {
		t.Errorf("scan_history must be newest-first")
	}
	if d.HasLedger {
		t.Errorf("no ledger seeded; has_ledger should be false")
	}

	// Forget → excluded from list, but detail still resolvable and reports preserved.
	if err := Forget(SlugFor(repo)); err != nil {
		t.Fatal(err)
	}
	for _, s := range ListSummaries(reportsDir) {
		if s.Slug == SlugFor(repo) {
			t.Errorf("forgotten app must not appear in the list")
		}
	}
	if _, ok := BuildDetail(SlugFor(repo), reportsDir); !ok {
		t.Errorf("forgotten app detail must still resolve while reports remain")
	}
	// Re-register un-hides.
	if _, err := Register(repo); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, s := range ListSummaries(reportsDir) {
		if s.Slug == SlugFor(repo) {
			found = true
		}
	}
	if !found {
		t.Errorf("re-registering must un-hide the app")
	}
}

func keysOf(m map[string]AppSummary) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}
func keysOfList(l []AppSummary) []string {
	var out []string
	for _, s := range l {
		out = append(out, s.Slug)
	}
	return out
}
