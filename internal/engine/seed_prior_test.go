package engine

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writePriorReport creates a minimal complete prior report directory for repo with
// the given findings.json body, so prior-report selection has something to find.
func writePriorReport(t *testing.T, reportsDir, name, repo, findingsJSON string) string {
	t.Helper()
	dir := filepath.Join(reportsDir, name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	meta := `{"repo":` + jsonStr(repo) + `,"phases_completed":["1","2","2b","4"],"phases_requested":["1","2","2b","4"]}`
	mustWrite(t, filepath.Join(dir, "scan_meta.json"), meta)
	mustWrite(t, filepath.Join(dir, "findings.json"), findingsJSON)
	mustWrite(t, filepath.Join(dir, "README.md"), "# report")
	return dir
}

func jsonStr(s string) string { return `"` + strings.ReplaceAll(s, `\`, `\\`) + `"` }
func mustWrite(t *testing.T, p, s string) {
	t.Helper()
	if err := os.WriteFile(p, []byte(s), 0o644); err != nil {
		t.Fatal(err)
	}
}

const priorFindings = `{"findings":[
{"title":"SQL injection in search","cwe":"CWE-89","location":"app/db.py:21","severity":"high","verification_status":"supported"},
{"title":"Reflected XSS","cwe":"CWE-79","location":"app/views.py:10","severity":"medium"}
]}`

// FR-010/011, SC-002: seed_prior on selects an eligible prior report for the SAME
// repo, injects findings as LEADS (not verdicts), records provenance and marks the
// run correlated; independent re-verification framing is present.
func TestPriorSeedAppliedSameRepo(t *testing.T) {
	repo := "/repos/myapp"
	reportsDir := t.TempDir()
	writePriorReport(t, reportsDir, "myapp_VULNHUNT_RESULTS_m_2026-01-01-000000", repo, priorFindings)

	rec := &RunRecord{}
	spec := ScanSpec{Repo: repo, ResultsDir: filepath.Join(reportsDir, "current"), ReportsDir: reportsDir, Phases: []string{"1"}, SeedPrior: true}
	task := applyPriorSeed(rec, spec, "BASE")

	if !strings.Contains(task, "Prior-report leads") || !strings.Contains(task, "SQL injection in search") {
		t.Error("prior leads not injected into recon task")
	}
	// Leads only: it must instruct re-verification and NOT carry prior verdicts.
	if !strings.Contains(task, "RE-VERIFY") {
		t.Error("prior seed must frame findings as leads to re-verify")
	}
	if strings.Contains(task, "supported") {
		t.Error("prior verification verdicts must NOT be copied into the seed")
	}
	if !rec.SeedPriorApplied || rec.SeedPriorReport == "" || !rec.SeededOrCorrelated {
		t.Errorf("prior-seed provenance/correlation not recorded: %+v", rec)
	}
}

// FR-010: seed_prior off injects nothing.
func TestPriorSeedOff(t *testing.T) {
	rec := &RunRecord{}
	spec := ScanSpec{Repo: "/repos/myapp", ResultsDir: "/x", ReportsDir: t.TempDir(), Phases: []string{"1"}, SeedPrior: false}
	if got := applyPriorSeed(rec, spec, "BASE"); got != "BASE" {
		t.Error("seed_prior=false must inject nothing")
	}
	if rec.SeedPriorRequested {
		t.Error("seed_prior=false must record no request")
	}
}

// FR-010, SC-002: no eligible / wrong-repo / no-prior yields an explained unseeded
// run — never a fake seed and never another repository's report.
func TestPriorSeedUnseededCases(t *testing.T) {
	reportsDir := t.TempDir()
	// A report for a DIFFERENT repo must never be borrowed.
	writePriorReport(t, reportsDir, "other_VULNHUNT_RESULTS_m_2026-01-01-000000", "/repos/other", priorFindings)

	t.Run("wrong repo not borrowed", func(t *testing.T) {
		rec := &RunRecord{}
		spec := ScanSpec{Repo: "/repos/myapp", ResultsDir: filepath.Join(reportsDir, "cur"), ReportsDir: reportsDir, Phases: []string{"1"}, SeedPrior: true}
		task := applyPriorSeed(rec, spec, "BASE")
		if task != "BASE" || rec.SeedPriorApplied {
			t.Error("must not seed from another repository's report")
		}
		if rec.SeedPriorReason == "" {
			t.Error("unseeded run must record a reason")
		}
	})

	t.Run("no reports dir", func(t *testing.T) {
		rec := &RunRecord{}
		spec := ScanSpec{Repo: "/repos/myapp", ResultsDir: "/cur", Phases: []string{"1"}, SeedPrior: true}
		if applyPriorSeed(rec, spec, "BASE") != "BASE" || rec.SeedPriorApplied {
			t.Error("no reports dir must yield explained unseeded run")
		}
	})

	t.Run("incomplete prior ignored", func(t *testing.T) {
		rd := t.TempDir()
		dir := filepath.Join(rd, "myapp_VULNHUNT_RESULTS_m_2026-01-02-000000")
		_ = os.MkdirAll(dir, 0o755)
		// phases_completed lacks "4" → not complete.
		mustWrite(t, filepath.Join(dir, "scan_meta.json"), `{"repo":"/repos/myapp","phases_completed":["1"],"phases_requested":["1"]}`)
		mustWrite(t, filepath.Join(dir, "findings.json"), priorFindings)
		rec := &RunRecord{}
		spec := ScanSpec{Repo: "/repos/myapp", ResultsDir: filepath.Join(rd, "cur"), ReportsDir: rd, Phases: []string{"1"}, SeedPrior: true}
		if applyPriorSeed(rec, spec, "BASE") != "BASE" || rec.SeedPriorApplied {
			t.Error("an incomplete prior report must not be seeded")
		}
	})
}
