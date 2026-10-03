package verification

import (
	"os"
	"path/filepath"
	"testing"

	"vhlocal/internal/consolidate"
)

func TestSourceIdentityKeepsDistinctSitesAndIgnoresLineShifts(t *testing.T) {
	repo, root := t.TempDir(), t.TempDir()
	src := "class First:\n    def query(self, x):\n        conn.execute(x)\n        conn.execute(x)\n\nclass Second:\n    def query(self, x):\n        conn.execute(x)\n"
	path := filepath.Join(repo, "app.py")
	if err := os.WriteFile(path, []byte(src), 0600); err != nil {
		t.Fatal(err)
	}
	fs := []consolidate.Finding{candFinding("app.py:3"), candFinding("app.py:4"), candFinding("app.py:8"), candFinding("app.py:3")}
	// Legacy prose dedup must not preempt source identity.
	duplicate := "V1"
	fs[1].DuplicateOf = &duplicate
	m, err := BuildManifest(root, repo, "rev", fs)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Candidates) != 3 || m.RawCount != 4 {
		t.Fatalf("lost distinct sites or failed repeated-sample dedup: %+v", m)
	}
	original := m.Candidates[0].ID
	if err := os.WriteFile(path, []byte("\n\n"+src), 0600); err != nil {
		t.Fatal(err)
	}
	shifted, err := BuildManifest(root, repo, "rev", []consolidate.Finding{candFinding("app.py:5")})
	if err != nil {
		t.Fatal(err)
	}
	if shifted.Candidates[0].ID != original {
		t.Fatal("blank-line shift changed source identity")
	}
	// Final consolidation must not merge distinct canonical candidates again.
	rc := &Reconciliation{}
	for _, c := range m.Candidates {
		rc.Results = append(rc.Results, DecisionResult{CandidateID: c.ID, Status: "supported"})
	}
	final := consolidate.Prepare(FinalFindings(m, rc))
	for _, f := range final {
		if f.DuplicateOf != nil {
			t.Fatalf("canonical candidate re-deduplicated: %+v", f)
		}
	}
}

func TestReviewRequiresReasoningAndMatchingRevision(t *testing.T) {
	repo := vulnRepo(t)
	m := manifestOf(repo, "app/db.py:2")
	for _, verdict := range []string{"supported", "rejected"} {
		for _, field := range []string{"reviewer", "entry_point", "attacker_control", "preconditions", "defenses_reviewed", "security_impact", "revision"} {
			t.Run(verdict+"/"+field, func(t *testing.T) {
				d := dec(m.Candidates[0].ID, verdict, evFor(repo, "app/db.py", 1, 2))
				fields := map[string]*string{"reviewer": &d.Reviewer, "entry_point": &d.EntryPoint, "attacker_control": &d.AttackerControl, "preconditions": &d.Preconditions, "defenses_reviewed": &d.DefensesReviewed, "security_impact": &d.SecurityImpact, "revision": &d.Revision}
				*fields[field] = " "
				if field == "revision" {
					d.Revision = "stale"
				}
				rc := Reconcile(m, []Decision{d}, repo)
				if rc.Complete || rc.Results[0].Status != "unresolved" {
					t.Fatalf("accepted incomplete review: %+v", rc)
				}
			})
		}
	}
}

func TestRejectedEvidenceMustCoverCandidate(t *testing.T) {
	repo := vulnRepo(t)
	m := manifestOf(repo, "app/db.py:2")
	d := dec(m.Candidates[0].ID, "rejected", evFor(repo, "app/safe.py", 1, 2))
	if rc := Reconcile(m, []Decision{d}, repo); rc.Complete {
		t.Fatal("unrelated source accepted as rejection evidence")
	}
}

func TestEvidenceAndArtifactsRejectEscapingSymlinks(t *testing.T) {
	repo, outside := t.TempDir(), t.TempDir()
	os.WriteFile(filepath.Join(outside, "proof.py"), []byte("# CAND-test app.py:1\nassert True\n"), 0600)
	if err := os.Symlink(outside, filepath.Join(repo, "linked")); err != nil {
		t.Fatal(err)
	}
	ev := Evidence{Path: "linked/proof.py", StartLine: 1, EndLine: 1, Quote: "# CAND-test app.py:1"}
	if evidenceMatchesSource(ev, repo) {
		t.Fatal("accepted outside evidence")
	}
	os.Mkdir(filepath.Join(repo, "poc"), 0700)
	if err := os.Symlink(filepath.Join(outside, "proof.py"), filepath.Join(repo, "poc", "proof.py")); err != nil {
		t.Fatal(err)
	}
	writeManifest(t, repo, []ArtifactEntry{{CandidateID: "CAND-test", Path: "poc/proof.py", Kind: "poc", Status: "authored"}})
	if errs := ValidateArtifacts(repo, []consolidate.Finding{supportedFinding("CAND-test", "app.py:1")}); len(errs) == 0 {
		t.Fatal("accepted outside artifact")
	}
}

func TestPrimaryEvidenceUsesExactPathAndFullRange(t *testing.T) {
	repo := vulnRepo(t)
	os.MkdirAll(filepath.Join(repo, "other", "app"), 0700)
	data, _ := os.ReadFile(filepath.Join(repo, "app", "db.py"))
	os.WriteFile(filepath.Join(repo, "other", "app", "db.py"), data, 0600)
	m := manifestOf(repo, "app/db.py:2")
	d := dec(m.Candidates[0].ID, "supported", evFor(repo, "other/app/db.py", 1, 2))
	if rc := Reconcile(m, []Decision{d}, repo); rc.Complete {
		t.Fatal("same basename/suffix accepted as primary evidence")
	}
	m = manifestOf(repo, "app/db.py:1-2")
	d = dec(m.Candidates[0].ID, "rejected", evFor(repo, "app/db.py", 1, 1))
	if rc := Reconcile(m, []Decision{d}, repo); rc.Complete {
		t.Fatal("partial source range accepted")
	}
}
