package parity

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"vhlocal/internal/consolidate"
	"vhlocal/internal/verification"
)

// This oracle is exported by Python, never by the Go implementation under test.
func TestPythonReferenceContracts(t *testing.T) {
	var fixture struct {
		Source  string
		Finding consolidate.Finding
		Cases   []struct {
			Name      string
			Decisions []verification.Decision
			Expected  struct {
				Complete bool
				Status   string
			}
		}
		Identity struct {
			Source      string
			Locations   []string
			UniqueCount int `json:"unique_count"`
		}
		Artifacts []struct {
			Name    string
			Entries []verification.ArtifactEntry
			Valid   bool
		} `json:"artifact_cases"`
	}
	b, err := os.ReadFile(filepath.Join(moduleRoot(t), "tests", "parity", "reference", "contracts.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(b, &fixture); err != nil {
		t.Fatal(err)
	}
	repo, out := t.TempDir(), t.TempDir()
	if err = os.WriteFile(filepath.Join(repo, "app.py"), []byte(fixture.Source), 0600); err != nil {
		t.Fatal(err)
	}
	man := verification.Manifest{SchemaVersion: 1, Revision: "rev1", Repo: repo, Candidates: []verification.Candidate{{ID: fixture.Finding.ID, Finding: fixture.Finding}}}
	for _, c := range fixture.Cases {
		t.Run(c.Name, func(t *testing.T) {
			got := verification.Reconcile(&man, c.Decisions, repo)
			if got.Complete != c.Expected.Complete || len(got.Results) != 1 || got.Results[0].Status != c.Expected.Status {
				t.Fatalf("Python expected %+v; Go returned %+v", c.Expected, got)
			}
		})
	}
	os.WriteFile(filepath.Join(repo, "sites.py"), []byte(fixture.Identity.Source), 0600)
	var fs []consolidate.Finding
	for _, loc := range fixture.Identity.Locations {
		f := fixture.Finding
		f.Location = loc
		fs = append(fs, f)
	}
	m, err := verification.BuildManifest(out, repo, "rev1", fs)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Candidates) != fixture.Identity.UniqueCount {
		t.Fatalf("Python keeps %d unique sites, Go kept %d", fixture.Identity.UniqueCount, len(m.Candidates))
	}
	fixture.Finding.VerificationStatus = "supported"
	for _, c := range fixture.Artifacts {
		t.Run("artifacts/"+c.Name, func(t *testing.T) {
			b, _ := json.Marshal(c.Entries)
			os.WriteFile(filepath.Join(out, verification.ArtifactManifestFile), b, 0600)
			errs := verification.ValidateArtifacts(out, []consolidate.Finding{fixture.Finding})
			if (len(errs) == 0) != c.Valid {
				t.Fatalf("Python valid=%v, Go errors=%v", c.Valid, errs)
			}
		})
	}
}
