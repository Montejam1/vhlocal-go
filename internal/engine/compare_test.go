package engine

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"vhlocal/internal/consolidate"
	"vhlocal/internal/verification"
)

func TestFrozenVerifierComparison(t *testing.T) {
	repo := sinkRepo(t)
	frozen := t.TempDir()
	rev, err := SourceFingerprint(repo)
	if err != nil {
		t.Fatal(err)
	}
	_, err = verification.BuildManifest(frozen, repo, rev, []consolidate.Finding{{ID: "V1", Location: "app/db.py:21", CWE: "CWE-89", Title: "SQL injection"}})
	if err != nil {
		t.Fatal(err)
	}
	manifest := filepath.Join(frozen, verification.CandidateManifestFile)
	before, _ := os.ReadFile(manifest)
	a := newIdentityRecordingProvider("a", verifyingProvider{verdict: "supported"})
	b := newIdentityRecordingProvider("b", verifyingProvider{verdict: "unresolved"})
	result, err := CompareVerification(context.Background(), ComparisonSpec{Manifest: manifest, Repo: repo, Revision: rev, OutputDir: filepath.Join(t.TempDir(), "comparison"), Variants: []CompareVariant{{Name: "a", Model: "a", Provider: a}, {Name: "b", Model: "b", Provider: b}, {Name: "planned", Model: "planned"}}})
	if err != nil {
		t.Fatal(err)
	}
	if result.Variants[0].Decisions.Supported != 1 || result.Variants[1].Decisions.UnresolvedExplicit != 1 || !result.Variants[2].NotRun {
		t.Fatalf("variants: %+v", result.Variants)
	}
	if result.Variants[1].Gate.Reason != "all_unresolved" || result.Variants[1].Gate.EfficacyImproved {
		t.Fatal("all-unresolved comparison passed")
	}
	for i, p := range []*identityRecordingProvider{a, b} {
		if len(p.Calls()) == 0 || len(result.Variants[i].Provenance) != len(p.Calls()) {
			t.Fatal("missing call provenance")
		}
		for _, pr := range result.Variants[i].Provenance {
			if pr.RequestedModel != p.name {
				t.Fatal("override not applied")
			}
		}
	}
	after, _ := os.ReadFile(manifest)
	if string(before) != string(after) {
		t.Fatal("frozen input modified")
	}
	if _, err = CompareVerification(context.Background(), ComparisonSpec{Manifest: manifest, Repo: repo, Revision: "wrong", OutputDir: filepath.Join(t.TempDir(), "bad")}); err == nil {
		t.Fatal("revision mismatch accepted")
	}
}
