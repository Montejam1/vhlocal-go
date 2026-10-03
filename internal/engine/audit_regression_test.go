package engine

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"vhlocal/internal/client"
	"vhlocal/internal/consolidate"
	"vhlocal/internal/verification"
)

type silentProvider struct{}

func (silentProvider) Backend() client.Backend { return "fake" }
func (silentProvider) Endpoint() string        { return "fake://silent" }
func (silentProvider) Chat(context.Context, client.ChatRequest) (*client.ChatResponse, error) {
	return &client.ChatResponse{Message: client.Message{Role: "assistant", Content: "done"}}, nil
}

func TestMissingDecisionsCannotCompleteVerification(t *testing.T) {
	repo, out := sinkRepo(t), t.TempDir()
	spec := brokenSpec(repo, out)
	rec, err := Execute(context.Background(), spec, Providers{Hunt: &pathWriter{model: "m"}, Verify: silentProvider{}}, staticSkill{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if containsStr(rec.PhasesCompleted, "2b") || runStatus(t, out)["execution_status"] == "complete" {
		t.Fatal("missing decisions marked complete")
	}
	if loadState(out)["2b"] {
		t.Fatal("missing decisions checkpointed complete")
	}
}

func TestEmptyRepeatedHuntCannotComplete(t *testing.T) {
	repo, out := sinkRepo(t), t.TempDir()
	spec := brokenSpec(repo, out)
	spec.Phases = []string{"2"}
	spec.HuntSamples = 3
	rec, err := Execute(context.Background(), spec, Providers{Hunt: silentProvider{}}, staticSkill{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if containsStr(rec.PhasesCompleted, "2") || deliverableValid(filepath.Join(out, "results")) {
		t.Fatal("empty samples became hunt evidence")
	}
}

func TestMissingArtifactsInvalidateCompletionAndReports(t *testing.T) {
	repo, out := sinkRepo(t), t.TempDir()
	spec := brokenSpec(repo, out)
	spec.Phases = []string{"1", "2", "2b", "3", "3d", "4"}
	rec, err := Execute(context.Background(), spec, Providers{Hunt: &pathWriter{model: "m"}, Verify: verifyingProvider{verdict: "supported"}, Reproduce: silentProvider{}}, staticSkill{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if containsStr(rec.PhasesCompleted, "3") || len(rec.ArtifactErrors) == 0 {
		t.Fatalf("missing artifact accepted: %+v", rec)
	}
	doc := loadFindings(t, out)
	if doc["run_status"].(map[string]any)["execution_status"] == "complete" {
		t.Fatal("report claims completion")
	}
	if _, ok := doc["meta"].(map[string]any)["artifact_errors"]; !ok {
		t.Fatal("artifact errors absent from published metadata")
	}
	if loadState(out)["3"] || phaseValid(spec, "3", filepath.Join(out, "phase3_output.md")) {
		t.Fatal("invalid reproduction is resumable")
	}
	// Regeneration must not hide the empty manifest or change the finding list.
	if err := Regenerate(out); err != nil {
		t.Fatal(err)
	}
	if runStatus(t, out)["execution_status"] == "complete" {
		t.Fatal("regeneration hid missing artifacts")
	}
	readme, _ := os.ReadFile(filepath.Join(out, "README.md"))
	report, _ := os.ReadFile(filepath.Join(out, "SCAN_REPORT.md"))
	if string(readme) != string(report) {
		t.Fatal("README diverges from canonical report")
	}
}

func TestEvidenceCaptureCannotEscapeThroughSymlink(t *testing.T) {
	repo, outside := t.TempDir(), t.TempDir()
	os.WriteFile(filepath.Join(outside, "sentinel.py"), []byte("audit sentinel\n"), 0600)
	if err := os.Symlink(outside, filepath.Join(repo, "linked")); err != nil {
		t.Fatal(err)
	}
	evidence := map[string]verification.Evidence{}
	if _, err := captureEvidence(repo, "linked/sentinel.py", 1, 1, evidence); err == nil {
		t.Fatal("outside capture succeeded")
	}
	if text := initialContext(repo, "linked/sentinel.py:1", evidence); strings.Contains(text, "audit sentinel") || len(evidence) > 0 {
		t.Fatal("outside source leaked into model context")
	}
}

func TestSweepFindsLeadsWithoutPromotingOrCrossingLanguages(t *testing.T) {
	repo, out := t.TempDir(), t.TempDir()
	os.WriteFile(filepath.Join(repo, "app.py"), []byte("conn.execute(x)\nconn.execute(y)\n"), 0600)
	os.WriteFile(filepath.Join(repo, "front.js"), []byte("conn.execute(x)\n"), 0600)
	os.Mkdir(filepath.Join(repo, "tests"), 0700)
	os.WriteFile(filepath.Join(repo, "tests", "fixture.py"), []byte("conn.execute(x)\n"), 0600)
	f := consolidate.NewFinding("CAND-test")
	f.CWE = "CWE-89"
	f.Location = "app.py:1"
	if err := writeSweep(repo, out, []consolidate.Finding{f}); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(out, "phase3d_output.md"))
	text := string(b)
	if !strings.Contains(text, "app.py:2` | **LEAD**") || strings.Contains(text, "front.js") || strings.Contains(text, "fixture.py") {
		t.Fatalf("bad sweep:\n%s", text)
	}
}

func TestZeroSupportedCandidatesSkipReproductionModels(t *testing.T) {
	repo, out := sinkRepo(t), t.TempDir()
	spec := brokenSpec(repo, out)
	spec.Phases = []string{"1", "2", "2b", "3", "3d", "4"}
	rec, err := Execute(context.Background(), spec, Providers{Hunt: &pathWriter{model: "m"}, Verify: verifyingProvider{verdict: "rejected"}, Reproduce: alwaysEndpointError{}}, staticSkill{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !containsStr(rec.PhasesCompleted, "3") || len(rec.ArtifactErrors) > 0 {
		t.Fatal("valid zero-supported scan did not complete reproduction")
	}
	for _, a := range rec.Agents {
		if a.Phase == "3" || ((a.Phase == "3d" || a.Phase == "4") && a.Model != "deterministic") {
			t.Fatalf("unexpected model work: %+v", a)
		}
	}
	b, _ := os.ReadFile(filepath.Join(out, verification.ArtifactManifestFile))
	var entries []verification.ArtifactEntry
	if json.Unmarshal(b, &entries) != nil || len(entries) != 0 {
		t.Fatal("unexpected artifacts for rejected candidates")
	}
}

func TestRegenerateRevokesStaleVerificationCompletion(t *testing.T) {
	repo, out := sinkRepo(t), t.TempDir()
	spec := brokenSpec(repo, out)
	_, err := Execute(context.Background(), spec, Providers{Hunt: &pathWriter{model: "m"}, Verify: verifyingProvider{verdict: "supported"}}, staticSkill{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	// Simulate missing/corrupted persisted review records after a completed run.
	os.WriteFile(filepath.Join(out, verification.DecisionsFile), []byte("[]"), 0600)
	if err := Regenerate(out); err != nil {
		t.Fatal(err)
	}
	if runStatus(t, out)["execution_status"] == "complete" || loadState(out)["2b"] {
		t.Fatal("regeneration retained stale completion")
	}
	handoff, _ := os.ReadFile(filepath.Join(out, "phase2b_handoff.md"))
	if strings.Contains(string(handoff), "| CAND-") {
		t.Fatal("stale supported handoff survived regeneration")
	}
}

func TestResumeRejectsMissingHuntAssignment(t *testing.T) {
	repo, out := sinkRepo(t), t.TempDir()
	spec := brokenSpec(repo, out)
	spec.Phases = []string{"2"}
	_, err := Execute(context.Background(), spec, Providers{Hunt: &pathWriter{model: "m"}}, staticSkill{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	h, ok := loadHuntExecution(out)
	if !ok || !h.Complete {
		t.Fatal("completed hunt has no assignment manifest")
	}
	if err := os.Remove(filepath.Join(out, h.Files[0])); err != nil {
		t.Fatal(err)
	}
	spec.Resume = true
	rec, err := Execute(context.Background(), spec, Providers{Hunt: silentProvider{}}, staticSkill{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if containsStr(rec.PhasesCompleted, "2") || containsStr(rec.PhasesSkipped, "2") {
		t.Fatal("partial hunt was reused as complete")
	}
}
