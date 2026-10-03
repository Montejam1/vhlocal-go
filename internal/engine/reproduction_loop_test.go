package engine

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"vhlocal/internal/client"
	"vhlocal/internal/consolidate"
	"vhlocal/internal/tools"
	"vhlocal/internal/verification"
)

var reReproDeliv = regexp.MustCompile(`(\S+/repro/(CAND-[A-Za-z0-9]+)\.json)`)
var reReproLoc = regexp.MustCompile(`[\w./\-]+\.py:\d+`)

// reproFake drives the per-candidate authoring loop: a "fix" candidate authors an
// INVALID PoC first (missing the canonical ID) then a VALID one after the rejection
// feedback; a "bad" candidate is always invalid (→ deferral).
type reproFake struct{}

func (reproFake) Backend() client.Backend { return "fake" }
func (reproFake) Endpoint() string        { return "fake://repro" }
func (reproFake) Chat(_ context.Context, req client.ChatRequest) (*client.ChatResponse, error) {
	if n := len(req.Messages); n > 0 && req.Messages[n-1].Role == "tool" {
		return &client.ChatResponse{Message: client.Message{Role: "assistant", Content: "done"}}, nil
	}
	task := ""
	for _, m := range req.Messages {
		if m.Role == "user" {
			task = m.Content
		}
	}
	m := reReproDeliv.FindStringSubmatch(task)
	if m == nil {
		return &client.ChatResponse{Message: client.Message{Role: "assistant", Content: "no deliverable named"}}, nil
	}
	deliv, id := m[1], m[2]
	results := filepath.Dir(filepath.Dir(deliv))
	loc := reReproLoc.FindString(task)

	// A "defer" candidate submits an explicit, reasoned MODEL deferral (valid).
	if strings.Contains(id, "defer") {
		entry, _ := json.Marshal(map[string]string{"candidate_id": id, "kind": "deferred", "reason": "requires live credentials"})
		delivArgs, _ := json.Marshal(map[string]string{"path": deliv, "content": string(entry)})
		return &client.ChatResponse{Model: "m", Message: client.Message{Role: "assistant",
			ToolCalls: []client.ToolCall{{ID: "w1", Name: "Write", Arguments: string(delivArgs)}}}}, nil
	}

	valid := strings.Contains(task, "REJECTED") && strings.Contains(id, "fix")
	pocRel := "poc/" + id + ".py"
	pocAbs := filepath.Join(results, pocRel)
	poc := "# PoC (incomplete)\nprint('x')\n"
	if valid {
		poc = "# PoC for " + id + " at " + loc + "\nprint('exploit path')\n"
	}
	entry, _ := json.Marshal(map[string]string{"candidate_id": id, "kind": "poc", "path": pocRel, "status": "authored"})
	pocArgs, _ := json.Marshal(map[string]string{"path": pocAbs, "content": poc})
	delivArgs, _ := json.Marshal(map[string]string{"path": deliv, "content": string(entry)})
	return &client.ChatResponse{Model: "m", Message: client.Message{Role: "assistant", ToolCalls: []client.ToolCall{
		{ID: "w1", Name: "Write", Arguments: string(pocArgs)},
		{ID: "w2", Name: "Write", Arguments: string(delivArgs)},
	}}}, nil
}

func reproFinding(id string) consolidate.Finding {
	f := consolidate.NewFinding(id)
	f.CWE, f.Location, f.VerificationStatus = "CWE-89", "app/db.py:2", "supported"
	consolidate.ApplyKnowledge(&f)
	return f
}

// CB-12/13/14 (feature 007, FR-025..027): an invalid reproduction submission gets
// bounded corrective feedback and is repaired; an unrepairable one becomes an
// explicit deferral; candidate IDs stay stable; authored material is never executed.
func TestReproductionPerCandidateLoop(t *testing.T) {
	repo := t.TempDir()
	os.MkdirAll(filepath.Join(repo, "app"), 0o755)
	os.WriteFile(filepath.Join(repo, "app", "db.py"), []byte("def q(x):\n    return conn.execute(x)\n"), 0o644)
	results := t.TempDir()
	sb, err := tools.NewSandbox(repo, "", results)
	if err != nil {
		t.Fatal(err)
	}
	spec := ScanSpec{Repo: repo, ResultsDir: results, Model: "m", NumCtx: 4096, MaxOutputTokens: 512}
	rec := &RunRecord{Usage: map[string]any{}}
	noop := Emit(func(string, map[string]any) {})

	// Repairable candidate: invalid first attempt → corrective feedback → valid.
	fix := reproFinding("CAND-fix0000000000000000000000")
	e, ok := authorCandidate(context.Background(), rec, reproFake{}, sb, spec, "", fix, noop)
	if !ok || e.Kind != "poc" {
		t.Fatalf("repairable candidate must end with a valid poc, got ok=%v %+v", ok, e)
	}
	if e.Status != "authored" {
		t.Errorf("material must be authored (never executed), got status %q", e.Status)
	}
	if why := verification.ValidateEntry(results, e, fix); why != "" {
		t.Errorf("final entry must validate, got: %s", why)
	}
	if e.CandidateID != fix.ID {
		t.Errorf("candidate id must stay stable, got %q", e.CandidateID)
	}

	// Unrepairable candidate: always invalid, no explicit deferral → NOT registered
	// (ok=false), so the harness leaves it as a missing disposition, not a fake pass.
	bad := reproFinding("CAND-bad0000000000000000000000")
	if _, ok := authorCandidate(context.Background(), rec, reproFake{}, sb, spec, "", bad, noop); ok {
		t.Errorf("an unrepairable candidate must NOT be registered (no fabricated disposition)")
	}

	// Explicit model deferral: a reasoned deferral IS a valid disposition.
	def := reproFinding("CAND-defer00000000000000000000")
	e3, ok3 := authorCandidate(context.Background(), rec, reproFake{}, sb, spec, "", def, noop)
	if !ok3 || e3.Kind != "deferred" || strings.TrimSpace(e3.Reason) == "" {
		t.Errorf("an explicit model deferral must be accepted with a reason, got ok=%v %+v", ok3, e3)
	}
}
