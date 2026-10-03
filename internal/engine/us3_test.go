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
)

// sinkRepo builds a repo whose app/db.py has a real SQL sink at line 21 (matching
// pathWriter's canned finding location — a REAL line, since feature 015 validates
// every citation against the tree) so source corroboration can pass.
func sinkRepo(t *testing.T) string {
	t.Helper()
	repo := t.TempDir()
	os.MkdirAll(filepath.Join(repo, "app"), 0o755)
	var b strings.Builder
	b.WriteString("from fastapi import APIRouter\nrouter = APIRouter()\n")
	for i := 3; i < 21; i++ {
		b.WriteString("# pad\n")
	}
	b.WriteString("    return conn.execute(q)  # line 21 sink\n")
	os.WriteFile(filepath.Join(repo, "app", "db.py"), []byte(b.String()), 0o644)
	os.WriteFile(filepath.Join(repo, "app", "routes.py"),
		[]byte("from fastapi import APIRouter\nrouter=APIRouter()\n@router.get('/api/search')\ndef s(q: str):\n    return q\n"), 0o644)
	return repo
}

var reEV = regexp.MustCompile(`EV-[0-9a-f]{24}`)

// verifyingProvider drives a verification session to a SUPPORTED verdict: it
// references the auto-captured initial evidence (whose id appears in the prompt).
type verifyingProvider struct{ verdict string }

func (verifyingProvider) Backend() client.Backend { return "fake" }
func (verifyingProvider) Endpoint() string        { return "fake://verify" }
func (v verifyingProvider) Chat(_ context.Context, req client.ChatRequest) (*client.ChatResponse, error) {
	ev := ""
	for _, m := range req.Messages {
		if id := reEV.FindString(m.Content); id != "" {
			ev = id
		}
	}
	args := map[string]any{
		"verdict": v.verdict, "rationale": "the query parameter reaches conn.execute unsanitized",
		"entry_point": "GET /api/search", "attacker_control": "q query parameter",
		"preconditions": "none", "defenses_reviewed": "none observed", "security_impact": "database read/write",
		"evidence_ids": []string{ev}, "unresolved_questions": []string{},
	}
	b, _ := json.Marshal(args)
	return &client.ChatResponse{Message: client.Message{Role: "assistant",
		ToolCalls: []client.ToolCall{{ID: "s1", Name: "submit_verification", Arguments: string(b)}}},
		Usage: client.Usage{PromptTokens: 8, CompletionTokens: 4}}, nil
}

// C-3a/b/e + FR-018..023: a full verification session that captures evidence and
// submits supported yields a from_confirmed finding, and writes the handoff.
func TestVerificationSessionSupported(t *testing.T) {
	repo := sinkRepo(t)
	results := t.TempDir()
	spec := brokenSpec(repo, results)
	spec.Repo = repo
	rec, err := Execute(context.Background(), spec, Providers{Hunt: &pathWriter{model: "m"}, Verify: verifyingProvider{verdict: "supported"}}, staticSkill{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	// candidate manifest built before 2b; decisions + handoff written.
	for _, f := range []string{"candidate_manifest.json", "verification_decisions.json",
		"verification_reconciliation.json", "phase2b_output.md", "phase2b_handoff.md"} {
		if _, e := os.Stat(filepath.Join(results, f)); e != nil {
			t.Errorf("missing verification artifact %s", f)
		}
	}
	doc := loadFindings(t, results)
	fs := doc["findings"].([]any)
	if len(fs) == 0 {
		t.Fatal("expected candidates")
	}
	supported := false
	for _, fi := range fs {
		if fi.(map[string]any)["from_confirmed"] == true {
			supported = true
		}
	}
	if !supported {
		t.Errorf("a supported verification decision must yield a from_confirmed finding")
	}
	// handoff lists the supported candidate.
	h, _ := os.ReadFile(filepath.Join(results, "phase2b_handoff.md"))
	if !strings.Contains(string(h), "CAND-") {
		t.Errorf("handoff should list the supported candidate; got:\n%s", h)
	}
	_ = rec
}

// C-C1: an all-rejected verification yields ZERO supported findings and never
// resurrects raw hunt candidates as supported.
func TestVerificationSessionZeroSurvivor(t *testing.T) {
	repo := sinkRepo(t)
	results := t.TempDir()
	spec := brokenSpec(repo, results)
	spec.Repo = repo
	if _, err := Execute(context.Background(), spec, Providers{Hunt: &pathWriter{model: "m"}, Verify: verifyingProvider{verdict: "rejected"}}, staticSkill{}, nil); err != nil {
		t.Fatal(err)
	}
	doc := loadFindings(t, results)
	for _, fi := range doc["findings"].([]any) {
		f := fi.(map[string]any)
		if f["from_confirmed"] == true || f["classification"] == "statically_supported" {
			t.Errorf("a rejected candidate must not be published as supported: %v", f)
		}
	}
}

// A tool-parse 500 during a verification session is recovered within the session
// (steered + retried), not failed as an endpoint outage — parity with the hunt
// loop's feature-004 repair.
type toolParseThenSubmit struct{ n int }

func (*toolParseThenSubmit) Backend() client.Backend { return "fake" }
func (*toolParseThenSubmit) Endpoint() string        { return "fake://verify" }
func (v *toolParseThenSubmit) Chat(_ context.Context, req client.ChatRequest) (*client.ChatResponse, error) {
	v.n++
	if v.n == 1 {
		return nil, &client.TransportError{Backend: "fake", Kind: client.KindToolParse, Raw: "prose {bad json", Retryable: false}
	}
	ev := ""
	for _, m := range req.Messages {
		if id := reEV.FindString(m.Content); id != "" {
			ev = id
		}
	}
	args := map[string]any{"verdict": "unresolved", "rationale": "insufficient evidence",
		"entry_point": "GET /x", "attacker_control": "n/a", "preconditions": "n/a",
		"defenses_reviewed": "n/a", "security_impact": "n/a",
		"evidence_ids": []string{ev}, "unresolved_questions": []string{"needs a live PoC"}}
	b, _ := json.Marshal(args)
	return &client.ChatResponse{Message: client.Message{Role: "assistant",
		ToolCalls: []client.ToolCall{{ID: "s", Name: "submit_verification", Arguments: string(b)}}}}, nil
}

func TestVerifyToolParseRecovered(t *testing.T) {
	repo := sinkRepo(t)
	results := t.TempDir()
	spec := brokenSpec(repo, results)
	spec.Repo = repo
	rec, err := Execute(context.Background(), spec, Providers{Hunt: &pathWriter{model: "m"}, Verify: &toolParseThenSubmit{}}, staticSkill{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range rec.Agents {
		if a.Phase == "2b" && a.StoppedReason == "endpoint_failure" {
			t.Errorf("a tool-parse 500 in a verify session must be recovered, not an endpoint_failure")
		}
	}
}
