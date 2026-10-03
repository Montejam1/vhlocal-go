package engine

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"vhlocal/internal/client"
	"vhlocal/internal/report"
	"vhlocal/internal/threatmodel"
)

// threatModelWriter writes a caller-supplied threat model for phase 1t and
// behaves like pathWriter elsewhere.
type threatModelWriter struct {
	pw *pathWriter
	md string
}

func (w *threatModelWriter) Backend() client.Backend { return "fake" }
func (w *threatModelWriter) Endpoint() string        { return "fake://local" }
func (w *threatModelWriter) Chat(ctx context.Context, req client.ChatRequest) (*client.ChatResponse, error) {
	if n := len(req.Messages); n > 0 && req.Messages[n-1].Role == "tool" {
		return &client.ChatResponse{Message: client.Message{Role: "assistant", Content: "done"}}, nil
	}
	task := ""
	for _, m := range req.Messages {
		if m.Role == "user" {
			task = m.Content
		}
	}
	all := reOutPath.FindAllString(task, -1)
	if len(all) > 0 && strings.HasSuffix(all[len(all)-1], "threat_model.md") {
		args, _ := json.Marshal(map[string]string{"path": all[len(all)-1], "content": w.md})
		return &client.ChatResponse{Model: "m", Message: client.Message{Role: "assistant",
			ToolCalls: []client.ToolCall{{ID: "w", Name: "Write", Arguments: string(args)}}}}, nil
	}
	return w.pw.Chat(ctx, req)
}

// T036 (C-A12, FR-011): a 1t run writes threat_model_diagram.json from the file the
// model produced; regeneration reproduces it byte-identically; a run without the
// threat model writes none; the report model references it and states the result.
func TestThreatModelDiagramArtifactWrittenAndRegenerated(t *testing.T) {
	repo := filepath.Join(repoRoot(t), "testdata", "vulnapp")
	corpus, err := os.ReadFile(filepath.Join(repoRoot(t), "testdata", "diagrams", "07-two-diagrams.md"))
	if err != nil {
		t.Fatal(err)
	}
	results := t.TempDir()
	spec := brokenSpec(repo, results)
	spec.Phases = []string{"1", "1t", "2"}
	spec.ThreatModel = true
	prov := &threatModelWriter{pw: &pathWriter{model: "m"}, md: "## Application characterization\n\nx\n\n## Data flow diagram\n\n" + string(corpus)}
	if _, err := Execute(context.Background(), spec, Providers{Hunt: prov}, staticSkill{}, nil); err != nil {
		t.Fatal(err)
	}
	art, err := threatmodel.Load(results)
	if err != nil {
		t.Fatalf("artifact missing: %v", err)
	}
	if len(art.Diagrams) != 2 || art.Diagrams[0].State != threatmodel.StateValid || art.Diagrams[1].State != threatmodel.StateInvalid {
		t.Errorf("artifact = %+v", art.Diagrams)
	}
	b1, _ := os.ReadFile(filepath.Join(results, threatmodel.ArtifactFile))
	if err := Regenerate(results); err != nil {
		t.Fatal(err)
	}
	b2, _ := os.ReadFile(filepath.Join(results, threatmodel.ArtifactFile))
	if string(b1) != string(b2) {
		t.Error("regeneration changed the diagram artifact")
	}
	m, err := report.LoadModel(results)
	if err != nil || m.Refs["diagram"] != threatmodel.ArtifactFile || !strings.Contains(m.DiagramSummary, "diagram 2 invalid (line 2, E_EDGE_LABEL_UNTERMINATED)") {
		t.Errorf("report model diagram ref/summary: %v %q", err, m.DiagramSummary)
	}
	md, _ := os.ReadFile(filepath.Join(results, "SCAN_REPORT.md"))
	if !strings.Contains(string(md), "### Threat model diagram") || !strings.Contains(string(md), "[threat_model_diagram.json](threat_model_diagram.json)") {
		t.Error("report lacks the diagram validation line")
	}

	// No threat model ⇒ no artifact, no ref.
	results2 := t.TempDir()
	spec2 := brokenSpec(repo, results2)
	spec2.Phases = []string{"1", "2"}
	if _, err := Execute(context.Background(), spec2, Providers{Hunt: &pathWriter{model: "m"}}, staticSkill{}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(results2, threatmodel.ArtifactFile)); err == nil {
		t.Error("artifact written without a threat model")
	}
	m2, _ := report.LoadModel(results2)
	if _, ok := m2.Refs["diagram"]; ok || m2.DiagramSummary != "" {
		t.Error("report model must not reference a diagram that does not exist")
	}
}
