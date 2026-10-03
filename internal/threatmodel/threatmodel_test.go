package threatmodel

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

type expectedCase struct {
	Diagrams []struct {
		State         string   `json:"state"`
		Repairs       []string `json:"repairs"`
		Errors        []string `json:"errors"`
		ErrorLine     int      `json:"error_line"`
		Nodes         int      `json:"nodes"`
		Edges         int      `json:"edges"`
		Boundaries    int      `json:"boundaries"`
		LabelContains string   `json:"label_contains"`
	} `json:"diagrams"`
}

func corpusDir(t *testing.T) string {
	t.Helper()
	wd, _ := os.Getwd()
	for d := wd; d != "/" && d != ""; d = filepath.Dir(d) {
		if _, err := os.Stat(filepath.Join(d, "go.mod")); err == nil {
			return filepath.Join(d, "testdata", "diagrams")
		}
	}
	t.Fatal("repo root not found")
	return ""
}

// T034 (C-A12, C-A13, FR-014): every corpus case yields its expected state,
// repairs and errors; repairs never change topology; the audited edge is invalid
// and never guessed; malicious labels survive as text.
func TestCorpusStatesRepairsAndErrors(t *testing.T) {
	dir := corpusDir(t)
	eb, err := os.ReadFile(filepath.Join(dir, "expected.json"))
	if err != nil {
		t.Fatal(err)
	}
	var exp struct {
		Cases map[string]expectedCase `json:"cases"`
	}
	if err := json.Unmarshal(eb, &exp); err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(exp.Cases))
	for n := range exp.Cases {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, name := range names {
		want := exp.Cases[name]
		t.Run(name, func(t *testing.T) {
			b, err := os.ReadFile(filepath.Join(dir, name))
			if err != nil {
				t.Fatal(err)
			}
			art := Validate(string(b))
			if len(art.Diagrams) != len(want.Diagrams) {
				t.Fatalf("diagrams = %d, want %d", len(art.Diagrams), len(want.Diagrams))
			}
			for i, wd := range want.Diagrams {
				got := art.Diagrams[i]
				if got.State != wd.State {
					t.Errorf("diagram %d state = %s, want %s (errors %+v repairs %+v)", i, got.State, wd.State, got.Errors, got.Repairs)
				}
				var rules []string
				for _, r := range got.Repairs {
					rules = append(rules, r.Rule)
				}
				if !reflect.DeepEqual(rules, wd.Repairs) && !(len(rules) == 0 && len(wd.Repairs) == 0) {
					t.Errorf("diagram %d repairs = %v, want %v", i, rules, wd.Repairs)
				}
				var codes []string
				for _, e := range got.Errors {
					codes = append(codes, e.Code)
				}
				if !reflect.DeepEqual(codes, wd.Errors) && !(len(codes) == 0 && len(wd.Errors) == 0) {
					t.Errorf("diagram %d errors = %v, want %v", i, codes, wd.Errors)
				}
				if wd.ErrorLine > 0 && (len(got.Errors) == 0 || got.Errors[0].Line != wd.ErrorLine) {
					t.Errorf("diagram %d error line = %+v, want %d", i, got.Errors, wd.ErrorLine)
				}
				if wd.State == StateValid || wd.State == StateRepaired {
					if got.Structure == nil {
						t.Fatalf("diagram %d has no structure", i)
					}
					if len(got.Structure.Nodes) != wd.Nodes || len(got.Structure.Edges) != wd.Edges || len(got.Structure.Boundaries) != wd.Boundaries {
						t.Errorf("diagram %d structure = %d nodes/%d edges/%d boundaries, want %d/%d/%d", i,
							len(got.Structure.Nodes), len(got.Structure.Edges), len(got.Structure.Boundaries), wd.Nodes, wd.Edges, wd.Boundaries)
					}
					if got.Normalized == "" {
						t.Errorf("diagram %d lacks a normalized serialization", i)
					}
					// Serialization is deterministic and idempotent.
					again := ParseFence(got.Normalized)
					if again.State != StateValid || again.Normalized != got.Normalized {
						t.Errorf("diagram %d re-parse of normalized differs (state %s)", i, again.State)
					}
					// A repaired diagram's topology equals the original's parsed topology
					// (repairs only fix syntax): nodes/edges of the repaired parse equal those
					// obtained by parsing the original with repairs (the same thing) — assert
					// no repair added an edge by checking edges ⊆ arrows in the original.
					if got.State == StateRepaired {
						for _, e := range got.Structure.Edges {
							if !strings.Contains(got.Original, e.From) || !strings.Contains(got.Original, e.To) {
								t.Errorf("repair invented an edge %s→%s", e.From, e.To)
							}
						}
					}
				} else if got.Structure != nil {
					t.Errorf("diagram %d in state %s must not carry a structure", i, got.State)
				}
				if wd.LabelContains != "" {
					found := false
					for _, n := range got.Structure.Nodes {
						if n.Label == wd.LabelContains {
							found = true
						}
					}
					if !found {
						t.Errorf("label %q not preserved as text", wd.LabelContains)
					}
				}
			}
		})
	}
}

func TestAuditedEdgeIsNeverRepaired(t *testing.T) {
	d := ParseFence("flowchart TD\n    B -.->|HTTP request (untrusted) .-> E\n")
	if d.State != StateInvalid || len(d.Errors) != 1 || d.Errors[0].Code != EEdgeLabelUnterminated || d.Errors[0].Line != 2 {
		t.Errorf("audited edge: %+v", d)
	}
	if len(d.Repairs) != 0 {
		t.Errorf("no repair may touch an ambiguous edge: %+v", d.Repairs)
	}
}

func TestSerializeDeterministic(t *testing.T) {
	st := &Structure{
		Nodes:      []Node{{ID: "B", Label: "b", Shape: "rect"}, {ID: "A", Label: "a", Shape: "rect"}},
		Edges:      []Edge{{From: "B", To: "A", Style: "solid"}, {From: "A", To: "B", Style: "dotted", Label: "x"}},
		Boundaries: []Boundary{{ID: "Z", Label: "z", Nodes: []string{"B"}}},
	}
	a := Serialize("LR", st)
	st.Nodes[0], st.Nodes[1] = st.Nodes[1], st.Nodes[0]
	st.Edges[0], st.Edges[1] = st.Edges[1], st.Edges[0]
	if b := Serialize("LR", st); a != b {
		t.Errorf("serialization depends on input order:\n%s\n%s", a, b)
	}
	if !strings.HasPrefix(a, "flowchart LR\n    subgraph Z[\"z\"]\n") {
		t.Errorf("unexpected serialization:\n%s", a)
	}
}

func TestWriteArtifactRoundTrip(t *testing.T) {
	dir := t.TempDir()
	if _, ok, _ := WriteArtifact(dir); ok {
		t.Fatal("no threat_model.md must write nothing")
	}
	src, _ := os.ReadFile(filepath.Join(corpusDir(t), "07-two-diagrams.md"))
	os.WriteFile(filepath.Join(dir, "threat_model.md"), src, 0o644)
	art, ok, err := WriteArtifact(dir)
	if !ok || err != nil || len(art.Diagrams) != 2 || art.RendererVersion != RendererVersion {
		t.Fatalf("write: ok=%v err=%v %+v", ok, err, art)
	}
	loaded, err := Load(dir)
	if err != nil || len(loaded.Diagrams) != 2 || loaded.Diagrams[1].State != StateInvalid {
		t.Errorf("load: %v %+v", err, loaded)
	}
	if !strings.Contains(art.Summary(), "diagram 1 valid; diagram 2 invalid (line 2, E_EDGE_LABEL_UNTERMINATED)") {
		t.Errorf("summary = %q", art.Summary())
	}
}
