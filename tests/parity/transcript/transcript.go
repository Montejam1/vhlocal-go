// Package transcript defines the Go-only response-rule transcript that drives the
// engine deterministically through every phase on the shared fixture (feature 006,
// US2). It is keyed by the semantic situation the engine exposes — the Phase-1
// partition plan, the per-(partition×class) hunt units, and the per-candidate
// verification session — so the same transcript could ground either engine. No
// Python is involved; this is the Go regression gate's input.
package transcript

import (
	"encoding/json"
	"os"
)

// Transcript is the full scripted set of model responses for one fixture run.
type Transcript struct {
	// PartitionTable is the markdown written to phase1_output.md (a Subgraph
	// Partitions table), exercising US1 partition resolution.
	PartitionTable string `json:"partition_table"`
	// Hunt maps a (partition, class) unit to the findings its agent reports.
	Hunt []HuntRule `json:"hunt"`
	// Verify holds the per-candidate verification decisions, matched by location.
	Verify []VerifyRule `json:"verify"`
}

// HuntRule is the finding markdown a hunt agent emits for one (partition, class).
type HuntRule struct {
	Partition string        `json:"partition"` // slug, e.g. "sg-1"
	Class     string        `json:"class"`     // inj | nav | log | all | sink
	Findings  []HuntFinding `json:"findings"`
}

// HuntFinding is one reported candidate (rendered into hunt markdown).
type HuntFinding struct {
	ID         string `json:"id"`
	Title      string `json:"title"`
	CWE        string `json:"cwe"`
	Severity   string `json:"severity"`
	Location   string `json:"location"`
	EntryPoint string `json:"entry_point"`
	DataFlow   string `json:"data_flow"`
}

// VerifyRule is one candidate's scripted verification decision. FuncStart/FuncEnd
// bound the evidence the provider captures (the complete containing function, so a
// supported verdict clears the US3 function-span gate); EntryPoint must equal the
// resolved route guard for a supported route-handler candidate.
type VerifyRule struct {
	Location   string `json:"location"`
	Verdict    string `json:"verdict"` // supported | rejected | unresolved
	FuncStart  int    `json:"func_start"`
	FuncEnd    int    `json:"func_end"`
	EntryPoint string `json:"entry_point"`
	Rationale  string `json:"rationale"`
}

// Load reads and parses a transcript JSON file.
func Load(path string) (*Transcript, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var t Transcript
	if err := json.Unmarshal(b, &t); err != nil {
		return nil, err
	}
	return &t, nil
}

// FindVerify returns the verify rule whose location matches loc (exact), or nil.
func (t *Transcript) FindVerify(loc string) *VerifyRule {
	for i := range t.Verify {
		if t.Verify[i].Location == loc {
			return &t.Verify[i]
		}
	}
	return nil
}
