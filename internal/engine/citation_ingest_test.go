package engine

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"vhlocal/internal/verification"
)

const auditedAmbiguous = "confirm_password_reset function, line 224-242 in backend/app/routers/auth.py"

func huntDetailOf(t *testing.T, results string) []HuntFile {
	t.Helper()
	h, ok := loadHuntExecution(results)
	if !ok {
		t.Fatal("hunt_execution.json unreadable")
	}
	return h.Detail
}

// T063 (C-C1, C-C3, SC-010): a unit whose deliverable cites an unresolvable location
// gets exactly one correction turn with structured feedback; the rewritten file is
// accepted; the record names invalid/repaired/remaining/correction_turns.
func TestCitationCorrectionTurnRepairs(t *testing.T) {
	repo := filepath.Join(repoRoot(t), "testdata", "coverage100")
	results := t.TempDir()
	w := newCitationRepairWriter(auditedAmbiguous, "svc01/routes.py:12")
	if _, err := Execute(context.Background(), coverageSpec(repo, results), Providers{Hunt: w}, staticSkill{}, nil); err != nil {
		t.Fatal(err)
	}
	units, repaired := 0, 0
	for _, f := range huntDetailOf(t, results) {
		if f.Status != HuntFileValid || f.Citation == nil || f.Citation.Findings == 0 {
			continue
		}
		units++
		c := f.Citation
		if c.Invalid != 1 || c.CorrectionTurns != 1 || c.Remaining != 0 || c.Repaired != 1 {
			t.Errorf("%s: citation = %+v (want invalid 1, one correction turn, repaired 1, remaining 0)", f.Path, c)
		}
		if f.Attempts != 2 {
			t.Errorf("%s: the correction turn must count as an attempt: attempts=%d", f.Path, f.Attempts)
		}
		repaired++
	}
	if units == 0 {
		t.Fatal("no unit deliverable carried findings")
	}
	// The feedback reached the model as its own prompt record (kind repair, per finding
	// field/code/received/expected) and never contained a corrected citation.
	fh, err := os.Open(filepath.Join(results, PromptsFile))
	if err != nil {
		t.Fatal(err)
	}
	defer fh.Close()
	sc := bufio.NewScanner(fh)
	sc.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	feedbackRecords := 0
	for sc.Scan() {
		var r PromptRecord
		if json.Unmarshal(sc.Bytes(), &r) != nil {
			continue
		}
		if strings.HasSuffix(r.Label, ".citation") {
			feedbackRecords++
			if r.Kind != "repair" {
				t.Errorf("correction turn kind = %q, want repair", r.Kind)
			}
			for _, want := range []string{"E_CITATION_AMBIGUOUS", "field `location`", "received `", "expected:"} {
				if !strings.Contains(r.Task, want) {
					t.Errorf("feedback lacks %q", want)
				}
			}
			if i := strings.Index(r.Task, "## Citation corrections required"); i < 0 || strings.Contains(r.Task[i:], "svc01/routes.py:12") {
				t.Error("feedback must never hand the model a corrected citation")
			}
		}
	}
	if feedbackRecords == 0 {
		t.Error("no correction-turn prompt record")
	}
}

// T063 (C-C1, C-C8): a citation that stays invalid enters the manifest as
// invalid_citation, counts in raw_count, gets no session, and reaches the report
// appendix with its own class — it is never dropped and never verified.
func TestInvalidCitationIsVisibleNeverVerified(t *testing.T) {
	repo := filepath.Join(repoRoot(t), "testdata", "coverage100")
	results := t.TempDir()
	spec := coverageSpec(repo, results)
	spec.Phases = []string{"1", "2", "2b"}
	w := newCitationRepairWriter(auditedAmbiguous, auditedAmbiguous) // "repair" repeats the bad text
	if _, err := Execute(context.Background(), spec, Providers{Hunt: w}, staticSkill{}, nil); err != nil {
		t.Fatal(err)
	}
	for _, f := range huntDetailOf(t, results) {
		if f.Citation != nil && f.Citation.Findings > 0 && (f.Citation.Remaining != 1 || f.Citation.CorrectionTurns != 1) {
			t.Errorf("%s: %+v (one bounded turn, still invalid)", f.Path, f.Citation)
		}
	}
	mb, _ := os.ReadFile(filepath.Join(results, verification.CandidateManifestFile))
	var man verification.Manifest
	if err := json.Unmarshal(mb, &man); err != nil {
		t.Fatal(err)
	}
	if man.SchemaVersion != verification.ManifestSchema || len(man.Candidates) == 0 || man.RawCount == 0 {
		t.Fatalf("manifest schema=%d candidates=%d raw=%d", man.SchemaVersion, len(man.Candidates), man.RawCount)
	}
	for _, c := range man.Candidates {
		if c.Citation == nil || c.Citation.Status != verification.CitationInvalid || c.Citation.Error == nil || c.Citation.Error.Code != "E_CITATION_AMBIGUOUS" || c.Citation.Original != auditedAmbiguous {
			t.Errorf("candidate %s citation = %+v", c.ID, c.Citation)
		}
	}
	if n := len(verification.LoadSessions(results)); n != 0 {
		t.Errorf("invalid candidates must never get a session: %d sessions", n)
	}
	reasons := reconciliationReasons(t, results)
	if len(reasons) == 0 || !strings.Contains(reasons[0], "invalid citation (E_CITATION_AMBIGUOUS)") {
		t.Errorf("reconciliation reason = %v", reasons)
	}
	mo, _ := os.ReadFile(filepath.Join(results, "report_model.json"))
	var model struct {
		Counts struct {
			TotalCandidates  int `json:"total_candidates"`
			UnresolvedFailed int `json:"unresolved_failed"`
		} `json:"counts"`
		Appendix struct {
			UnresolvedFailed []struct {
				ID, Class, Operation, Code, Message string
			} `json:"unresolved_failed"`
		} `json:"appendix"`
	}
	if err := json.Unmarshal(mo, &model); err != nil {
		t.Fatal(err)
	}
	if model.Counts.TotalCandidates != len(man.Candidates) || len(model.Appendix.UnresolvedFailed) != len(man.Candidates) {
		t.Errorf("report counts = %+v appendix=%d (want every invalid candidate listed)", model.Counts, len(model.Appendix.UnresolvedFailed))
	}
	for _, row := range model.Appendix.UnresolvedFailed {
		if row.Class != ClassInvalidCitation || row.Code != "E_CITATION_AMBIGUOUS" || row.Operation != "citation" {
			t.Errorf("appendix row = %+v", row)
		}
	}
}
