package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"vhlocal/internal/client"
	"vhlocal/internal/verification"
)

// T065 (C-C7, C-C9): a same-anchor amendment keeps the candidate id; a different-
// anchor amendment creates a superseding candidate (no decision inherited); a second
// amendment in a session is refused; regeneration never invokes the model or
// rewrites citations; the evidence contract still gates the decision.
func TestAmendCandidateIdentityRule(t *testing.T) {
	repo, routes, spans := coverageFixture(t)
	all := make([]string, 0, len(spans))
	for _, s := range spans {
		all = append(all, s)
	}
	rw := newReadingWriter(all)
	hs := newHandlerSpans(repo)
	plans := map[string]verifyPlan{}
	amends := map[string]amendPlan{}
	var keptCited, movedCited, targetEntry string
	byPath := map[string]struct {
		r    routeLike
		s, e int
	}{}
	for _, r := range routes {
		sc := hs.scopeFor(r)
		byPath[r.File+" "+r.Path] = struct {
			r    routeLike
			s, e int
		}{routeLike{r.Method, r.Path, r.File}, sc.Start, sc.End}
	}
	// Kept: svc01 /svc01/items cited as "start+1 to start+2"; amended to exactly the
	// last cited line (same statement, same function ⇒ same anchor).
	if h, ok := byPath["svc01/routes.py /svc01/items"]; ok {
		keptCited = fmt.Sprintf("svc01/routes.py:%d-%d", h.s+2, h.s+3)
		rw.findings["svc01/routes.py"] = plantedFinding{Location: keptCited, CWE: "CWE-862", EntryPoint: h.r.method + " " + h.r.path, Title: "Missing authorization on items"}
		plans[keptCited] = verifyPlan{File: "svc01/routes.py", Start: h.s, End: h.e, EntryPoint: h.r.method + " " + h.r.path}
		amends[keptCited] = amendPlan{Path: "svc01/routes.py", Start: h.s + 3, End: h.s + 3, Reason: "the sink is the final statement"}
	}
	// Superseded: svc02 first handler cited; amended into svc02's SECOND handler (a
	// different function ⇒ new identity); evidence/entry point follow the new handler.
	var svc02 []struct {
		r    routeLike
		s, e int
	}
	for _, r := range routes {
		if r.File == "svc02/routes.py" {
			sc := hs.scopeFor(r)
			svc02 = append(svc02, struct {
				r    routeLike
				s, e int
			}{routeLike{r.Method, r.Path, r.File}, sc.Start, sc.End})
		}
	}
	if len(svc02) < 2 {
		t.Fatal("svc02 needs two handlers")
	}
	movedCited = fmt.Sprintf("svc02/routes.py:%d", svc02[0].s+2)
	targetEntry = svc02[1].r.method + " " + svc02[1].r.path
	rw.findings["svc02/routes.py"] = plantedFinding{Location: movedCited, CWE: "CWE-862", EntryPoint: svc02[0].r.method + " " + svc02[0].r.path, Title: "Missing authorization on first"}
	plans[movedCited] = verifyPlan{File: "svc02/routes.py", Start: svc02[1].s, End: svc02[1].e, EntryPoint: targetEntry}
	amends[movedCited] = amendPlan{Path: "svc02/routes.py", Start: svc02[1].s + 2, End: svc02[1].s + 2, Reason: "the real sink is in the next handler"}

	results := t.TempDir()
	spec := coverageSpec(repo, results)
	spec.Phases = []string{"1", "2", "2b"}
	prov := newAmendingVerifier(newVerifyingWriter(rw, plans), amends)
	if _, err := Execute(context.Background(), spec, Providers{Hunt: prov}, staticSkill{}, nil); err != nil {
		t.Fatal(err)
	}
	mb, _ := os.ReadFile(filepath.Join(results, verification.CandidateManifestFile))
	var man verification.Manifest
	if err := json.Unmarshal(mb, &man); err != nil {
		t.Fatal(err)
	}
	if len(man.Amendments) != 2 {
		t.Fatalf("amendments = %+v", man.Amendments)
	}
	var kept, moved verification.Amendment
	for _, a := range man.Amendments {
		if a.Outcome != "accepted" {
			t.Errorf("amendment rejected: %+v", a)
		}
		if a.Identity == "kept" {
			kept = a
		} else if strings.HasPrefix(a.Identity, "superseded_by:") {
			moved = a
		}
	}
	if kept.CandidateID == "" || moved.CandidateID == "" {
		t.Fatalf("want one kept and one superseding amendment: %+v", man.Amendments)
	}
	newID := strings.TrimPrefix(moved.Identity, "superseded_by:")
	byID := map[string]verification.Candidate{}
	for _, c := range man.Candidates {
		byID[c.ID] = c
	}
	if byID[kept.CandidateID].Finding.Location != kept.Amended || byID[kept.CandidateID].Citation.Status != verification.CitationValid {
		t.Errorf("kept candidate not updated: %+v", byID[kept.CandidateID].Finding.Location)
	}
	old, nc := byID[moved.CandidateID], byID[newID]
	if old.Superseded != newID || nc.Supersedes != old.ID || nc.Finding.Location != moved.Amended || len(man.Superseded) != 1 {
		t.Errorf("supersession links: old=%+v new=%+v pairs=%+v", old.Superseded, nc.Supersedes, man.Superseded)
	}
	// Decisions: kept id decided; the NEW id decided (supported through the full
	// evidence contract on the new handler); the old id inherits nothing.
	db, _ := os.ReadFile(filepath.Join(results, verification.DecisionsFile))
	var decs []verification.Decision
	_ = json.Unmarshal(db, &decs)
	decided := map[string]string{}
	for _, d := range decs {
		decided[d.CandidateID] = d.Verdict
	}
	if decided[kept.CandidateID] != "supported" || decided[newID] != "supported" {
		t.Errorf("decisions = %v", decided)
	}
	if _, has := decided[old.ID]; has {
		t.Error("the superseded candidate must not carry a decision")
	}
	reasons := reconciliationReasons(t, results)
	joined := strings.Join(reasons, " | ")
	if !strings.Contains(joined, "superseded: superseded by "+newID) {
		t.Errorf("reconciliation must mark the old id superseded: %v", reasons)
	}
	// findings.json: the old identity folds into the new one as a duplicate.
	fj := loadFindings(t, results)
	for _, f := range fj["findings"].([]any) {
		m := f.(map[string]any)
		if m["id"] == old.ID && m["duplicate_of"] != newID {
			t.Errorf("superseded finding duplicate_of = %v", m["duplicate_of"])
		}
	}
	if fj["class_counts"].(map[string]any)["supported"] != float64(2) {
		t.Errorf("class counts = %v", fj["class_counts"])
	}
	// Regeneration never invokes a model and never rewrites citations.
	before, _ := os.ReadFile(filepath.Join(results, verification.CandidateManifestFile))
	if err := Regenerate(results); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(filepath.Join(results, verification.CandidateManifestFile))
	if string(before) != string(after) {
		t.Error("regeneration rewrote the candidate manifest")
	}
	// A second amendment in one session is refused.
	res := agentResult{Amended: true}
	out, decidedNow, _, stop := handleVerifyTool(nil, repo, &man, &man.Candidates[0], client.ToolCall{ID: "a", Name: "amend_candidate",
		Arguments: `{"candidate_id":"` + man.Candidates[0].ID + `","path":"svc01/routes.py","start_line":9,"end_line":9,"reason":"x"}`}, map[string]verification.Evidence{}, new(int), &res)
	if decidedNow || stop != "" || !strings.Contains(out, verification.EAmendmentLimit) {
		t.Errorf("second amendment must be refused: %s", out)
	}
	// An amendment that does not resolve is rejected with the citation code.
	res2 := agentResult{}
	out2, _, _, _ := handleVerifyTool(nil, repo, &man, &man.Candidates[0], client.ToolCall{ID: "b", Name: "amend_candidate",
		Arguments: `{"candidate_id":"` + man.Candidates[0].ID + `","path":"svc01/routes.py","start_line":900,"end_line":900,"reason":"x"}`}, map[string]verification.Evidence{}, new(int), &res2)
	if !strings.Contains(out2, "E_RANGE_OUT_OF_BOUNDS") || res2.Amended {
		t.Errorf("unresolvable amendment must be rejected: %s", out2)
	}
}

type routeLike struct{ method, path, file string }
