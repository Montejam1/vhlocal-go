package engine

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"vhlocal/internal/consolidate"
	"vhlocal/internal/report"
	"vhlocal/internal/verification"
)

// Feature 016 T083 (FR-026, C-C9, C-C10, C-C11): regeneration produces the reader-facing
// report from records alone.
//
// Repeated regeneration produces identical primary content; every record, decision, identity
// and evidence reference survives; no provider is called, no scan starts and no target code
// runs; and an unfinished results directory is refused rather than half-regenerated.
//
// The corpus is built here from verification records — the same shape the engine writes — so
// regeneration has something real to re-derive. Everything is written under t.TempDir(); the
// operator's own stores are never read or touched (FR-028, C-C13). The frozen
// testdata/report016 fixture is a report-rendering corpus and carries no raw phase outputs,
// so it is exercised by the report package's own regeneration tests instead.
func TestRegenerate016IsDeterministicAndOffline(t *testing.T) {
	repo, results := seedRegenerable016(t)

	if err := Regenerate(results); err != nil {
		t.Fatalf("first regeneration failed: %v", err)
	}
	first := readPresentation016(t, results)
	firstMD := readFile016(t, filepath.Join(results, report.MDFile))
	firstHTML := readFile016(t, filepath.Join(results, report.HTMLFile))
	firstModel := readFile016(t, filepath.Join(results, report.ModelFile))

	for i := 2; i <= 3; i++ {
		if err := Regenerate(results); err != nil {
			t.Fatalf("regeneration %d failed: %v", i, err)
		}
		if got := readFile016(t, filepath.Join(results, report.MDFile)); got != firstMD {
			t.Errorf("regeneration %d produced a different SCAN_REPORT.md", i)
		}
		if got := readFile016(t, filepath.Join(results, report.HTMLFile)); got != firstHTML {
			t.Errorf("regeneration %d produced a different SCAN_REPORT.html", i)
		}
		if got := readFile016(t, filepath.Join(results, report.ModelFile)); got != firstModel {
			t.Errorf("regeneration %d produced a different report_model.json", i)
		}
	}

	// The projection is there, versioned, with the reader-facing unit.
	if first.Version != report.PresentationVersion {
		t.Errorf("presentation version = %d, want %d", first.Version, report.PresentationVersion)
	}
	if len(first.Issues) == 0 {
		t.Fatal("regeneration produced no primary issues")
	}

	// Identities and decisions survive: each supported detection is accounted for exactly
	// once, the rejected candidate is still dismissed, and the undecided one still needs
	// review. None of the three changes category on a re-render.
	supported := supportedIDs016(t, results)
	seen := map[string]int{}
	for _, is := range first.Issues {
		for _, mem := range is.Members {
			seen[mem.FindingID]++
		}
	}
	for id := range supported {
		if seen[id] != 1 {
			t.Errorf("detection %s appears in %d issues after regeneration, want 1", id, seen[id])
		}
	}
	if len(seen) != len(supported) {
		t.Errorf("regeneration accounts for %d detections, the records hold %d", len(seen), len(supported))
	}
	if len(first.Dismissed) != 1 {
		t.Errorf("dismissed = %d, want the 1 rejected candidate", len(first.Dismissed))
	}
	if len(first.ReviewItems) != 1 {
		t.Errorf("review items = %d, want the 1 candidate with no decision", len(first.ReviewItems))
	}
	if first.Counts.IssuesToFix != len(first.Issues) {
		t.Errorf("headline %d does not match %d issues", first.Counts.IssuesToFix, len(first.Issues))
	}

	// Evidence references survive the round trip, with their recorded ranges.
	excerpts := 0
	for _, is := range first.Issues {
		for _, e := range is.Evidence {
			excerpts++
			if e.Path == "" || e.Start == 0 {
				t.Errorf("%s carries an evidence excerpt with no citation: %+v", is.Ref, e)
			}
			if !strings.Contains(firstMD, fmt.Sprintf("`%s:%d-%d`", e.Path, e.Start, e.End)) {
				t.Errorf("%s evidence citation %s:%d-%d is not in the document", is.Ref, e.Path, e.Start, e.End)
			}
		}
	}
	if excerpts == 0 {
		t.Error("regeneration produced no evidence excerpts although the records carry them")
	}

	// Offline and static: no provider was called and no target code ran.
	if _, err := os.Stat(filepath.Join(results, "prompts.jsonl")); err == nil {
		t.Error("regeneration wrote a prompt record, which means a provider was called")
	}
	for _, bad := range []string{"tests ran", "exploit succeeded", "scan started"} {
		if strings.Contains(strings.ToLower(firstMD), bad) {
			t.Errorf("the regenerated report claims %q", bad)
		}
	}
	// The repository under review is untouched by regeneration.
	if got := readFile016(t, filepath.Join(repo, "app", "db.py")); !strings.Contains(got, "conn.execute") {
		t.Error("regeneration modified the repository under review")
	}
}

// T083 (C-C11): an unfinished record is refused, and the refusal rewrites nothing.
func TestRegenerate016RefusesUnfinishedRecords(t *testing.T) {
	_, results := seedRegenerable016(t)
	if err := Regenerate(results); err != nil {
		t.Fatal(err)
	}
	before := readFile016(t, filepath.Join(results, report.MDFile))

	// A scan that is still running: the engine stamps schema "partial" while it writes, so
	// this is the state of an actively-writing directory.
	patchScanMeta016(t, results, map[string]any{"schema": "partial", "status": "running"})
	err := Regenerate(results)
	if err == nil {
		t.Fatal("regeneration of an unfinished scan must be refused")
	}
	if !strings.Contains(err.Error(), "unfinished") {
		t.Errorf("the refusal does not say why: %v", err)
	}
	if after := readFile016(t, filepath.Join(results, report.MDFile)); after != before {
		t.Error("a refused regeneration still rewrote the report")
	}

	// A directory with no record is refused by name rather than panicking.
	empty := t.TempDir()
	if err := Regenerate(empty); err == nil {
		t.Fatal("regeneration of a directory with no record must be refused")
	} else if !strings.Contains(err.Error(), ScanMetaFile) {
		t.Errorf("the refusal does not name the missing record: %v", err)
	}

	// A finished record whose status field was left "running" by an older engine still
	// regenerates: the guard is the schema, not a stale label.
	patchScanMeta016(t, results, map[string]any{"schema": "", "status": "running"})
	if err := Regenerate(results); err != nil {
		t.Errorf("a complete record with a stale status field must still regenerate: %v", err)
	}
}

// seedRegenerable016 writes a results directory the engine can regenerate: a small repository,
// a verification manifest with three candidates, one supported decision, one rejection, one
// candidate with no decision, and a scan record naming the phases that ran.
func seedRegenerable016(t *testing.T) (repo, results string) {
	t.Helper()
	repo, results = t.TempDir(), t.TempDir()
	if err := os.MkdirAll(filepath.Join(repo, "app"), 0o755); err != nil {
		t.Fatal(err)
	}
	db := "def run(q):\n    return conn.execute(q)\n"
	write016(t, filepath.Join(repo, "app", "db.py"), db)
	files := "def read(p):\n    return open(INVOICE_DIR + p).read()\n"
	write016(t, filepath.Join(repo, "app", "files.py"), files)
	write016(t, filepath.Join(repo, "app", "api.py"), "def get(i):\n    return Order.find(i)\n")

	mk := func(id, cwe, loc, entry, flow string) consolidate.Finding {
		f := consolidate.NewFinding(id)
		f.CWE, f.Location, f.EntryPoint, f.DataFlow = cwe, loc, entry, flow
		f.Title = "Issue at " + loc
		consolidate.ApplyKnowledge(&f)
		return f
	}
	cands := []consolidate.Finding{
		mk("V1", "CWE-89", "app/db.py:2", "GET /search", "q -> execute()"),
		mk("V2", "CWE-22", "app/files.py:2", "GET /invoice", "p -> open()"),
		mk("V3", "CWE-639", "app/api.py:2", "GET /order", "i -> find()"),
	}
	man, err := verification.BuildManifest(results, repo, "rev016", cands)
	if err != nil {
		t.Fatal(err)
	}
	idFor := map[string]string{}
	for _, c := range man.Candidates {
		idFor[c.Finding.Location] = c.ID
	}

	decs := []verification.Decision{
		{
			CandidateID: idFor["app/db.py:2"], Verdict: "supported",
			Rationale: "the query parameter reaches execute unsanitized", EntryPoint: "GET /search",
			AttackerControl: "the q query parameter", Preconditions: "none",
			DefensesReviewed: "none observed", SecurityImpact: "read and write of arbitrary rows",
			Revision: "rev016", Reviewer: "phase2b-model",
			Evidence: []verification.Evidence{{ID: "EV-1", Path: "app/db.py", StartLine: 1, EndLine: 2, Quote: strings.TrimRight(db, "\n")}},
		},
		{
			CandidateID: idFor["app/files.py:2"], Verdict: "rejected",
			Rationale: "the path is confined under INVOICE_DIR", EntryPoint: "GET /invoice",
			AttackerControl: "the p path segment", Preconditions: "none",
			DefensesReviewed: "the directory prefix is fixed", SecurityImpact: "none established",
			Revision: "rev016", Reviewer: "phase2b-model",
			Evidence: []verification.Evidence{{ID: "EV-2", Path: "app/files.py", StartLine: 1, EndLine: 2, Quote: strings.TrimRight(files, "\n")}},
		},
	}
	writeJSONFile(t, filepath.Join(results, verification.DecisionsFile), decs)
	// The third candidate's session ended without a decision.
	writeJSONFile(t, filepath.Join(results, verification.SessionsFile),
		[]verification.SessionOutcome{{CandidateID: idFor["app/api.py:2"], StopReason: "max_turns", Turns: 20, Failures: 2}})

	meta := map[string]any{
		"repo": repo, "results_dir": results, "model": "gpt-oss:120b", "backend": "ollama",
		"host": "http://127.0.0.1:11434", "num_ctx": 8192,
		"phases_requested": []string{"1", "2", "2b", "4"},
		"phases_completed": []string{"1", "2", "2b", "4"},
		"agents":           []any{map[string]any{"label": "2b", "phase": "2b", "stopped_reason": "complete", "turns": 6}},
		"usage":            map[string]any{}, "engine_version": "test", "quality_strictness": "balanced",
		"started_at": 1.0, "finished_at": 2.0,
	}
	b, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	write016(t, filepath.Join(results, ScanMetaFile), string(b))
	// phase2b_output.md must exist for the 2b phase to stay valid on re-render.
	write016(t, filepath.Join(results, "phase2b_output.md"), "# Verification\n\nDecisions were submitted through the tool contract.\n")
	return repo, results
}

func write016(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func readFile016(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}

func readPresentation016(t *testing.T, dir string) *report.Presentation {
	t.Helper()
	var m report.ReportModel
	if err := json.Unmarshal([]byte(readFile016(t, filepath.Join(dir, report.ModelFile))), &m); err != nil {
		t.Fatal(err)
	}
	if m.Presentation == nil {
		t.Fatal("the regenerated model carries no presentation projection")
	}
	return m.Presentation
}

func supportedIDs016(t *testing.T, dir string) map[string]bool {
	t.Helper()
	var doc struct {
		Findings []map[string]any `json:"findings"`
	}
	if err := json.Unmarshal([]byte(readFile016(t, filepath.Join(dir, "findings.json"))), &doc); err != nil {
		t.Fatal(err)
	}
	out := map[string]bool{}
	for _, f := range doc.Findings {
		if consolidate.Classify(f) == consolidate.ClassSupported {
			id, _ := f["id"].(string)
			out[id] = true
		}
	}
	return out
}

func patchScanMeta016(t *testing.T, dir string, fields map[string]any) {
	t.Helper()
	path := filepath.Join(dir, ScanMetaFile)
	var meta map[string]any
	if err := json.Unmarshal([]byte(readFile016(t, path)), &meta); err != nil {
		t.Fatal(err)
	}
	for k, v := range fields {
		meta[k] = v
	}
	b, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	write016(t, path, string(b))
}
