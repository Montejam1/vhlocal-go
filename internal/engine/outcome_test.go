package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"vhlocal/internal/client"
	"vhlocal/internal/config"
	"vhlocal/internal/verification"
)

// replayScenario mirrors testdata/replay-audit/scenario.json (feature 014, T004).
type replayScenario struct {
	Repo        string   `json:"repo"`
	Phases      []string `json:"phases"`
	ThreatModel bool     `json:"threat_model"`
	SilentUnit  string   `json:"silent_hunt_unit"`
	Supported   struct {
		File, Path, CWE string
	} `json:"supported_candidate"`
	Exhausted struct {
		File, Path, CWE, Class string
	} `json:"exhausted_candidate"`
	OrphanArtifact string `json:"orphan_artifact"`
	Expected       struct {
		ExecutionStatus        string   `json:"execution_status"`
		CoverageStatus         string   `json:"coverage_status"`
		DisabledOptionalPhases []string `json:"disabled_optional_phases"`
		FailedAssignmentStatus string   `json:"failed_assignment_status"`
		FailedCandidateClass   string   `json:"failed_candidate_class"`
		MissingArtifactMarkers []string `json:"missing_artifact_markers"`
	} `json:"expected"`
}

func loadReplayScenario(t *testing.T) replayScenario {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(repoRoot(t), "testdata", "replay-audit", "scenario.json"))
	if err != nil {
		t.Fatal(err)
	}
	var s replayScenario
	if err := json.Unmarshal(b, &s); err != nil {
		t.Fatal(err)
	}
	return s
}

// replayProvider induces the audited failure shapes on top of verifyingWriter:
// the named hunt unit is silent (no Write, on both attempts), the named candidate's
// verification session reads validly until the turn limit and never submits, and
// everything else behaves (reads every span, supports the planted candidate).
type replayProvider struct {
	vw        *verifyingWriter
	silent    string
	exhausted string
}

func (p *replayProvider) Backend() client.Backend { return "fake" }
func (p *replayProvider) Endpoint() string        { return "fake://local" }
func (p *replayProvider) Chat(ctx context.Context, req client.ChatRequest) (*client.ChatResponse, error) {
	task := ""
	for _, m := range req.Messages {
		if m.Role == "user" {
			task = m.Content
			break
		}
	}
	if strings.HasPrefix(task, "Verify EXACTLY this one candidate") {
		if strings.Contains(task, p.exhausted) {
			args := fmt.Sprintf(`{"file_path":%q,"offset":1,"limit":5}`, p.exhausted)
			return &client.ChatResponse{Model: "m", Message: client.Message{Role: "assistant",
				ToolCalls: []client.ToolCall{{ID: "x", Name: "Read", Arguments: args}}}}, nil
		}
		return p.vw.Chat(ctx, req)
	}
	inScope := strings.Contains(task, p.silent+" ") || strings.Contains(task, p.silent+"\n") || strings.Contains(task, p.silent+"/")
	if strings.Contains(task, "/results/") && inScope && !strings.Contains(task, "_followup") {
		return &client.ChatResponse{Message: client.Message{Role: "assistant", Content: "done"},
			Usage: client.Usage{PromptTokens: 5, CompletionTokens: 2}}, nil
	}
	return p.vw.Chat(ctx, req)
}

// runReplay executes the replay scenario into results and returns the record.
func runReplay(t *testing.T, results string) (*RunRecord, replayScenario) {
	t.Helper()
	sc := loadReplayScenario(t)
	repo, routes, spans := coverageFixture(t)
	all := make([]string, 0, len(spans))
	for _, s := range spans {
		all = append(all, s)
	}
	rw := newReadingWriter(all)
	plans := map[string]verifyPlan{}
	hs := newHandlerSpans(repo)
	for _, r := range routes {
		plant := func(cwe string, withPlan bool) {
			s := hs.scopeFor(r)
			loc := fmt.Sprintf("%s:%d", r.File, s.Start+1)
			entry := r.Method + " " + r.Path
			rw.findings[r.File] = plantedFinding{Location: loc, CWE: cwe, EntryPoint: entry, Title: "Missing authorization on " + entry}
			if withPlan {
				plans[loc] = verifyPlan{File: r.File, Start: s.Start, End: s.End, EntryPoint: entry}
			}
		}
		switch {
		case r.File == sc.Supported.File && r.Path == sc.Supported.Path:
			plant(sc.Supported.CWE, true)
		case r.File == sc.Exhausted.File && r.Path == sc.Exhausted.Path:
			plant(sc.Exhausted.CWE, false)
		}
	}
	if len(rw.findings) != 2 {
		t.Fatalf("scenario must plant exactly 2 candidates, planted %d", len(rw.findings))
	}
	os.MkdirAll(filepath.Dir(filepath.Join(results, sc.OrphanArtifact)), 0o755)
	if err := os.WriteFile(filepath.Join(results, sc.OrphanArtifact), []byte("# not registered\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	spec := coverageSpec(repo, results)
	spec.Phases = sc.Phases
	spec.ThreatModel = sc.ThreatModel
	prov := &replayProvider{vw: newVerifyingWriter(rw, plans), silent: sc.SilentUnit, exhausted: sc.Exhausted.File}
	rec, err := Execute(context.Background(), spec, Providers{Hunt: prov}, staticSkill{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return rec, sc
}

// outcomeJSON returns the canonical JSON of run_status.outcome from findings.json.
func outcomeJSON(t *testing.T, results string) []byte {
	t.Helper()
	doc := loadFindings(t, results)
	rs, _ := doc["run_status"].(map[string]any)
	oc, ok := rs["outcome"]
	if !ok || oc == nil {
		t.Fatal("findings.json run_status.outcome missing")
	}
	b, _ := json.Marshal(oc)
	return b
}

func canonical(t *testing.T, v any) []byte {
	t.Helper()
	b, _ := json.Marshal(v)
	var m any
	if json.Unmarshal(b, &m) != nil {
		t.Fatal("not JSON")
	}
	out, _ := json.Marshal(m)
	return out
}

func sectionOf(md, heading string) string {
	i := strings.Index(md, heading)
	if i < 0 {
		return ""
	}
	rest := md[i+len(heading):]
	if j := strings.Index(rest, "\n## "); j >= 0 {
		rest = rest[:j]
	}
	return rest
}

// T047 (SC-009, FR-021..023): the completion block is identical in scan_meta.json,
// findings.json run_status.outcome, the Markdown and HTML reports, and the
// regenerated view; execution partial + coverage degraded with reasons, on the
// replay of the audited failure categories.
func TestOutcomeConsistentAcrossRecordsReportAndRegeneration(t *testing.T) {
	results := t.TempDir()
	rec, sc := runReplay(t, results)
	if rec.Outcome == nil {
		t.Fatal("RunRecord.Outcome not assembled")
	}
	o := rec.Outcome

	// --- the audited categories are each visible as their own axis ---
	if o.Units.Total != 100 {
		t.Errorf("units.total = %d, want 100", o.Units.Total)
	}
	// The silent unit's routes are either failed/skipped, or recovered by the ONE bounded
	// follow-up unit (coverage enforcement) — in which case the failed assignments
	// below still stay listed: recovery never hides the failure (FR-017).
	ru0 := reviewUnitsOf(t, results)
	if o.Units.Failed+o.Units.Skipped == 0 && !ru0.FollowUpRan {
		t.Errorf("silent unit %s left no failed/skipped routes and no follow-up ran: %+v", sc.SilentUnit, o.Units)
	}
	if o.Candidates.Supported != 1 || o.Candidates.Unresolved != 1 {
		t.Errorf("candidates = %+v, want supported=1 unresolved=1", o.Candidates)
	}
	if len(o.FailedAssignments) == 0 {
		t.Fatal("failed_assignments empty; the silent unit's deliverable must be listed")
	}
	for _, fa := range o.FailedAssignments {
		if fa.UnitID == "" || !strings.Contains(fa.UnitID, "sg-") {
			t.Errorf("failed assignment %s must name its unit, got %q", fa.Path, fa.UnitID)
		}
		if !strings.Contains(fa.Reason, "never written after 2 attempt(s)") {
			t.Errorf("failed assignment %s reason %q should name the missing deliverable", fa.Path, fa.Reason)
		}
	}
	if len(o.FailedCandidates) != 1 || o.FailedCandidates[0].Class != sc.Expected.FailedCandidateClass {
		t.Errorf("failed_candidates = %+v, want one of class %s", o.FailedCandidates, sc.Expected.FailedCandidateClass)
	}
	joined := strings.Join(o.MissingArtifacts, " | ")
	for _, m := range sc.Expected.MissingArtifactMarkers {
		if !strings.Contains(joined, m) {
			t.Errorf("missing_artifacts lacks %q: %v", m, o.MissingArtifacts)
		}
	}
	if !reflect.DeepEqual(o.DisabledOptionalPhases, sc.Expected.DisabledOptionalPhases) {
		t.Errorf("disabled_optional_phases = %v, want %v", o.DisabledOptionalPhases, sc.Expected.DisabledOptionalPhases)
	}
	if _, err := os.Stat(filepath.Join(results, sc.OrphanArtifact)); err != nil {
		t.Error("orphan artifact must be kept on disk")
	}
	steps := strings.Join(o.RecoverySteps, " | ")
	for _, want := range []string{"failed hunt assignment", "turn limit", "reproduction", "threat_model=true", "scan log"} {
		if !strings.Contains(steps, want) {
			t.Errorf("recovery_steps lack a %q step: %v", want, o.RecoverySteps)
		}
	}

	// --- axes stay independent; job termination is not part of run_status ---
	doc := loadFindings(t, results)
	rs := doc["run_status"].(map[string]any)
	if rs["execution_status"] != sc.Expected.ExecutionStatus || rs["coverage_status"] != sc.Expected.CoverageStatus {
		t.Errorf("run_status = %v/%v, want %s/%s", rs["execution_status"], rs["coverage_status"], sc.Expected.ExecutionStatus, sc.Expected.CoverageStatus)
	}
	if n := len(toAnySlice(rs["coverage_degraded_reasons"])); n == 0 {
		t.Error("coverage degraded without reasons")
	}
	if _, has := rs["status"]; has {
		t.Error("run_status must not carry the queue job status")
	}

	// --- identical block everywhere ---
	fromFindings := outcomeJSON(t, results)
	fromRecord := canonical(t, o)
	if string(fromFindings) != string(fromRecord) {
		t.Errorf("findings.json outcome differs from RunRecord.Outcome:\n%s\n%s", fromFindings, fromRecord)
	}
	meta := readJSON(t, filepath.Join(results, ScanMetaFile))
	if string(canonical(t, meta["outcome"])) != string(fromRecord) {
		t.Error("scan_meta.json outcome differs from RunRecord.Outcome")
	}
	md, _ := os.ReadFile(filepath.Join(results, "SCAN_REPORT.md"))
	html, _ := os.ReadFile(filepath.Join(results, "SCAN_REPORT.html"))
	comp := sectionOf(string(md), "## Completion")
	if comp == "" {
		t.Fatal("SCAN_REPORT.md has no Completion section")
	}
	u := o.Units
	wantUnits := fmt.Sprintf("%d reviewed of %d entry points — %d with findings, %d no issue, %d partial, %d failed, %d skipped, %d unsupported, %d not reviewed",
		u.ReviewedWithFindings+u.ReviewedNoIssue, u.Total, u.ReviewedWithFindings, u.ReviewedNoIssue, u.Partial, u.Failed, u.Skipped, u.Unsupported, u.NotReviewed)
	wantCands := fmt.Sprintf("%d supported, %d rejected, %d unresolved", o.Candidates.Supported, o.Candidates.Rejected, o.Candidates.Unresolved)
	for _, want := range []string{
		wantUnits, wantCands,
		fmt.Sprintf("**Failed assignments** ([hunt_execution.json](hunt_execution.json)): %d", len(o.FailedAssignments)),
		fmt.Sprintf("**Failed candidates** ([verification_sessions.json](verification_sessions.json)): %d", len(o.FailedCandidates)),
		fmt.Sprintf("**Missing artifacts** ([artifact_manifest.json](artifact_manifest.json)): %d", len(o.MissingArtifacts)),
		"1t (threat_model=false)",
	} {
		if !strings.Contains(comp, want) {
			t.Errorf("Markdown Completion lacks %q:\n%s", want, comp)
		}
	}
	// Feature 015: per-candidate failure classes are rendered once, in the operator
	// section. Feature 016 (T036) moved that section from "Appendix A — Unresolved
	// (session failed)" into "Scan details — Unfinished verification sessions", because a
	// verification failure class is scanner troubleshooting rather than a vulnerability
	// (FR-003). The guarantee asserted here is unchanged.
	if ops := sectionOf(string(md), "### Unfinished verification sessions"); !strings.Contains(ops, "["+sc.Expected.FailedCandidateClass+"]") {
		t.Errorf("Scan details lacks the failed candidate class %q:\n%s", sc.Expected.FailedCandidateClass, ops)
	}
	for i, s := range o.RecoverySteps {
		if !strings.Contains(comp, fmt.Sprintf("%d. %s", i+1, s)) {
			t.Errorf("Markdown Completion lacks recovery step %d", i+1)
		}
	}
	for _, want := range []string{"<h3>Completion</h3>", wantUnits, wantCands, `<a href="review_units.json">`, `<a href="hunt_execution.json">`, `<a href="verification_sessions.json">`, `<a href="artifact_manifest.json">`} {
		if !strings.Contains(string(html), want) {
			t.Errorf("HTML report lacks %q", want)
		}
	}
	// Review coverage section (FR-016): every unreviewed route with its reason.
	ru := reviewUnitsOf(t, results)
	rc := sectionOf(string(md), "## Review coverage")
	if rc == "" {
		t.Fatal("SCAN_REPORT.md has no Review coverage section")
	}
	if !strings.Contains(rc, fmt.Sprintf("Unreviewed entry points ([review_units.json](review_units.json)): %d", len(ru.Gaps))) {
		t.Errorf("Review coverage header does not carry the gap count %d:\n%s", len(ru.Gaps), rc)
	}
	for _, g := range ru.Gaps {
		if !strings.Contains(rc, "`"+g.RouteID+"` — "+g.Reason) {
			t.Errorf("Review coverage lacks gap %s (%s)", g.RouteID, g.Reason)
		}
	}

	// --- regeneration reproduces the identical block from records only ---
	if err := Regenerate(results); err != nil {
		t.Fatal(err)
	}
	if again := outcomeJSON(t, results); string(again) != string(fromFindings) {
		t.Errorf("regenerated outcome differs:\n%s\n%s", again, fromFindings)
	}
	md2, _ := os.ReadFile(filepath.Join(results, "SCAN_REPORT.md"))
	if sectionOf(string(md2), "## Completion") != comp {
		t.Error("regenerated Completion section differs from the live one")
	}
	if sectionOf(string(md2), "## Review coverage") != rc {
		t.Error("regenerated Review coverage section differs from the live one")
	}
}

// T048 (FR-023): regeneration alters no finding evidence and no human review
// decision — byte-compare every evidence/record file before and after.
func TestRegenerationLeavesEvidenceAndReviewsUntouched(t *testing.T) {
	results := t.TempDir()
	runReplay(t, results)

	// A human review decision in the (isolated) reviews store.
	reviews := config.ReviewsDir()
	os.MkdirAll(reviews, 0o755)
	reviewFile := filepath.Join(reviews, filepath.Base(results)+".json")
	if err := os.WriteFile(reviewFile, []byte(`{"VULN-001":{"decision":"accepted_risk","by":"operator"}}`), 0o644); err != nil {
		t.Fatal(err)
	}

	evidence := []string{
		verification.DecisionsFile, verification.CandidateManifestFile, verification.SessionsFile,
		verification.ArtifactManifestFile, "hunt_execution.json", ReviewUnitsFile,
		"phase1_output.md", "phase2b_output.md", "poc/stray_test.py",
	}
	entries, _ := os.ReadDir(filepath.Join(results, "results"))
	for _, e := range entries {
		if !e.IsDir() {
			evidence = append(evidence, "results/"+e.Name())
		}
	}
	snap := func() map[string]string {
		m := map[string]string{}
		for _, rel := range evidence {
			b, err := os.ReadFile(filepath.Join(results, rel))
			if err != nil {
				continue // absent stays absent — recorded as missing below
			}
			m[rel] = string(b)
		}
		b, _ := os.ReadFile(reviewFile)
		m["<review>"] = string(b)
		return m
	}
	before := snap()
	for _, must := range []string{verification.DecisionsFile, verification.SessionsFile, "hunt_execution.json", ReviewUnitsFile} {
		if _, ok := before[must]; !ok {
			t.Fatalf("replay run did not persist %s", must)
		}
	}
	if err := Regenerate(results); err != nil {
		t.Fatal(err)
	}
	after := snap()
	var changed []string
	for k, v := range before {
		if after[k] != v {
			changed = append(changed, k)
		}
	}
	for k := range after {
		if _, ok := before[k]; !ok {
			changed = append(changed, k+" (new)")
		}
	}
	sort.Strings(changed)
	if len(changed) > 0 {
		t.Errorf("regeneration changed evidence/review files: %v", changed)
	}
}

func readJSON(t *testing.T, path string) map[string]any {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func toAnySlice(v any) []any {
	s, _ := v.([]any)
	return s
}
