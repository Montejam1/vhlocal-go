package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"vhlocal/internal/verification"
)

// verifiedSpec: hunt + verification over vulnapp (pathWriter emits VULN-001 at
// app/db.py:21, a real candidate), so the 2b session behavior under test runs.
func verifiedSpec(repo, results string) ScanSpec {
	s := brokenSpec(repo, results)
	s.Phases = []string{"1", "2", "2b"}
	return s
}

func sessionsOf(t *testing.T, results string) map[string]verification.SessionOutcome {
	t.Helper()
	m := verification.LoadSessions(results)
	if len(m) == 0 {
		t.Fatal("verification_sessions.json missing or empty")
	}
	return m
}

func reconciliationReasons(t *testing.T, results string) []string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(results, verification.ReconciliationFile))
	if err != nil {
		t.Fatal(err)
	}
	var rc struct {
		Results []struct {
			Status string `json:"status"`
			Reason string `json:"reason"`
		} `json:"results"`
	}
	if err := json.Unmarshal(b, &rc); err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, r := range rc.Results {
		out = append(out, r.Status+": "+r.Reason)
	}
	return out
}

// Feature 014 (FR-018, SC-007, T040): each failure class is recorded per candidate
// with the failed operation; persistent failures stay unresolved with an actionable
// reason citing the dominant class; evidence validation is not weakened.
func TestVerificationFailureTaxonomy(t *testing.T) {
	repo := filepath.Join(repoRoot(t), "testdata", "vulnapp")
	cases := []struct {
		class    string
		wantStop string
		op       string
	}{
		{"transport", "endpoint_failure", "chat"},
		{"tool_envelope", "tool_repair", "chat"},
		{"invalid_tool_args", "", "Read"}, // never submits → max_turns; args failures recorded
		// Feature 015 (C-C6): the double repeats the IDENTICAL rejected submission, so
		// the session now ends with repeated_submission after the second one.
		{"invalid_submission", "repeated_submission", "submit_verification"},
		{"turn_exhaustion", "max_turns", "turn limit"},
	}
	for _, c := range cases {
		t.Run(c.class, func(t *testing.T) {
			results := t.TempDir()
			if _, err := Execute(context.Background(), verifiedSpec(repo, results), Providers{Hunt: newFailureClassProvider(c.class)}, staticSkill{}, nil); err != nil {
				t.Fatal(err)
			}
			ss := sessionsOf(t, results)
			var s verification.SessionOutcome
			for _, v := range ss {
				s = v
				break
			}
			if s.FailuresByClass[c.class] == 0 {
				t.Errorf("failures_by_class[%s] should be >0: %+v", c.class, s)
			}
			if c.wantStop != "" && s.StopReason != c.wantStop {
				t.Errorf("stop_reason = %q, want %q", s.StopReason, c.wantStop)
			}
			if s.LastOperation != c.op && c.class != "turn_exhaustion" {
				t.Errorf("last_operation = %q, want %q", s.LastOperation, c.op)
			}
			if c.class == "invalid_submission" && s.LastContractViolation == "" {
				t.Error("an invalid submission must record the violated contract")
			}
			// Persistent failure → unresolved with a reason naming the class.
			reasons := reconciliationReasons(t, results)
			joined := strings.Join(reasons, " | ")
			if !strings.Contains(joined, "unresolved") || !strings.Contains(joined, "dominant failure: "+c.class) {
				t.Errorf("reconciliation must stay unresolved citing %s; got %v", c.class, reasons)
			}
		})
	}
}

// FR-018 (repairable): one provider tool-envelope error is repaired within the
// session and the candidate is still SUPPORTED through the full evidence contract.
func TestVerificationRepairableEnvelopeRecovers(t *testing.T) {
	repo, routes, spans := coverageFixture(t)
	all := make([]string, 0, len(spans))
	for _, s := range spans {
		all = append(all, s)
	}
	rw := newReadingWriter(all)
	plans := map[string]verifyPlan{}
	hs := newHandlerSpans(repo)
	for _, r := range routes {
		if r.File == "svc01/routes.py" && r.Path == "/svc01/items" {
			sc := hs.scopeFor(r)
			loc := fmt.Sprintf("%s:%d", r.File, sc.Start+1)
			entry := r.Method + " " + r.Path
			rw.findings[r.File] = plantedFinding{Location: loc, CWE: "CWE-862", EntryPoint: entry, Title: "Missing authorization on " + entry}
			plans[loc] = verifyPlan{File: r.File, Start: sc.Start, End: sc.End, EntryPoint: entry}
		}
	}
	results := t.TempDir()
	spec := coverageSpec(repo, results)
	spec.Phases = []string{"1", "2", "2b"}
	prov := &envelopeOnce{inner: newVerifyingWriter(rw, plans)}
	if _, err := Execute(context.Background(), spec, Providers{Hunt: prov}, staticSkill{}, nil); err != nil {
		t.Fatal(err)
	}
	ss := sessionsOf(t, results)
	for _, s := range ss {
		if s.FailuresByClass["tool_envelope"] != 1 {
			t.Errorf("expected exactly one repaired tool_envelope failure, got %+v", s.FailuresByClass)
		}
		if s.StopReason != "complete" {
			t.Errorf("repairable session should complete, got %q", s.StopReason)
		}
	}
	reasons := reconciliationReasons(t, results)
	if len(reasons) != 1 || !strings.HasPrefix(reasons[0], "supported") {
		t.Errorf("candidate should be supported after repair: %v", reasons)
	}
}

// FR-018 (T041): cancellation mid-verification flushes session outcomes (incl. the
// cancelled one) — nothing is lost to a cancel.
func TestVerificationSessionsFlushedOnCancel(t *testing.T) {
	repo := filepath.Join(repoRoot(t), "testdata", "vulnapp")
	results := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	prov := &cancelOnVerify{inner: &pathWriter{model: "m"}, cancel: cancel}
	rec, err := Execute(ctx, verifiedSpec(repo, results), Providers{Hunt: prov}, staticSkill{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !rec.Cancelled {
		t.Fatal("run should be cancelled")
	}
	ss := verification.LoadSessions(results)
	if len(ss) == 0 {
		t.Fatal("verification_sessions.json must be written on cancellation")
	}
	sawCancelled := false
	for _, s := range ss {
		if s.StopReason == "cancelled" {
			sawCancelled = true
		}
	}
	if !sawCancelled {
		t.Errorf("the in-flight session must be recorded as cancelled: %+v", ss)
	}
}
