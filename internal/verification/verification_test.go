package verification

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"vhlocal/internal/consolidate"
	"vhlocal/internal/inventory"
)

func vulnRepo(t *testing.T) string {
	t.Helper()
	repo := t.TempDir()
	os.MkdirAll(filepath.Join(repo, "app"), 0o755)
	// line 2 contains a SQL sink; safe.py has none.
	os.WriteFile(filepath.Join(repo, "app", "db.py"), []byte("def q(x):\n    return conn.execute(x)\n"), 0o644)
	os.WriteFile(filepath.Join(repo, "app", "safe.py"), []byte("def q(x):\n    return sanitize(x)\n"), 0o644)
	return repo
}

func candFinding(loc string) consolidate.Finding {
	f := consolidate.NewFinding("V1")
	f.CWE, f.Location, f.EntryPoint, f.DataFlow = "CWE-89", loc, "GET /s", "x -> execute()"
	consolidate.ApplyKnowledge(&f)
	return f
}

func manifestOf(repo, loc string) *Manifest {
	f := candFinding(loc)
	id := candidateIdentity(f, repo)
	return &Manifest{SchemaVersion: 1, Revision: "rev1", Repo: repo,
		Candidates: []Candidate{{ID: "CAND-" + id[:24], Identity: id, Finding: f}}}
}

func evFor(repo, path string, start, end int) Evidence {
	b, _ := os.ReadFile(filepath.Join(repo, path))
	lines := splitLines(string(b))
	quote := ""
	for i := start - 1; i < end && i < len(lines); i++ {
		if quote != "" {
			quote += "\n"
		}
		quote += lines[i]
	}
	return Evidence{ID: "EV-x", Path: path, StartLine: start, EndLine: end, Quote: quote}
}

func splitLines(s string) []string {
	var out, cur = []string{}, ""
	for _, r := range s {
		if r == '\n' {
			out = append(out, cur)
			cur = ""
		} else {
			cur += string(r)
		}
	}
	out = append(out, cur)
	return out
}

func dec(cid, verdict string, ev ...Evidence) Decision {
	return Decision{CandidateID: cid, Verdict: verdict, Rationale: "because", EntryPoint: "GET /s",
		Reviewer: "test-reviewer", Preconditions: "none", DefensesReviewed: "none observed", AttackerControl: "query param", SecurityImpact: "data exfiltration", Evidence: ev, Revision: "rev1"}
}

// C-3c / FR-020: every candidate gets a disposition; supported requires evidence +
// source corroboration; rejected is first-class with evidence; unresolved accepted.
func TestReconcileSupported(t *testing.T) {
	repo := vulnRepo(t)
	m := manifestOf(repo, "app/db.py:2")
	cid := m.Candidates[0].ID
	rc := Reconcile(m, []Decision{dec(cid, "supported", evFor(repo, "app/db.py", 1, 2))}, repo)
	if !rc.Complete || rc.Results[0].Status != "supported" {
		t.Fatalf("expected supported+complete, got %+v errors=%v", rc.Results, rc.Errors)
	}
}

func TestReconcileSupportedNeedsSourceSink(t *testing.T) {
	repo := vulnRepo(t)
	m := manifestOf(repo, "app/safe.py:2") // no sink at this location
	cid := m.Candidates[0].ID
	rc := Reconcile(m, []Decision{dec(cid, "supported", evFor(repo, "app/safe.py", 1, 2))}, repo)
	if rc.Results[0].Status == "supported" {
		t.Errorf("supported must be refused when the source has no matching sink")
	}
}

func TestReconcileSupportedNeedsEvidence(t *testing.T) {
	repo := vulnRepo(t)
	m := manifestOf(repo, "app/db.py:2")
	cid := m.Candidates[0].ID
	rc := Reconcile(m, []Decision{dec(cid, "supported")}, repo) // no evidence
	if rc.Complete || rc.Results[0].Status == "supported" {
		t.Errorf("supported without evidence must be refused, got %+v", rc.Results[0])
	}
}

func TestReconcileRejectedAndUnresolved(t *testing.T) {
	repo := vulnRepo(t)
	m := manifestOf(repo, "app/db.py:2")
	cid := m.Candidates[0].ID
	if rc := Reconcile(m, []Decision{dec(cid, "rejected", evFor(repo, "app/db.py", 1, 2))}, repo); rc.Results[0].Status != "rejected" {
		t.Errorf("rejected with evidence should be accepted, got %v", rc.Results[0].Status)
	}
	if rc := Reconcile(m, []Decision{dec(cid, "unresolved")}, repo); rc.Results[0].Status != "unresolved" {
		t.Errorf("explicit unresolved should be accepted, got %v", rc.Results[0].Status)
	}
}

// C-C2 / FR-020: a missing or malformed decision leaves the candidate unresolved
// and the reconciliation incomplete — never confirmed.
func TestReconcileMissingAndMalformed(t *testing.T) {
	repo := vulnRepo(t)
	m := manifestOf(repo, "app/db.py:2")
	cid := m.Candidates[0].ID
	if rc := Reconcile(m, nil, repo); rc.Complete || rc.Results[0].Status != "unresolved" {
		t.Errorf("no decision → unresolved + incomplete, got %+v", rc.Results[0])
	}
	bad := dec(cid, "maybe")
	if rc := Reconcile(m, []Decision{bad}, repo); rc.Complete || rc.Results[0].Status == "supported" {
		t.Errorf("malformed verdict must not confer support, got %+v", rc.Results[0])
	}
}

// C-3a (feature 006, FR-009): a supported verdict requires the cited evidence to
// cover the COMPLETE containing function (decorators + defenses), not just the
// isolated dangerous line, so a context check cannot bleed past the handler.
func spanRepo(t *testing.T) string {
	t.Helper()
	repo := t.TempDir()
	os.MkdirAll(filepath.Join(repo, "app"), 0o755)
	// handler() spans lines 2..5; the SQL sink is on line 5. other() begins line 7.
	src := "import x\n" + // 1
		"def handler(q):\n" + // 2
		"    a = 1\n" + // 3
		"    b = 2\n" + // 4
		"    return conn.execute(q)\n" + // 5 (sink)
		"\n" + // 6
		"def other():\n" + // 7
		"    pass\n" // 8
	os.WriteFile(filepath.Join(repo, "app", "db.py"), []byte(src), 0o644)
	return repo
}

func TestReconcileSupportedNeedsCompleteFunction(t *testing.T) {
	repo := spanRepo(t)
	m := manifestOf(repo, "app/db.py:5")
	cid := m.Candidates[0].ID
	// Evidence covering only the sink line → incomplete containing-function context.
	rc := Reconcile(m, []Decision{dec(cid, "supported", evFor(repo, "app/db.py", 5, 5))}, repo)
	if rc.Results[0].Status == "supported" {
		t.Errorf("supported must require complete containing-function evidence; got %+v", rc.Results[0])
	}
	// Evidence covering the whole function (lines 2..5) → accepted.
	rc2 := Reconcile(m, []Decision{dec(cid, "supported", evFor(repo, "app/db.py", 2, 5))}, repo)
	if rc2.Results[0].Status != "supported" {
		t.Errorf("full-function evidence should be accepted, got %+v reason=%s", rc2.Results[0], rc2.Results[0].Reason)
	}
}

// C-3b (feature 006, FR-010): when the cited location resolves to a route handler,
// a supported verdict's entry_point must equal the resolved route guard
// (METHOD PATH); a mismatch refuses support.
func routeRepo(t *testing.T) string {
	t.Helper()
	repo := t.TempDir()
	os.MkdirAll(filepath.Join(repo, "app"), 0o755)
	src := "from flask import Flask, request\n" + // 1
		"app = Flask(__name__)\n" + // 2
		"@app.route('/orders')\n" + // 3 (decorator)
		"def orders():\n" + // 4
		"    return conn.execute(request.args['q'])\n" // 5 (sink)
	os.WriteFile(filepath.Join(repo, "app", "api.py"), []byte(src), 0o644)
	return repo
}

func TestReconcileSupportedEntryPointMustMatchRoute(t *testing.T) {
	repo := routeRepo(t)
	routes, _ := inventory.EnumerateRoutes(repo)
	want := ""
	for _, r := range routes {
		if strings.HasSuffix(r.File, "api.py") {
			want = r.Method + " " + r.Path
		}
	}
	if want == "" {
		t.Fatalf("fixture route not enumerated; routes=%+v", routes)
	}
	m := manifestOf(repo, "app/api.py:5")
	cid := m.Candidates[0].ID

	// Wrong entry_point → refused even with complete evidence.
	bad := dec(cid, "supported", evFor(repo, "app/api.py", 3, 5))
	bad.EntryPoint = "GET /wrong"
	if rc := Reconcile(m, []Decision{bad}, repo); rc.Results[0].Status == "supported" {
		t.Errorf("entry_point mismatch must refuse support; got %+v", rc.Results[0])
	}
	// Correct entry_point (the resolved route guard) → accepted.
	good := dec(cid, "supported", evFor(repo, "app/api.py", 3, 5))
	good.EntryPoint = want
	if rc := Reconcile(m, []Decision{good}, repo); rc.Results[0].Status != "supported" {
		t.Errorf("matching entry_point should be accepted, got %+v reason=%s want=%q", rc.Results[0], rc.Results[0].Reason, want)
	}
}

// CB-11 (feature 007, FR-024): an authorization/logic candidate with a complete
// evidence-backed review is supported even though it has no injection-style
// syntactic sink — while the entry-point/function/evidence requirements still hold.
func TestReconcileSupportedAuthzLogicNoSink(t *testing.T) {
	repo := t.TempDir()
	os.MkdirAll(filepath.Join(repo, "app"), 0o755)
	src := "from flask import Flask, request, session\n" + // 1
		"app = Flask(__name__)\n" + // 2
		"@app.route('/orders/<oid>')\n" + // 3 decorator
		"def get_order(oid):\n" + // 4
		"    return db.fetch(oid)\n" // 5 IDOR: no ownership check, no sink
	os.WriteFile(filepath.Join(repo, "app", "api.py"), []byte(src), 0o644)

	f := consolidate.NewFinding("V1")
	f.CWE, f.Location, f.Title = "CWE-639", "app/api.py:5", "IDOR on order object"
	consolidate.ApplyKnowledge(&f)
	id := candidateIdentity(f, repo)
	m := &Manifest{SchemaVersion: 1, Revision: "rev1", Repo: repo,
		Candidates: []Candidate{{ID: "CAND-" + id[:24], Identity: id, Finding: f}}}
	cid := m.Candidates[0].ID

	routes, _ := inventory.EnumerateRoutes(repo)
	want := ""
	for _, r := range routes {
		if strings.HasSuffix(r.File, "api.py") {
			want = r.Method + " " + r.Path
		}
	}
	d := dec(cid, "supported", evFor(repo, "app/api.py", 3, 5))
	d.EntryPoint = want
	rc := Reconcile(m, []Decision{d}, repo)
	if rc.Results[0].Status != "supported" {
		t.Errorf("an evidence-backed authz/logic review must be supported without a sink; got %+v reason=%s",
			rc.Results[0], rc.Results[0].Reason)
	}
}

// FinalFindings: FromConfirmed only for supported (C-C1).
func TestFinalFindingsFromConfirmed(t *testing.T) {
	repo := vulnRepo(t)
	m := manifestOf(repo, "app/db.py:2")
	cid := m.Candidates[0].ID
	rc := Reconcile(m, []Decision{dec(cid, "rejected", evFor(repo, "app/db.py", 1, 2))}, repo)
	fs := FinalFindings(m, rc)
	if len(fs) != 1 || fs[0].FromConfirmed {
		t.Errorf("a rejected candidate must not be from_confirmed, got %+v", fs)
	}
}
