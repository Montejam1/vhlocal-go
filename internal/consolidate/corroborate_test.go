package consolidate

import (
	"os"
	"path/filepath"
	"testing"
)

// C-4a/C-4b (feature 005): statically-supported requires the cited SOURCE to
// contain a matching sink — never a prose arrow / text field alone — and a
// logic/authorization CWE is never supported on prose.
func TestSourceCorroborationGate(t *testing.T) {
	repo := t.TempDir()
	os.MkdirAll(filepath.Join(repo, "app"), 0o755)
	os.WriteFile(filepath.Join(repo, "app", "db.py"), []byte("def q(x):\n    return conn.execute(x)\n"), 0o644)
	os.WriteFile(filepath.Join(repo, "app", "safe.py"), []byte("def q(x):\n    return sanitize(x)\n"), 0o644)

	// C-4a: cited source contains a matching sink → statically supported.
	f := NewFinding("V1")
	f.CWE, f.Location, f.EntryPoint, f.DataFlow = "CWE-89", "app/db.py:2", "GET /s", "x -> execute()"
	ApplyKnowledge(&f)
	ApplyQuality(&f, StrictBalanced, repo)
	if f.Classification != ClassStaticallySupported {
		t.Errorf("a source-corroborated sink finding must be statically supported, got %q", f.Classification)
	}

	// C-4a: same prose, but the cited source has NO matching sink → hypothesis.
	f2 := NewFinding("V2")
	f2.CWE, f2.Location, f2.EntryPoint, f2.DataFlow = "CWE-89", "app/safe.py:2", "GET /s", "x -> execute()"
	ApplyKnowledge(&f2)
	ApplyQuality(&f2, StrictBalanced, repo)
	if f2.Classification == ClassStaticallySupported {
		t.Errorf("a prose-only finding whose source lacks the sink must NOT be supported")
	}

	// C-4b: a logic/authorization CWE is never statically supported on prose.
	f3 := NewFinding("V3")
	f3.CWE, f3.Location, f3.EntryPoint, f3.DataFlow = "CWE-862", "app/db.py:2", "GET /s", "x -> y"
	ApplyKnowledge(&f3)
	ApplyQuality(&f3, StrictBalanced, repo)
	if f3.Classification == ClassStaticallySupported {
		t.Errorf("a logic/authorization CWE must not be statically supported on prose, got %q", f3.Classification)
	}
}

// C-4b (feature 005, FR-025): the per-class veto battery refutes support even when
// a sink is present — weak randomness only matters at a security-sensitive consumer.
func TestClassEvidenceVeto(t *testing.T) {
	repo := t.TempDir()
	os.MkdirAll(filepath.Join(repo, "app"), 0o755)
	// A weak-random sink with NO security consumer → veto demotes to hypothesis.
	os.WriteFile(filepath.Join(repo, "app", "r.py"), []byte("def h():\n    x = random.randint(1, 9)\n    return x\n"), 0o644)
	f := NewFinding("V1")
	f.CWE, f.Location = "CWE-338", "app/r.py:2"
	ApplyKnowledge(&f)
	ApplyQuality(&f, StrictBalanced, repo)
	if f.Classification == ClassStaticallySupported {
		t.Errorf("weak randomness with no security consumer must not be supported")
	}
	// The same sink stored into a security-sensitive name → supported.
	os.WriteFile(filepath.Join(repo, "app", "s.py"), []byte("def h():\n    token = random.randint(1, 9)\n    return token\n"), 0o644)
	f2 := NewFinding("V2")
	f2.CWE, f2.Location = "CWE-338", "app/s.py:2"
	ApplyKnowledge(&f2)
	ApplyQuality(&f2, StrictBalanced, repo)
	if f2.Classification != ClassStaticallySupported {
		t.Errorf("weak randomness reaching a security consumer should be supported, got %q", f2.Classification)
	}
}

// C-3c (feature 006, FR-011): SSTI whose template source is a constant is refuted —
// rendering attacker data against a constant template does not evaluate it as
// template source. A non-constant (attacker-controlled) template is not refuted.
func TestClassEvidenceSSTIConstant(t *testing.T) {
	repo := t.TempDir()
	os.MkdirAll(filepath.Join(repo, "app"), 0o755)
	// Constant template string → refuted.
	os.WriteFile(filepath.Join(repo, "app", "c.py"), []byte(
		"def h(name):\n    t = Template(\"<p>hello</p>\")\n    return t.render(name=name)\n"), 0o644)
	f := NewFinding("V1")
	f.CWE, f.Location, f.Title = "CWE-1336", "app/c.py:2", "Server-Side Template Injection"
	ApplyKnowledge(&f)
	if !ClassEvidenceRefuted(&f, repo) {
		t.Errorf("a constant template source must refute SSTI support")
	}
	ApplyQuality(&f, StrictBalanced, repo)
	if f.Classification == ClassStaticallySupported {
		t.Errorf("constant-template SSTI must not be statically supported, got %q", f.Classification)
	}

	// Attacker-controlled (non-constant) template → not refuted by this rule.
	os.WriteFile(filepath.Join(repo, "app", "d.py"), []byte(
		"def h(tpl, name):\n    t = Template(tpl)\n    return t.render(name=name)\n"), 0o644)
	f2 := NewFinding("V2")
	f2.CWE, f2.Location, f2.Title = "CWE-1336", "app/d.py:2", "Server-Side Template Injection"
	ApplyKnowledge(&f2)
	if ClassEvidenceRefuted(&f2, repo) {
		t.Errorf("a non-constant (attacker-controlled) template must NOT be refuted by the constant-template rule")
	}
}

// C-3c (feature 006, FR-011): a broken-access-control CWE is class-evidence NA —
// guard-name detection can neither establish nor refute effective permissions, so
// it is never statically supported on prose (matches the reference authz posture).
func TestClassEvidenceAccessControlNA(t *testing.T) {
	repo := t.TempDir()
	os.MkdirAll(filepath.Join(repo, "app"), 0o755)
	os.WriteFile(filepath.Join(repo, "app", "u.py"), []byte(
		"def get_user(uid):\n    return db.users.find_one(uid)\n"), 0o644)
	f := NewFinding("V1")
	f.CWE, f.Location, f.Title = "CWE-639", "app/u.py:2", "IDOR on user object"
	ApplyKnowledge(&f)
	if ClassEvidenceRefuted(&f, repo) {
		t.Errorf("access-control class evidence must be NA (never a fail), not refuted")
	}
	if ClassPrimaryEvidence(&f, repo) {
		t.Errorf("access-control is not a primary-evidence class")
	}
	ApplyQuality(&f, StrictBalanced, repo)
	if f.Classification == ClassStaticallySupported {
		t.Errorf("an access-control CWE must not be statically supported on prose, got %q", f.Classification)
	}
}

// C-3d (feature 006, FR-011): a finding carrying a validated review record (a
// source-grounded review on the current checkout) is tiered `reviewed` — above
// `statically_supported`. An incomplete/unbacked record is not.
func TestReviewedTierFromReviewRecord(t *testing.T) {
	repo := t.TempDir()
	os.MkdirAll(filepath.Join(repo, "app"), 0o755)
	os.WriteFile(filepath.Join(repo, "app", "db.py"), []byte("def q(x):\n    return conn.execute(x)\n"), 0o644)

	rec := &ReviewRecord{
		Verdict: "supported", Revision: "rev1", Reviewer: "analyst",
		Rationale: "confirmed SQL sink", EntryPoint: "GET /s", AttackerControl: "query",
		Preconditions: "authenticated", DefensesReviewed: "none", SecurityImpact: "data exfiltration",
		Evidence: []ReviewEvidence{{Path: "app/db.py", StartLine: 1, EndLine: 2, Quote: "def q(x):\n    return conn.execute(x)"}},
	}
	f := NewFinding("V1")
	f.CWE, f.Location = "CWE-89", "app/db.py:2"
	f.ReviewRecord = rec
	ApplyKnowledge(&f)
	ApplyQuality(&f, StrictBalanced, repo)
	if f.Classification != ClassReviewed {
		t.Errorf("a validated review record must tier the finding as reviewed, got %q", f.Classification)
	}
	if f.Assessment != AssessSupported {
		t.Errorf("a reviewed finding is substantiated (supported), got %q", f.Assessment)
	}

	// An incomplete record (missing rationale) → not reviewed.
	bad := *rec
	bad.Rationale = ""
	f2 := NewFinding("V2")
	f2.CWE, f2.Location = "CWE-89", "app/db.py:2"
	f2.ReviewRecord = &bad
	ApplyKnowledge(&f2)
	ApplyQuality(&f2, StrictBalanced, repo)
	if f2.Classification == ClassReviewed {
		t.Errorf("an incomplete review record must NOT tier as reviewed")
	}
}
