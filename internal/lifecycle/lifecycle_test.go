package lifecycle

import (
	"testing"

	"vhlocal/internal/consolidate"
)

func mk(id, cwe, loc, title string) consolidate.Finding {
	f := consolidate.NewFinding(id)
	f.CWE, f.Location, f.Title = cwe, loc, title
	consolidate.ApplyKnowledge(&f)
	f.RootCauseKey = consolidate.RootCauseKey(&f)
	return f
}

func TestReconcileNewPersistingNotObserved(t *testing.T) {
	prior := []consolidate.Finding{
		mk("VULN-001", "CWE-89", "app/db.py:42", "SQLi q -> execute"),
		mk("VULN-002", "CWE-22", "app/files.py:10", "path traversal name -> open"),
	}
	current := []consolidate.Finding{
		mk("VULN-001", "CWE-89", "app/db.py:44", "SQLi q -> execute"),          // persisting (line drift, same key)
		mk("VULN-007", "CWE-78", "app/main.py:31", "cmd inj src -> os.system"), // new
	}
	block := Reconcile(current, prior, nil, "prior-report", "abc", "def")

	if current[0].FindingLifecycle != Persisting {
		t.Errorf("VULN-001 = %q want persisting", current[0].FindingLifecycle)
	}
	if current[1].FindingLifecycle != New {
		t.Errorf("VULN-007 = %q want new", current[1].FindingLifecycle)
	}
	if block["new"] != 1 || block["persisting"] != 1 {
		t.Errorf("counts new=%v persisting=%v", block["new"], block["persisting"])
	}
	// The path-traversal finding is gone now -> not_observed (aka fixed).
	if block["not_observed"] != 1 || block["fixed"] != 1 {
		t.Errorf("not_observed=%v fixed(alias)=%v", block["not_observed"], block["fixed"])
	}
}

func TestReappearedFromPriorFixed(t *testing.T) {
	f := mk("VULN-001", "CWE-89", "app/db.py:42", "SQLi q -> execute")
	priorFixed := []string{Key(f)}
	current := []consolidate.Finding{f}
	block := Reconcile(current, nil, priorFixed, "prior", "", "")
	if current[0].FindingLifecycle != Regressed {
		t.Errorf("lifecycle = %q want regressed", current[0].FindingLifecycle)
	}
	if block["reappeared"] != 1 || block["regressed"] != 1 {
		t.Errorf("reappeared=%v regressed(alias)=%v", block["reappeared"], block["regressed"])
	}
}

func TestNoPriorBaseline(t *testing.T) {
	current := []consolidate.Finding{mk("VULN-001", "CWE-89", "app/db.py:42", "SQLi")}
	block := NoPrior(current, "commit")
	if block["has_prior"] != false || block["new"] != 1 {
		t.Errorf("no-prior block wrong: %v", block)
	}
	keys := block["fixed_keys"].([]string)
	if len(keys) != 1 {
		t.Errorf("baseline fixed_keys = %v", keys)
	}
	if current[0].FindingLifecycle != New {
		t.Errorf("lifecycle = %q want new", current[0].FindingLifecycle)
	}
}

func TestKeyPrecedence(t *testing.T) {
	f := consolidate.NewFinding("V1")
	f.StableIdentity = "abc123"
	if Key(f) != "source-v1:abc123" {
		t.Errorf("stable_identity precedence: %q", Key(f))
	}
	// family-normalized root_cause_key: sibling CWE rolls to canonical.
	f2 := consolidate.NewFinding("V2")
	f2.RootCauseKey = "CWE-639:main.py:check:id"
	if got := Key(f2); got != "CWE-284:main.py:check:id" {
		t.Errorf("family-normalized key = %q", got)
	}
}
