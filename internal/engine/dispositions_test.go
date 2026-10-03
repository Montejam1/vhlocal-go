package engine

import (
	"path/filepath"
	"testing"

	"vhlocal/internal/agent"
	"vhlocal/internal/inventory"
)

const sampleSection = `## Findings

# output

## Handler dispositions

- **Handler**: svc01/routes.py:12 GET /svc01/items
- **Checks**: INJ=done, NAV=n/a(not this pass), LOG=unresolved(auth branch not traced)
- **Defenses reviewed**: parameterized query
- **Evidence**: svc01/routes.py:12-20, ` + "`svc01/routes.py:21-25`" + `
- **Rationale**: no sink reachable
- **Unresolved**: auth branch

- **Handler**: ghost/none.py:1 GET /nowhere
- **Checks**: INJ=done
- **Evidence**: ghost/none.py:1-3
- **Rationale**: x
- **Unresolved**: none

I reviewed every handler in svc01/routes.py thoroughly; no issues found.
`

// T045 (C-B2..B4): the v2 section parses into structured blocks; prose is not a
// disposition; validation names out_of_scope / stale / not_read / outside_span /
// fabricated precisely.
func TestParseAndValidateDispositions(t *testing.T) {
	ds := parseDispositions(sampleSection)
	if len(ds) != 2 {
		t.Fatalf("blocks = %d, want 2 (prose is not a block)", len(ds))
	}
	d := ds[0]
	if d.RouteID != "svc01/routes.py:12 GET /svc01/items" || len(d.Checks) != 3 || d.Checks[2].Status != CheckUnresolved || d.Checks[2].Reason != "auth branch not traced" {
		t.Errorf("block 0 = %+v", d)
	}
	if len(d.Evidence) != 2 || d.Evidence[1].Start != 21 || d.Evidence[1].End != 25 || d.Unresolved[0] != "auth branch" {
		t.Errorf("evidence/unresolved = %+v %v", d.Evidence, d.Unresolved)
	}
	if parseDispositions("## Findings\n\nI reviewed every handler thoroughly; no issues found.\n") != nil {
		t.Error("a bare claim must not produce a disposition")
	}

	repo, routes, _ := coverageFixture(t)
	byID := map[string]inventory.Route{}
	for _, r := range routes {
		byID[RouteID(r)] = r
	}
	var target inventory.Route
	for _, r := range routes {
		if r.File == "svc01/routes.py" {
			target = r
			break
		}
	}
	spans := newHandlerSpans(repo)
	sc := spans.scopeFor(target)
	id := RouteID(target)
	mk := func(evStart, evEnd int) *HandlerDisposition {
		return &HandlerDisposition{RouteID: id, Checks: []CheckResult{{Class: "INJ", Status: CheckDone}}, Evidence: []EvidenceRange{{Path: target.File, Start: evStart, End: evEnd}}}
	}
	readAll := unitEvidence{label: "hunt:sg-1:inj", class: "INJ", reads: []agent.ReadSpan{{File: filepath.Join(repo, target.File), Start: 1, End: 0}}}
	assigned := map[string]bool{id: true}

	d1 := mk(sc.Start, sc.End)
	validateDisposition(d1, readAll, assigned, byID, spans, repo, "r1", "r1")
	if !d1.Validation.OK() {
		t.Errorf("valid disposition rejected: %+v", d1.Validation)
	}
	d2 := mk(sc.Start, sc.End)
	validateDisposition(d2, readAll, map[string]bool{}, byID, spans, repo, "r1", "r1")
	if d2.Validation.Scope != ValOutOfScope {
		t.Errorf("scope = %s, want out_of_scope", d2.Validation.Scope)
	}
	d3 := mk(sc.Start, sc.End)
	validateDisposition(d3, readAll, assigned, byID, spans, repo, "r1", "r2")
	if d3.Validation.Revision != ValStale {
		t.Errorf("revision = %s, want stale", d3.Validation.Revision)
	}
	d4 := mk(sc.Start, sc.End)
	validateDisposition(d4, unitEvidence{label: "u", class: "INJ"}, assigned, byID, spans, repo, "r1", "r1")
	if d4.Validation.Evidence != ValNotRead {
		t.Errorf("evidence = %s, want not_read", d4.Validation.Evidence)
	}
	d5 := mk(sc.End+50, sc.End+60)
	validateDisposition(d5, readAll, assigned, byID, spans, repo, "r1", "r1")
	if d5.Validation.Evidence != ValOutsideSpan {
		t.Errorf("evidence = %s, want outside_span", d5.Validation.Evidence)
	}
	d6 := &HandlerDisposition{RouteID: "ghost/none.py:1 GET /nowhere", Checks: []CheckResult{{Class: "INJ", Status: CheckDone}}, Evidence: []EvidenceRange{{Path: "ghost/none.py", Start: 1, End: 3}}}
	validateDisposition(d6, readAll, assigned, byID, spans, repo, "r1", "r1")
	if d6.Validation.Identity != ValFabricated {
		t.Errorf("identity = %s, want fabricated", d6.Validation.Identity)
	}

	// Aggregation: a class's verdict comes only from its own unit (or a follow-up).
	planned := []string{"INJ", "NAV", "LOG"}
	inj := HandlerDisposition{Class: "INJ", Validation: DispositionValidation{ValOK, ValOK, ValOK, ValOK}, Checks: []CheckResult{{Class: "INJ", Status: CheckDone}, {Class: "NAV", Status: CheckNA}, {Class: "LOG", Status: CheckNA}}}
	if credited, _, _, _ := aggregateChecks(planned, []HandlerDisposition{inj}); credited {
		t.Error("another class's n/a must not credit NAV/LOG")
	}
	nav := HandlerDisposition{Class: "NAV", Validation: inj.Validation, Checks: []CheckResult{{Class: "NAV", Status: CheckDone}}}
	log := HandlerDisposition{Class: "LOG", Validation: inj.Validation, Checks: []CheckResult{{Class: "LOG", Status: CheckNA, Reason: "no crypto"}}}
	if credited, _, _, _ := aggregateChecks(planned, []HandlerDisposition{inj, nav, log}); !credited {
		t.Error("done/n_a from each class's own unit must credit")
	}
	logU := HandlerDisposition{Class: "LOG", Validation: inj.Validation, Checks: []CheckResult{{Class: "LOG", Status: CheckUnresolved, Reason: "race not traced"}}}
	credited, partial, _, unresolved := aggregateChecks(planned, []HandlerDisposition{inj, nav, logU})
	if credited || !partial || len(unresolved) != 1 {
		t.Errorf("unresolved check: credited=%v partial=%v unresolved=%v", credited, partial, unresolved)
	}
	fu := HandlerDisposition{Class: "FOLLOWUP", Validation: inj.Validation, Checks: []CheckResult{{Class: "INJ", Status: CheckDone}, {Class: "NAV", Status: CheckDone}, {Class: "LOG", Status: CheckDone}}}
	if credited, _, _, _ := aggregateChecks(planned, []HandlerDisposition{fu}); !credited {
		t.Error("a follow-up unit reviews all classes")
	}
	bad := inj
	bad.Validation.Evidence = ValNotRead
	if credited, _, _, _ := aggregateChecks([]string{"INJ"}, []HandlerDisposition{bad}); credited {
		t.Error("an invalid disposition must not credit")
	}
}
