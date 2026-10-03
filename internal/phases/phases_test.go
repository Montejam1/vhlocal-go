package phases

import (
	"reflect"
	"testing"
)

func TestSelectPhasesAll(t *testing.T) {
	got, err := SelectPhases("all")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"1", "1t", "2", "2b", "3", "3d", "4"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("all = %v want %v", got, want)
	}
	if g, _ := SelectPhases(""); !reflect.DeepEqual(g, want) {
		t.Errorf("empty should equal all, got %v", g)
	}
}

func TestSelectPhasesSubsetPreservesOrder(t *testing.T) {
	got, err := SelectPhases("2b,1,4")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"1", "2b", "4"} // PHASES order, not input order
	if !reflect.DeepEqual(got, want) {
		t.Errorf("subset = %v want %v", got, want)
	}
}

func TestSelectPhasesUnknown(t *testing.T) {
	_, err := SelectPhases("1,9x")
	if err == nil {
		t.Fatal("expected error for unknown phase")
	}
	if want := "unknown phase(s) 9x. Valid: 1, 1t, 2, 2b, 3, 3d, 4"; err.Error() != want {
		t.Errorf("err = %q want %q", err.Error(), want)
	}
}

func TestLoadPreamble(t *testing.T) {
	skill := "# SKILL\n\nintro\n\n## Operating Principles\n\nrule A\nrule B\n\n## Workflow\n\nsteps\n"
	got := LoadPreamble(skill)
	want := "## Operating Principles\n\nrule A\nrule B"
	if got != want {
		t.Errorf("preamble = %q want %q", got, want)
	}
	if LoadPreamble("no markers here") != "" {
		t.Error("missing start marker should yield empty preamble")
	}
}

func TestParseHuntTargets(t *testing.T) {
	md := "prose\n\n```json\n[{\"id\":\"T1\",\"subsystem\":\"syscall\",\"paths\":[\"pkg/a.go\"],\"threat\":\"escape\",\"cwe_class\":\"CWE-78\",\"priority\":\"high\"}]\n```\nmore prose\n"
	got := ParseHuntTargets(md)
	if len(got) != 1 || got[0].ID != "T1" || got[0].Subsystem != "syscall" || len(got[0].Paths) != 1 {
		t.Fatalf("parsed = %+v", got)
	}
	// unparseable -> nil (degrade visibly, don't crash)
	if ParseHuntTargets("no json at all") != nil {
		t.Error("expected nil for no hunt-targets block")
	}
	// object without paths/subsystem is ignored
	if r := ParseHuntTargets("```json\n[{\"note\":\"x\"}]\n```"); r != nil {
		t.Errorf("expected nil for objects lacking paths/subsystem, got %v", r)
	}
}
