package recognize

import "testing"

// T004 (C-R3): UnitID is deterministic and varies with identity.
func TestUnitIDDeterministicAndDistinct(t *testing.T) {
	a := UnitID(LangGo, "app", SurfaceWebRoute, "app/x.go:10", "GET /a")
	b := UnitID(LangGo, "app", SurfaceWebRoute, "app/x.go:10", "GET /a")
	c := UnitID(LangGo, "app", SurfaceWebRoute, "app/x.go:10", "GET /b")
	if a != b {
		t.Fatalf("UnitID not deterministic: %s vs %s", a, b)
	}
	if a == c {
		t.Fatal("distinct identities must yield distinct ids")
	}
	if got := a[:3]; got != "go:" {
		t.Fatalf("id missing language prefix: %s", a)
	}
}

// T004: the Go recognizer is registered with a zero-dependency (stdlib) mechanism.
func TestGoRegisteredStdlib(t *testing.T) {
	r, ok := For(LangGo)
	if !ok {
		t.Fatal("Go recognizer not registered")
	}
	if r.Mechanism() != MechStdlib {
		t.Fatalf("Go recognizer mechanism = %q, want stdlib (dependency budget)", r.Mechanism())
	}
	if len(Registered()) == 0 {
		t.Fatal("registry is empty")
	}
}

// LanguageFor maps extensions to baseline languages.
func TestLanguageFor(t *testing.T) {
	cases := map[string]Language{
		"a/b.go": LangGo, "x.ts": LangTypeScript, "y.py": LangPython, "z.rs": LangRust,
		"m.java": LangJava, "n.rb": LangRuby, "o.php": LangPHP, "p.cpp": LangCPP,
	}
	for path, want := range cases {
		if got, ok := LanguageFor(path); !ok || got != want {
			t.Errorf("LanguageFor(%q)=%q,%v want %q", path, got, ok, want)
		}
	}
	if _, ok := LanguageFor("readme.md"); ok {
		t.Error("non-source extension must not map to a language")
	}
}
