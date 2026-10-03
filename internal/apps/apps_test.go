package apps

import (
	"path/filepath"
	"testing"
)

func TestRegisterNameForget(t *testing.T) {
	// Ledger dir under temp; applications.json lives next to it.
	t.Setenv("VHLOCAL_LEDGER_DIR", filepath.Join(t.TempDir(), "ledger"))
	repo := "/some/path/myapp"
	slug, err := Register(repo)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := Lookup(slug); !ok {
		t.Fatal("registered app not found")
	}
	if _, err := SetName(slug, "My App", repo); err != nil {
		t.Fatal(err)
	}
	e, _ := Lookup(slug)
	if e.Name != "My App" {
		t.Errorf("name = %q", e.Name)
	}
	if len(List()) != 1 {
		t.Errorf("list should have 1 app")
	}
	if err := Forget(slug); err != nil {
		t.Fatal(err)
	}
	if _, ok := Lookup(slug); ok {
		t.Error("forgotten app should not be found")
	}
	if len(List()) != 0 {
		t.Error("forgotten app should not list")
	}
}

func TestValidSlug(t *testing.T) {
	if !IsValidSlug("app-1a2b3c4d") {
		t.Error("valid slug rejected")
	}
	for _, bad := range []string{"../etc", "a/b", "a b", "..", ""} {
		if IsValidSlug(bad) {
			t.Errorf("bad slug accepted: %q", bad)
		}
	}
}
