package engine

import (
	"os"
	"testing"

	"vhlocal/internal/testisolate"
)

// origHome is the operator's real home BEFORE isolation, captured so the leak
// regression (isolation_test.go) can prove nothing under it changed.
var origHome string

// isolatedHome is the temp root every default store is redirected into.
var isolatedHome string

// TestMain isolates ALL engine tests from the operator's real stores (feature 014,
// FR-027). Before this, 40+ Execute call sites registered temp repos into the real
// ~/.vhlocal/applications.json on every `go test` run. The redirection itself lives
// in internal/testisolate so every other test package applies the same one.
func TestMain(m *testing.M) {
	root, real, cleanup := testisolate.Isolate("vhlocal-engine-test-home-")
	origHome, isolatedHome = real, root
	code := m.Run()
	cleanup()
	os.Exit(code)
}
