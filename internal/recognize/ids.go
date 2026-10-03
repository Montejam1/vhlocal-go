package recognize

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// UnitID derives a stable, deterministic id for a unit from its language, module,
// surface kind, location, and identity (method+path / command / symbol). The same
// input always yields the same id (FR-022, contract C-R3); ids are collision-
// resistant via a truncated SHA-256 with a readable language/surface prefix.
func UnitID(lang Language, module string, surface SurfaceKind, location, identity string) string {
	anchor := strings.Join([]string{string(lang), module, string(surface), location, identity}, "|")
	sum := sha256.Sum256([]byte(anchor))
	return string(lang) + ":" + string(surface) + ":" + hex.EncodeToString(sum[:])[:16]
}
