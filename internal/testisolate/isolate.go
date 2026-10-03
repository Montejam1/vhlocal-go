// Package testisolate redirects every operator store to a throwaway root for a
// test binary (feature 014, FR-027 / SC-011). Each test package's TestMain calls
// Isolate before m.Run so that no test — whatever it exercises — can write to the
// real ~/.vhlocal (registry, ledger, jobs, central log, activity, reviews, views,
// assist) or ~/vulnhunter-reports. config.home() resolves via $HOME, so redirecting
// HOME covers every default path; the explicit VHLOCAL_* variables are set too for
// callers that read them directly.
//
// It is a plain (non-test) package so several test packages can share it; it has
// no dependency beyond the standard library and internal/config.
package testisolate

import (
	"os"
	"path/filepath"

	"vhlocal/internal/config"
)

// Isolate points HOME and every VHLOCAL_* store variable at a fresh temp root and
// returns that root plus the operator's real home (for leak regressions) and a
// cleanup func that removes the root.
func Isolate(prefix string) (root, realHome string, cleanup func()) {
	realHome, _ = os.UserHomeDir()
	root, err := os.MkdirTemp("", prefix)
	if err != nil {
		panic(err)
	}
	os.Setenv("HOME", root)
	os.Setenv("USERPROFILE", root) // windows parity for UserHomeDir
	os.Setenv(config.EnvLedgerDir, filepath.Join(root, ".vhlocal", "ledger"))
	os.Setenv(config.EnvProfilesDir, filepath.Join(root, ".vhlocal", "profiles"))
	os.Setenv(config.EnvLogFile, filepath.Join(root, ".vhlocal", "vhlocal.log"))
	os.Setenv(config.EnvLogDir, filepath.Join(root, ".vhlocal"))
	os.Setenv(config.EnvActivityFile, filepath.Join(root, ".vhlocal", "activity.jsonl"))
	os.Setenv(config.EnvReviewsDir, filepath.Join(root, ".vhlocal", "reviews"))
	os.Setenv(config.EnvViewsDir, filepath.Join(root, ".vhlocal", "views"))
	os.Setenv(config.EnvAssistDir, filepath.Join(root, ".vhlocal", "assist"))
	return root, realHome, func() { _ = os.RemoveAll(root) }
}
