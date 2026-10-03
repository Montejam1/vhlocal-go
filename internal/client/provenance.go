// Package client holds the inference-backend transports and provenance capture.
// This file provides best-effort git provenance of the scanned tree.
package client

import (
	"os/exec"
	"strings"
)

// GitProvenance is best-effort VCS provenance of the scanned tree, recorded so
// cross-run lifecycle reconciliation can say which commit a finding first
// appeared in or was fixed at. All fields are empty when the path is not a git
// repository (never an error — provenance is best-effort).
type GitProvenance struct {
	Commit string `json:"git_commit"`
	Branch string `json:"git_branch"`
	Dirty  bool   `json:"git_dirty"`
}

// Git returns provenance for the repo at dir. Empty struct when git is absent or
// dir is not a repo.
func Git(dir string) GitProvenance {
	var p GitProvenance
	if _, err := exec.LookPath("git"); err != nil {
		return p
	}
	run := func(args ...string) (string, bool) {
		cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
		out, err := cmd.Output()
		if err != nil {
			return "", false
		}
		return strings.TrimSpace(string(out)), true
	}
	// Confirm it's a work tree first.
	if v, ok := run("rev-parse", "--is-inside-work-tree"); !ok || v != "true" {
		return p
	}
	if v, ok := run("rev-parse", "HEAD"); ok {
		p.Commit = v
	}
	if v, ok := run("rev-parse", "--abbrev-ref", "HEAD"); ok {
		p.Branch = v
	}
	if v, ok := run("status", "--porcelain"); ok {
		p.Dirty = v != ""
	}
	return p
}
