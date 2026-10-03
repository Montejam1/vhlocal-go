package apps

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"

	"vhlocal/internal/reports"
)

// Feature 014 (FR-028, SC-011): previewable, backed-up cleanup of DEMONSTRABLY
// synthetic registry entries — the `/tmp/Test…/001` rows a pre-isolation test
// suite leaked into the operator's applications.json. Nothing is removed without
// a preview token that the operator echoes back; the registry file is backed up
// first; reports and ledgers are never touched.

// reSynthetic matches Go test temp-dir repos exactly as the leak produced them:
// t.TempDir() → /tmp/Test<Name><digits>/<3-digit sequence>.
var reSynthetic = regexp.MustCompile(`^/tmp/Test[A-Za-z0-9_]+\d+/\d{3}$`)

// CleanupCandidate is one registry entry the preview would remove, with why.
type CleanupCandidate struct {
	Slug   string `json:"slug"`
	Repo   string `json:"repo"`
	Reason string `json:"reason"`
}

// CleanupPreview is the result of PreviewSynthetic (nothing has changed yet).
type CleanupPreview struct {
	Candidates     []CleanupCandidate `json:"candidates"`
	PreservedCount int                `json:"preserved_count"`
	PreviewToken   string             `json:"preview_token"`
}

// CleanupResult is what Apply did.
type CleanupResult struct {
	Removed    []string `json:"removed"`
	BackupPath string   `json:"backup_path"`
}

// ErrBadToken is returned by Apply when the confirmation does not match the
// current preview; nothing is changed.
var ErrBadToken = errors.New("cleanup: confirmation token does not match the current preview")

// PreviewSynthetic lists registry entries that are synthetic beyond doubt: the
// repo path matches the Go test temp-dir shape AND the application has zero scan
// history under reportsDir AND the path no longer exists. Each candidate carries
// its reason; everything else is counted as preserved. Deterministic: the token
// is a digest of the candidate slugs, so Apply can prove the operator confirmed
// exactly this set.
func PreviewSynthetic(reportsDir string) CleanupPreview {
	reg := loadAll()
	history := map[string]int{}
	if rs, err := reports.Index(reportsDir); err == nil {
		for _, r := range rs {
			s := r.Slug
			if s == "" {
				s = r.Name
			}
			history[s]++
		}
	}
	var cands []CleanupCandidate
	preserved := 0
	slugs := make([]string, 0, len(reg))
	for s := range reg {
		slugs = append(slugs, s)
	}
	sort.Strings(slugs)
	for _, slug := range slugs {
		e := reg[slug]
		reason, ok := syntheticReason(e, history[slug])
		if !ok {
			preserved++
			continue
		}
		cands = append(cands, CleanupCandidate{Slug: slug, Repo: e.Repo, Reason: reason})
	}
	if cands == nil {
		cands = []CleanupCandidate{}
	}
	return CleanupPreview{Candidates: cands, PreservedCount: preserved, PreviewToken: tokenFor(cands)}
}

// syntheticReason applies the three-part criterion; all three must hold.
func syntheticReason(e Entry, scans int) (string, bool) {
	if !reSynthetic.MatchString(e.Repo) {
		return "", false
	}
	if scans > 0 {
		return "", false
	}
	if _, err := os.Stat(e.Repo); err == nil {
		return "", false
	}
	return "repository path matches the Go test temp-dir shape, has no scan history, and no longer exists", true
}

func tokenFor(cands []CleanupCandidate) string {
	if len(cands) == 0 {
		return ""
	}
	h := sha256.New()
	for _, c := range cands {
		h.Write([]byte(c.Slug))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))[:24]
}

// Apply removes exactly the entries of the CURRENT preview, but only when the
// operator's confirmation equals that preview's token. It backs the registry
// file up to `applications.json.bak-<ts>` BEFORE writing, and touches no report
// or ledger. An empty/mismatched token changes nothing.
func Apply(reportsDir, confirm string) (CleanupResult, error) {
	pv := PreviewSynthetic(reportsDir)
	if pv.PreviewToken == "" {
		return CleanupResult{Removed: []string{}}, errors.New("cleanup: nothing to remove")
	}
	if strings.TrimSpace(confirm) == "" || confirm != pv.PreviewToken {
		return CleanupResult{Removed: []string{}}, ErrBadToken
	}
	cur, err := os.ReadFile(storePath())
	if err != nil {
		return CleanupResult{Removed: []string{}}, fmt.Errorf("cleanup: read registry: %w", err)
	}
	backup := fmt.Sprintf("%s.bak-%s", storePath(), time.Now().UTC().Format("20060102T150405Z"))
	if err := os.WriteFile(backup, cur, 0o644); err != nil {
		return CleanupResult{Removed: []string{}}, fmt.Errorf("cleanup: backup: %w", err)
	}
	reg := loadAll()
	removed := make([]string, 0, len(pv.Candidates))
	for _, c := range pv.Candidates {
		if _, ok := reg[c.Slug]; ok {
			delete(reg, c.Slug)
			removed = append(removed, c.Slug)
		}
	}
	if err := saveAll(reg); err != nil {
		return CleanupResult{Removed: []string{}, BackupPath: backup}, fmt.Errorf("cleanup: write registry: %w", err)
	}
	return CleanupResult{Removed: removed, BackupPath: backup}, nil
}
