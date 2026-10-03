// Package lifecycle does deterministic cross-run finding reconciliation (Mode A):
// it labels each current finding new / persisting / regressed against the most
// recent prior report of the same target, and lists findings that were present
// before and are gone now as fixed. It never calls the model, so run
// independence is preserved (FR-015). Mirrors the Python lifecycle.py.
package lifecycle

import (
	"regexp"
	"strings"

	"vhlocal/internal/consolidate"
	"vhlocal/internal/knowledge"
)

const (
	New        = "new"
	Persisting = "persisting"
	Regressed  = "regressed"
)

var reLeadingCWE = regexp.MustCompile(`^CWE-\d+`)

// normalizeFamily rolls a root_cause_key's leading CWE segment up to its
// canonical family CWE, preserving the file:func:flowsig tail.
func normalizeFamily(rck string) string {
	if rck == "" {
		return ""
	}
	parts := strings.SplitN(rck, ":", 2)
	head := parts[0]
	tail := ""
	if len(parts) == 2 {
		tail = ":" + parts[1]
	}
	if reLeadingCWE.MatchString(head) {
		if nc := knowledge.NormalizedCWE(head); nc != "" {
			head = nc
		}
	}
	return head + tail
}

// Key computes a finding's cross-run identity, by precedence.
func Key(f consolidate.Finding) string {
	if f.StableIdentity != "" {
		return "source-v1:" + f.StableIdentity
	}
	if f.RootCauseKey != "" {
		return normalizeFamily(f.RootCauseKey)
	}
	nc := f.NormalizedCWE
	if nc == "" {
		nc = f.CWE
	}
	if nc != "" {
		if file := firstFile(f.Location); file != "" {
			return "cwefile:" + nc + ":" + file
		}
	}
	return ""
}

var reFile = regexp.MustCompile(`([\w./+\-]+\.[A-Za-z0-9]{1,6})`)

func firstFile(s string) string {
	m := reFile.FindString(s)
	if m == "" {
		return ""
	}
	if i := strings.LastIndexByte(m, '/'); i >= 0 {
		return m[i+1:]
	}
	return m
}

// FindingRef is a compact reference used in the lifecycle block's lists.
type FindingRef struct {
	ID       string `json:"id"`
	Title    string `json:"title"`
	CWE      string `json:"cwe"`
	Location string `json:"location"`
	Key      string `json:"key"`
}

// Reconcile labels current findings against prior findings and prior fixed keys.
// It mutates current[i].FindingLifecycle and returns the lifecycle block plus the
// fixed_keys for the next run.
func Reconcile(current, prior []consolidate.Finding, priorFixed []string, priorReport, priorCommit, currentCommit string) map[string]any {
	priorKeys := map[string]bool{}
	for _, f := range prior {
		if f.DuplicateOf != nil {
			continue
		}
		if k := Key(f); k != "" {
			priorKeys[k] = true
		}
	}
	priorFixedSet := map[string]bool{}
	for _, k := range priorFixed {
		priorFixedSet[k] = true
	}

	curKeys := map[string]bool{}
	var nNew, nPersist, nRegress int
	// canonical id -> state, for duplicate inheritance
	stateByCanonical := map[string]string{}
	for i := range current {
		f := &current[i]
		if f.DuplicateOf != nil {
			continue
		}
		k := Key(*f)
		if k != "" {
			curKeys[k] = true
		}
		switch {
		case priorKeys[k] && k != "":
			f.FindingLifecycle = Persisting
			nPersist++
		case priorFixedSet[k] && k != "":
			f.FindingLifecycle = Regressed
			nRegress++
		default:
			f.FindingLifecycle = New
			nNew++
		}
		stateByCanonical[f.ID] = f.FindingLifecycle
	}
	// Duplicates inherit their cluster canonical's state.
	for i := range current {
		f := &current[i]
		if f.DuplicateOf != nil {
			if s, ok := stateByCanonical[f.ClusterID]; ok {
				f.FindingLifecycle = s
			}
		}
	}

	// Prior keys absent now -> fixed (not_observed).
	var fixedRefs []FindingRef
	fixedKeysNext := map[string]bool{}
	for _, f := range prior {
		if f.DuplicateOf != nil {
			continue
		}
		k := Key(f)
		if k == "" {
			continue
		}
		if !curKeys[k] {
			fixedRefs = append(fixedRefs, refOf(f, k))
			fixedKeysNext[k] = true
		}
	}
	// Carry forward prior fixed keys that are still not present.
	for k := range priorFixedSet {
		if !curKeys[k] {
			fixedKeysNext[k] = true
		}
	}
	// Every current key is a baseline for next run's comparison.
	nextFixed := make([]string, 0)
	for k := range fixedKeysNext {
		nextFixed = append(nextFixed, k)
	}

	hasPrior := priorReport != ""
	block := map[string]any{
		"has_prior": hasPrior, "prior_report": priorReport, "prior_commit": priorCommit,
		"current_commit": currentCommit,
		"new":            nNew, "persisting": nPersist,
		"not_observed": len(fixedRefs), "not_observed_findings": refList(fixedRefs),
		"reappeared":  nRegress,
		"terminology": "not_observed supersedes fixed; reappeared supersedes regressed (deprecated aliases kept)",
		// deprecated aliases
		"regressed": nRegress, "fixed": len(fixedRefs), "fixed_findings": refList(fixedRefs),
		"fixed_keys": nextFixed,
	}
	return block
}

// Suppressed returns the lifecycle block for an UNRELIABLE run (execution not
// complete, or the hunt produced no output, or recon produced no map). It emits
// NO fixed/not_observed list — a run that found nothing because it broke has no
// basis to claim anything was fixed (constitution Principle I; FR-007). The
// trigger is the strict Reliable predicate, never coverage_status == degraded.
func Suppressed(reason string) map[string]any {
	return map[string]any{
		"has_prior": true, "comparison_status": "suppressed_unreliable_run", "reason": reason,
		"new": 0, "persisting": 0, "not_observed": 0, "not_observed_findings": []FindingRef{},
		"reappeared": 0, "regressed": 0, "fixed": 0, "fixed_findings": []FindingRef{}, "fixed_keys": []string{},
	}
}

// NoPrior returns the baseline lifecycle block for a run with no prior report.
// current findings' keys become the fixed_keys baseline for the next run.
func NoPrior(current []consolidate.Finding, currentCommit string) map[string]any {
	var keys []string
	for i := range current {
		if current[i].DuplicateOf != nil {
			continue
		}
		current[i].FindingLifecycle = New
		if k := Key(current[i]); k != "" {
			keys = append(keys, k)
		}
	}
	return map[string]any{
		"has_prior": false, "prior_report": "", "prior_commit": "",
		"current_commit": currentCommit, "new": len(keys), "persisting": 0,
		"not_observed": 0, "not_observed_findings": []FindingRef{}, "reappeared": 0,
		"regressed": 0, "fixed": 0, "fixed_findings": []FindingRef{}, "fixed_keys": keys,
		"terminology": "not_observed supersedes fixed; reappeared supersedes regressed (deprecated aliases kept)",
	}
}

func refOf(f consolidate.Finding, key string) FindingRef {
	return FindingRef{ID: f.ID, Title: f.Title, CWE: f.CWE, Location: f.Location, Key: key}
}

func refList(r []FindingRef) []FindingRef {
	if r == nil {
		return []FindingRef{}
	}
	return r
}

// Incomparable is the lifecycle block for a RELIABLE run whose source-review
// coverage is not complete (feature 015, C-B8): the run cannot tell "fixed" from
// "not looked at", so it claims neither — prior findings absent from this run are
// unknown_incomparable, never fixed/not_observed.
func Incomparable(reason string) map[string]any {
	return map[string]any{
		"has_prior": true, "comparison_status": "unknown_incomparable", "reason": reason,
		"new": 0, "persisting": 0, "not_observed": 0, "not_observed_findings": []FindingRef{},
		"reappeared": 0, "regressed": 0, "fixed": 0, "fixed_findings": []FindingRef{}, "fixed_keys": []string{},
	}
}
