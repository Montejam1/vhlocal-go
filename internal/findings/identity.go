// Package findings builds a cross-scan index of finding occurrences from the
// report data already on disk (findings.json), so an operator can review findings
// from every saved scan — including scans that ran with the ledger disabled
// (feature 010, FR-001). It adds no scan behavior and never rewrites scan
// evidence; it reads consolidate.Doc.Findings (raw maps) and reuses the engine's
// cross-run identity precedence (internal/lifecycle) so identities stay
// consistent with the ledger and lifecycle blocks.
package findings

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"

	"vhlocal/internal/consolidate"
	"vhlocal/internal/lifecycle"
)

// StableID returns a finding's cross-scan identity from its raw findings.json
// map, using the same precedence as the engine (lifecycle.Key): stable_identity
// → root_cause_key → cwe+file. It returns "" when no stable key can be derived,
// in which case callers fall back to a per-occurrence key (see OccurrenceID).
func StableID(f map[string]any) string {
	// Reuse lifecycle.Key by projecting the map onto the fields it consults. A
	// JSON round-trip keeps this faithful to the on-disk shape without hand-copying
	// each precedence rule.
	var cf consolidate.Finding
	if b, err := json.Marshal(f); err == nil {
		_ = json.Unmarshal(b, &cf)
	}
	return lifecycle.Key(cf)
}

// OccurrenceID uniquely identifies one finding as produced by one scan. It is the
// scan id joined to the stable identity; when a finding has no stable identity it
// falls back to the finding's own id (or its ordinal), so every occurrence is
// still addressable.
func OccurrenceID(scanID string, f map[string]any, ordinal int) string {
	sid := StableID(f)
	if sid == "" {
		if id, _ := f["id"].(string); id != "" {
			return scanID + "~id:" + id
		}
		return scanID + "~ord:" + itoa(ordinal)
	}
	return scanID + "~" + sid
}

// EvidenceFingerprint hashes the evidence a review decision is made against, so a
// later scan whose evidence for the same stable identity has materially changed
// can be surfaced rather than silently inheriting a prior disposition
// (FR-021). It is stable across marshaling order.
func EvidenceFingerprint(f map[string]any) string {
	keys := []string{"location", "entry_point", "data_flow", "cwe", "normalized_cwe",
		"severity", "verification_status", "verification_reason", "description"}
	parts := map[string]any{}
	for _, k := range keys {
		if v, ok := f[k]; ok {
			parts[k] = v
		}
	}
	// Marshal a sorted-key object deterministically.
	sort.Strings(keys)
	b, _ := json.Marshal(parts)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
