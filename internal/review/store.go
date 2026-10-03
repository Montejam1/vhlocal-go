// Package review is the durable human review-decision store for the analyst
// workspace (feature 010, US2). It records an operator's disposition, notes, and
// rationale per finding stable identity as an append-only history, separate from
// scan evidence and the AI verdict (which it never writes — Principle I,
// FR-020). Records live under ~/.vhlocal/reviews/<stable-id>.json, written
// atomically (temp+rename). Concurrent writes are guarded by an optimistic
// version so a stale browser cannot silently overwrite a newer decision
// (FR-021).
package review

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	"vhlocal/internal/config"
)

// Dispositions (FR-016). needs-review is the default when no record exists.
const (
	NeedsReview   = "needs-review"
	Investigating = "investigating"
	AcceptedRisk  = "accepted-risk"
	Dismissed     = "dismissed"
	Resolved      = "resolved"
)

// ErrConflict is returned when a write's base version is not the current head —
// the caller must re-read and retry, never overwrite (FR-021).
var ErrConflict = errors.New("review decision conflict: record changed since last read")

// ErrRationaleRequired is returned when a dismissal/accepted-risk/resolution is
// saved without a rationale (FR-018).
var ErrRationaleRequired = errors.New("rationale is required for dismissal, accepted risk, or resolution")

// Decision is one entry in a finding's review history.
type Decision struct {
	Version     int     `json:"version"`
	Disposition string  `json:"disposition"`
	Rationale   string  `json:"rationale"`
	Notes       string  `json:"notes"`
	ScanID      string  `json:"scan_id"`
	Revision    string  `json:"revision"`
	Operator    string  `json:"operator"`
	DecidedAt   float64 `json:"decided_at"`
}

// Record is the append-only history for one finding stable identity.
type Record struct {
	StableID            string     `json:"stable_id"`
	EvidenceFingerprint string     `json:"evidence_fingerprint"`
	History             []Decision `json:"history"`
}

// Head returns the current decision, or a synthetic needs-review at version 0
// when there is no history yet.
func (r Record) Head() Decision {
	if len(r.History) == 0 {
		return Decision{Version: 0, Disposition: NeedsReview}
	}
	return r.History[len(r.History)-1]
}

// Submission is a new decision to append.
type Submission struct {
	Disposition         string
	Rationale           string
	Notes               string
	ScanID              string
	Revision            string
	Operator            string
	EvidenceFingerprint string
	// BaseVersion is the head version the operator last saw. The append succeeds
	// only if it still matches the stored head (optimistic concurrency). Omit
	// (0) only for a brand-new record.
	BaseVersion int
}

func dir() string { return config.ReviewsDir() }

// Get returns the record for a stable id (an empty record when none exists).
func Get(stableID string) (Record, bool) {
	if !validID(stableID) {
		return Record{}, false
	}
	rec, ok := load(path(stableID))
	if !ok {
		return Record{StableID: stableID, History: []Decision{}}, false
	}
	return rec, true
}

// Disposition returns the head disposition for a stable id, defaulting to
// needs-review. It is the lookup the findings queue uses.
func Disposition(stableID string) string {
	rec, ok := Get(stableID)
	if !ok {
		return NeedsReview
	}
	return rec.Head().Disposition
}

// Submit appends a decision, enforcing the rationale rule and optimistic version
// check, and never rewrites scan evidence or a ledger (FR-020/022). It returns
// the new head.
func Submit(stableID string, s Submission) (Record, error) {
	if !validID(stableID) {
		return Record{}, errors.New("invalid finding identity")
	}
	if !validDisposition(s.Disposition) {
		return Record{}, errors.New("invalid disposition")
	}
	if requiresRationale(s.Disposition) && strings.TrimSpace(s.Rationale) == "" {
		return Record{}, ErrRationaleRequired
	}

	rec, _ := load(path(stableID))
	if rec.StableID == "" {
		rec.StableID = stableID
	}
	head := rec.Head()
	// Optimistic concurrency: the submitter must have seen the current head.
	if s.BaseVersion != head.Version {
		return rec, ErrConflict
	}

	next := Decision{
		Version:     head.Version + 1,
		Disposition: s.Disposition,
		Rationale:   strings.TrimSpace(s.Rationale),
		Notes:       s.Notes,
		ScanID:      s.ScanID,
		Revision:    s.Revision,
		Operator:    orStr(s.Operator, "local-operator"),
		DecidedAt:   float64(time.Now().Unix()),
	}
	rec.History = append(rec.History, next)
	if s.EvidenceFingerprint != "" {
		rec.EvidenceFingerprint = s.EvidenceFingerprint
	}
	if err := writeAtomic(path(stableID), rec); err != nil {
		return Record{}, err
	}
	return rec, nil
}

// EvidenceChanged reports whether the stored decision was made against evidence
// whose fingerprint differs from the current one — a signal not to silently
// carry a dismissal across materially changed evidence (FR-021). It is false
// when there is no record or no stored fingerprint.
func EvidenceChanged(stableID, currentFingerprint string) bool {
	rec, ok := Get(stableID)
	if !ok || rec.EvidenceFingerprint == "" || currentFingerprint == "" {
		return false
	}
	return rec.EvidenceFingerprint != currentFingerprint
}

func path(stableID string) string { return filepath.Join(dir(), fileID(stableID)+".json") }

func load(p string) (Record, bool) {
	b, err := os.ReadFile(p)
	if err != nil {
		return Record{}, false
	}
	var rec Record
	if json.Unmarshal(b, &rec) != nil || rec.StableID == "" {
		return Record{}, false
	}
	if rec.History == nil {
		rec.History = []Decision{}
	}
	return rec, true
}

func writeAtomic(p string, v any) error {
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}

func validDisposition(d string) bool {
	switch d {
	case NeedsReview, Investigating, AcceptedRisk, Dismissed, Resolved:
		return true
	}
	return false
}

func requiresRationale(d string) bool {
	return d == Dismissed || d == AcceptedRisk || d == Resolved
}

// validID accepts non-empty stable identities of bounded length. The identity is
// engine-derived (e.g. "source-v1:<hash>", "cwefile:CWE-79:app.js"); it may
// contain ':' and '.', so we do not restrict those, but we reject path
// separators and derive a safe filename via fileID.
func validID(id string) bool {
	return id != "" && len(id) <= 512 && !strings.ContainsAny(id, "/\\") && id != "." && id != ".."
}

// fileID makes a filesystem-safe, collision-resistant name from a stable id by
// replacing characters outside a conservative set. Distinct ids map to distinct
// files because unsafe runs are escaped, not dropped.
func fileID(id string) string {
	var b strings.Builder
	for _, r := range id {
		switch {
		case r == '-' || r == '_' || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9'):
			b.WriteRune(r)
		default:
			b.WriteByte('_')
			b.WriteString(hexByte(r))
		}
	}
	s := b.String()
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}

func hexByte(r rune) string {
	const hexd = "0123456789abcdef"
	// Encode the low 16 bits of the rune; enough to disambiguate the ASCII
	// punctuation that appears in identities (':', '.', '+', etc.).
	v := int(r) & 0xffff
	return string([]byte{
		hexd[(v>>12)&0xf], hexd[(v>>8)&0xf], hexd[(v>>4)&0xf], hexd[v&0xf],
	})
}

func orStr(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	return b
}
