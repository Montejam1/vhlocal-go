package verification

import (
	"fmt"
	"strings"

	"vhlocal/internal/citation"
	"vhlocal/internal/consolidate"
)

// Feature 015 (FR-025, C-C1/C-C8): every hunt finding's citation is validated
// before it enters the manifest. Valid citations are recorded in canonical form
// (the original text kept); invalid ones enter as `invalid_citation` — visible,
// counted, never scheduled for a session, never accepted with a verdict.

// ManifestSchema is the current candidate_manifest.json schema version.
const ManifestSchema = 2

// Citation statuses.
const (
	CitationValid   = "valid"
	CitationInvalid = "invalid_citation"
)

// CitationRecord is a candidate's validated citation (data-model "citation").
type CitationRecord struct {
	Original   string             `json:"original"`
	Normalized string             `json:"normalized,omitempty"`
	Binding    *citation.Binding  `json:"binding,omitempty"`
	Status     string             `json:"status"` // valid | invalid_citation
	Error      *citation.Error    `json:"error,omitempty"`
	Parsed     *citation.Citation `json:"parsed,omitempty"`
}

// ValidateCitation parses, resolves and binds a finding's location. On success the
// returned string is the canonical location to record on the finding.
func ValidateCitation(f consolidate.Finding, repo, revision string, binder *citation.Binder) (CitationRecord, string) {
	rec := CitationRecord{Original: f.Location, Status: CitationInvalid}
	c, perr := citation.Parse(f.Location)
	if perr != nil {
		rec.Error = perr
		return rec, ""
	}
	if _, rerr := citation.Resolve(repo, revision, &c); rerr != nil {
		rec.Error = rerr
		rec.Parsed = &c
		return rec, ""
	}
	if binder != nil {
		b := binder.Bind(c)
		rec.Binding = &b
		if rec.Error == nil {
			// Aids for a later repair are cheap to carry now.
			_ = citation.AidsFor(b)
		}
	}
	rec.Parsed = &c
	rec.Normalized = c.String()
	rec.Status = CitationValid
	return rec, rec.Normalized
}

// InvalidCitationReason renders the reconciliation reason for an invalid candidate.
func InvalidCitationReason(r *CitationRecord) string {
	if r == nil || r.Error == nil {
		return "invalid citation"
	}
	return fmt.Sprintf("invalid citation (%s): %s=%q, expected %s — not verified", r.Error.Code, r.Error.Field, clip(r.Error.Received, 80), r.Error.Expected)
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return strings.TrimSpace(s[:n]) + "…"
}

// HasValidCitation reports whether a candidate may be scheduled for verification.
func (c Candidate) HasValidCitation() bool {
	return c.Citation == nil || c.Citation.Status == CitationValid
}
