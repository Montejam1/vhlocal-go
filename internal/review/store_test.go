package review

import (
	"errors"
	"testing"
)

// T015 (FR-018): rationale is required for dismissal/accepted-risk/resolution.
func TestRationaleRequired(t *testing.T) {
	t.Setenv("VHLOCAL_REVIEWS_DIR", t.TempDir())
	for _, d := range []string{Dismissed, AcceptedRisk, Resolved} {
		if _, err := Submit("source-v1:s1", Submission{Disposition: d}); !errors.Is(err, ErrRationaleRequired) {
			t.Fatalf("disposition %q without rationale: err=%v want ErrRationaleRequired", d, err)
		}
	}
	// With a rationale it succeeds.
	if _, err := Submit("source-v1:s1", Submission{Disposition: Dismissed, Rationale: "false positive: input is constant"}); err != nil {
		t.Fatalf("dismiss with rationale: %v", err)
	}
	// needs-review / investigating do not require a rationale.
	if _, err := Submit("source-v1:s2", Submission{Disposition: Investigating}); err != nil {
		t.Fatalf("investigating without rationale should be allowed: %v", err)
	}
}

// T015 (FR-019): history is append-only; a later decision supersedes without
// erasing earlier entries, and versions increase monotonically.
func TestHistorySupersedeAppendOnly(t *testing.T) {
	t.Setenv("VHLOCAL_REVIEWS_DIR", t.TempDir())
	id := "source-v1:s1"
	r1, err := Submit(id, Submission{Disposition: Investigating, BaseVersion: 0})
	if err != nil {
		t.Fatalf("v1: %v", err)
	}
	if r1.Head().Version != 1 {
		t.Fatalf("first head version = %d, want 1", r1.Head().Version)
	}
	r2, err := Submit(id, Submission{Disposition: Resolved, Rationale: "fixed in commit deadbeef", BaseVersion: 1})
	if err != nil {
		t.Fatalf("v2: %v", err)
	}
	if r2.Head().Version != 2 || r2.Head().Disposition != Resolved {
		t.Fatalf("head after supersede: %+v", r2.Head())
	}
	if len(r2.History) != 2 || r2.History[0].Disposition != Investigating {
		t.Fatalf("history must preserve the earlier decision: %+v", r2.History)
	}
	if Disposition(id) != Resolved {
		t.Fatalf("Disposition() = %q, want resolved", Disposition(id))
	}
}

// T015 (FR-021): a stale base version conflicts rather than overwriting a newer
// decision; the current record is returned so the caller can re-read.
func TestOptimisticConflict(t *testing.T) {
	t.Setenv("VHLOCAL_REVIEWS_DIR", t.TempDir())
	id := "source-v1:s1"
	if _, err := Submit(id, Submission{Disposition: Investigating, BaseVersion: 0}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	// A second writer still thinks the head is version 0 → conflict.
	cur, err := Submit(id, Submission{Disposition: Dismissed, Rationale: "x", BaseVersion: 0})
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("stale write err=%v want ErrConflict", err)
	}
	if cur.Head().Version != 1 || cur.Head().Disposition != Investigating {
		t.Fatalf("conflict must return current head unchanged: %+v", cur.Head())
	}
}

// FR-016: an unknown finding defaults to needs-review; Get reports absence.
func TestDefaultDisposition(t *testing.T) {
	t.Setenv("VHLOCAL_REVIEWS_DIR", t.TempDir())
	if Disposition("source-v1:none") != NeedsReview {
		t.Fatal("default disposition must be needs-review")
	}
	if _, ok := Get("source-v1:none"); ok {
		t.Fatal("Get must report absence for an unwritten record")
	}
}

// FR-021: a changed evidence fingerprint is detectable.
func TestEvidenceChanged(t *testing.T) {
	t.Setenv("VHLOCAL_REVIEWS_DIR", t.TempDir())
	id := "source-v1:s1"
	if _, err := Submit(id, Submission{Disposition: Dismissed, Rationale: "np", BaseVersion: 0, EvidenceFingerprint: "fp-old"}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if !EvidenceChanged(id, "fp-new") {
		t.Fatal("changed fingerprint must be detected")
	}
	if EvidenceChanged(id, "fp-old") {
		t.Fatal("same fingerprint must not report a change")
	}
}
