package verification

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"vhlocal/internal/consolidate"
)

// T065/T073 (C-C7): accepted amendments replay idempotently on a rebuilt manifest
// at the same revision and are rejected (nothing applied) on a revision mismatch.
func TestReplayAmendmentsIdempotentAndRevisionChecked(t *testing.T) {
	repo, root := t.TempDir(), t.TempDir()
	os.MkdirAll(filepath.Join(repo, "app"), 0o755)
	src := "from flask import Flask, request\napp = Flask(__name__)\n\n@app.route('/a')\ndef a():\n    x = request.args.get('q')\n    return x\n\n@app.route('/b')\ndef b():\n    y = request.args.get('q')\n    return y\n"
	os.WriteFile(filepath.Join(repo, "app", "r.py"), []byte(src), 0o644)
	f := consolidate.NewFinding("V1")
	f.CWE, f.Location, f.EntryPoint, f.SourceID = "CWE-862", "app/r.py:6", "GET /a", "VULN-001"
	build := func(rev string) *Manifest {
		m, err := BuildManifest(root, repo, rev, []consolidate.Finding{f})
		if err != nil {
			t.Fatal(err)
		}
		return m
	}
	m := build("rev1")
	next, am, fb := ApplyAmendment(m, repo, &m.Candidates[0], "app/r.py", 11, 11, "sink is in b", "test", 1)
	if fb != nil || am.Outcome != "accepted" || !strings.HasPrefix(am.Identity, "superseded_by:") || next.ID == m.Candidates[0].ID || len(m.Candidates) != 2 {
		t.Fatalf("amendment = %+v fb=%+v cands=%d", am, fb, len(m.Candidates))
	}
	// Replay onto a freshly built manifest at the same revision: identical result,
	// and replaying twice adds nothing.
	fresh := build("rev1")
	ReplayAmendments(fresh, m, repo)
	ReplayAmendments(fresh, m, repo)
	if len(fresh.Candidates) != 2 || fresh.Candidates[0].Superseded != next.ID || fresh.Candidates[1].ID != next.ID {
		t.Errorf("replayed manifest = %+v", fresh.Candidates)
	}
	accepted := 0
	for _, a := range fresh.Amendments {
		if a.Outcome == "accepted" {
			accepted++
		}
	}
	if accepted != 2 || len(fresh.Superseded) != 1 {
		t.Errorf("replay must be idempotent on identities: amendments=%d superseded=%d", accepted, len(fresh.Superseded))
	}
	// Revision mismatch: recorded as rejected, nothing applied.
	other := build("rev2")
	ReplayAmendments(other, m, repo)
	if len(other.Candidates) != 1 || len(other.Amendments) != 1 || other.Amendments[0].Outcome != "rejected" || !strings.Contains(other.Amendments[0].Error, "revision mismatch") {
		t.Errorf("revision mismatch handling = cands %d amendments %+v", len(other.Candidates), other.Amendments)
	}
	// Same-anchor amendment keeps the identity.
	k := build("rev1")
	kept, am2, fb2 := ApplyAmendment(k, repo, &k.Candidates[0], "app/r.py", 6, 6, "same line", "test", 1)
	if fb2 != nil || am2.Identity != "kept" || kept.ID != k.Candidates[0].ID || len(k.Candidates) != 1 {
		t.Errorf("same-anchor amendment = %+v fb=%+v", am2, fb2)
	}
}
