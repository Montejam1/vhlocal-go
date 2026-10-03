package engine

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"vhlocal/internal/consolidate"
	"vhlocal/internal/review"
)

// replayCopy copies the sanitized live records into a temp results dir whose
// scan_meta.repo points at the fixture stub tree, so Regenerate can run on it.
func replayCopy(t *testing.T) (dir, repo string) {
	t.Helper()
	src := filepath.Join(repoRoot(t), "testdata", "replay-171")
	dir = filepath.Join(t.TempDir(), "replay_VULNHUNT_RESULTS_m_2026-09-29-000000")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(src)
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		b, err := os.ReadFile(filepath.Join(src, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, e.Name()), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	repo = filepath.Join(src, "target")
	var meta map[string]any
	mb, _ := os.ReadFile(filepath.Join(dir, ScanMetaFile))
	if err := json.Unmarshal(mb, &meta); err != nil {
		t.Fatal(err)
	}
	meta["repo"] = repo
	meta["results_dir"] = dir
	out, _ := json.MarshalIndent(meta, "", "  ")
	os.WriteFile(filepath.Join(dir, ScanMetaFile), out, 0o644)
	// The candidate manifest names the repo too (Reconcile compares it to the live repo).
	var man map[string]any
	cb, _ := os.ReadFile(filepath.Join(dir, "candidate_manifest.json"))
	if err := json.Unmarshal(cb, &man); err != nil {
		t.Fatal(err)
	}
	man["repo"] = repo
	mo, _ := json.MarshalIndent(man, "", "  ")
	os.WriteFile(filepath.Join(dir, "candidate_manifest.json"), mo, 0o644)
	return dir, repo
}

func findingsArray(t *testing.T, dir string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, "findings.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Findings json.RawMessage `json:"findings"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	return string(doc.Findings)
}

// T056 (C-B11): grouping rewrites no finding, decision or review record; the group
// decision status derives from the members' review records; members_changed_since
// flags members absent from the newest decision's scan; regeneration is identical.
func TestGroupsPreserveEvidenceAndDeriveDecisions(t *testing.T) {
	dir, _ := replayCopy(t)
	decisionsBefore, _ := os.ReadFile(filepath.Join(dir, "verification_decisions.json"))
	if err := Regenerate(dir); err != nil {
		t.Fatal(err)
	}
	findingsBefore := findingsArray(t, dir)
	// Regeneration re-reconciles every decision against the stub tree, so the
	// supported count is whatever the records + source support NOW — the groups must
	// cover exactly that set (raw == Σ members), never the historical 43.
	supported := 0
	var arr []map[string]any
	_ = json.Unmarshal([]byte(findingsBefore), &arr)
	for _, f := range arr {
		if consolidate.Classify(f) == consolidate.ClassSupported {
			supported++
		}
	}
	g, ok := consolidate.LoadGroups(dir)
	if !ok {
		t.Fatal("remediation_groups.json not written")
	}
	if supported == 0 || g.RawSupported != supported || g.Grouped != len(g.Groups) || g.Grouped == 0 || g.Grouped >= g.RawSupported {
		t.Fatalf("raw=%d grouped=%d supported=%d (groups must cover the supported set and reduce it)", g.RawSupported, g.Grouped, supported)
	}
	for _, gr := range g.Groups {
		if gr.DecisionStatus != "undecided" || gr.MembersChangedSince {
			t.Errorf("group %s without decisions: status=%s changed=%v", gr.ID, gr.DecisionStatus, gr.MembersChangedSince)
		}
	}
	// Pick a multi-member group and decide members in the review store.
	var multi *consolidate.Group
	for i := range g.Groups {
		if len(g.Groups[i].Members) >= 3 {
			multi = &g.Groups[i]
			break
		}
	}
	if multi == nil {
		t.Fatal("no multi-member group in the replay records")
	}
	scanID := filepath.Base(dir)
	rev := "047e3a2471ed7c14793c19798c460882cb1d1de1"
	sub := func(sid, scan string) {
		cur, _ := review.Get(sid)
		if _, err := review.Submit(sid, review.Submission{Disposition: review.Investigating, ScanID: scan, Revision: rev, Operator: "t", BaseVersion: cur.Head().Version}); err != nil {
			t.Fatal(err)
		}
	}
	// One decided member ⇒ mixed; decision from THIS scan ⇒ members present ⇒ not changed.
	sub(multi.Members[0].StableID, scanID)
	if err := Regenerate(dir); err != nil {
		t.Fatal(err)
	}
	g2, _ := consolidate.LoadGroups(dir)
	var m2 *consolidate.Group
	for i := range g2.Groups {
		if g2.Groups[i].ID == multi.ID {
			m2 = &g2.Groups[i]
		}
	}
	if m2 == nil || m2.DecisionStatus != "mixed" || m2.MembersChangedSince {
		t.Errorf("after one decision: %+v", m2)
	}
	// Every member decided ⇒ all-decided.
	for _, m := range multi.Members[1:] {
		sub(m.StableID, scanID)
	}
	if err := Regenerate(dir); err != nil {
		t.Fatal(err)
	}
	g3, _ := consolidate.LoadGroups(dir)
	for _, gr := range g3.Groups {
		if gr.ID == multi.ID && (gr.DecisionStatus != "all-decided" || gr.MembersChangedSince) {
			t.Errorf("all decided: %+v", gr)
		}
	}
	// Newest decision made at a scan where another member did not exist ⇒ changed.
	sub(multi.Members[0].StableID, "older_VULNHUNT_RESULTS_m_2026-09-01-000000")
	if err := Regenerate(dir); err != nil {
		t.Fatal(err)
	}
	g4, _ := consolidate.LoadGroups(dir)
	for _, gr := range g4.Groups {
		if gr.ID == multi.ID && !gr.MembersChangedSince {
			t.Errorf("newest decision from another scan must flag members_changed_since: %+v", gr)
		}
	}

	// Evidence untouched: findings array, decisions file, and the review store hold
	// exactly what was written (grouping added a separate record only).
	if findingsArray(t, dir) != findingsBefore {
		t.Error("grouping/regeneration changed findings.json findings")
	}
	if after, _ := os.ReadFile(filepath.Join(dir, "verification_decisions.json")); string(after) != string(decisionsBefore) {
		t.Error("verification_decisions.json changed")
	}
	rec, _ := review.Get(multi.Members[0].StableID)
	if len(rec.History) != 2 {
		t.Errorf("review history rewritten: %d entries", len(rec.History))
	}
	// Regeneration is byte-identical when nothing changed.
	b1, _ := os.ReadFile(filepath.Join(dir, consolidate.GroupsFile))
	if err := Regenerate(dir); err != nil {
		t.Fatal(err)
	}
	b2, _ := os.ReadFile(filepath.Join(dir, consolidate.GroupsFile))
	if string(b1) != string(b2) {
		t.Error("remediation_groups.json differs across identical regenerations")
	}
	// The report model carries the groups and every supported finding has one.
	mb, _ := os.ReadFile(filepath.Join(dir, "report_model.json"))
	var model struct {
		Groups []struct{ ID string } `json:"groups"`
		Index  []struct {
			GroupID string `json:"group_id"`
			Role    string `json:"role"`
		} `json:"index"`
		Counts struct {
			RemediationGroups int `json:"remediation_groups"`
			Supported         int `json:"supported"`
		} `json:"counts"`
	}
	if err := json.Unmarshal(mb, &model); err != nil {
		t.Fatal(err)
	}
	if len(model.Groups) != g.Grouped || model.Counts.RemediationGroups != g.Grouped || model.Counts.Supported != supported {
		t.Errorf("model groups=%d counts=%+v", len(model.Groups), model.Counts)
	}
	for _, row := range model.Index {
		if row.GroupID == "" || row.Role == "" {
			t.Errorf("index row lacks group/role: %+v", row)
			break
		}
	}
	// Pre-verification manifest reports equivalence only (no candidate dropped).
	cb, _ := os.ReadFile(filepath.Join(dir, "candidate_manifest.json"))
	var man struct {
		Candidates []struct {
			LikelyGroup string `json:"likely_group"`
		} `json:"candidates"`
	}
	_ = json.Unmarshal(cb, &man)
	if len(man.Candidates) != 171 {
		t.Errorf("candidate manifest must keep every candidate: %d", len(man.Candidates))
	}
}
