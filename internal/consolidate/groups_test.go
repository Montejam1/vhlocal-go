package consolidate

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func groupingFixture(t *testing.T) ([]Finding, string) {
	t.Helper()
	root := repoRootFrom(t)
	b, err := os.ReadFile(filepath.Join(root, "testdata", "grouping", "supported_findings.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fx struct {
		Findings []Finding `json:"findings"`
		Repo     string    `json:"repo"`
	}
	if err := json.Unmarshal(b, &fx); err != nil {
		t.Fatal(err)
	}
	return fx.Findings, filepath.Join(root, fx.Repo)
}

func repoRootFrom(t *testing.T) string {
	t.Helper()
	dir, _ := os.Getwd()
	for i := 0; i < 6; i++ {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		dir = filepath.Dir(dir)
	}
	t.Fatal("repo root not found")
	return ""
}

func groupOf(g Groups, id string) *Group {
	for i := range g.Groups {
		for _, m := range g.Groups[i].Members {
			if m.FindingID == id || strings.HasPrefix(m.FindingID, id) {
				return &g.Groups[i]
			}
		}
	}
	return nil
}

// T055 (C-B9, C-B10, C-B12): the live run's repeated pickle / XSS / XXE / NoSQL /
// open-redirect candidates each form ONE established group; distinct defects on one
// endpoint stay separate; every supported finding is in exactly one group; counts
// reconcile; ids are stable when a non-primary member is removed.
func TestGroupsFixture(t *testing.T) {
	findings, repo := groupingFixture(t)
	g := BuildGroups(findings, repo)
	if g.Version != GroupsVersion || g.RawSupported != 31 || g.Grouped != len(g.Groups) {
		t.Fatalf("version=%d raw=%d grouped=%d groups=%d", g.Version, g.RawSupported, g.Grouped, len(g.Groups))
	}
	sum, seen := 0, map[string]int{}
	for _, gr := range g.Groups {
		sum += len(gr.Members)
		if gr.ID[:3] != "RG-" || len(gr.ID) != 19 {
			t.Errorf("group id %q is not RG-<16hex>", gr.ID)
		}
		if gr.Status != GroupEstablished && gr.Status != GroupSuggested {
			t.Errorf("group %s status %q", gr.ID, gr.Status)
		}
		primaries := 0
		for _, m := range gr.Members {
			seen[m.FindingID]++
			if m.Role == RolePrimary {
				primaries++
			}
			if m.StableID == "" || m.EntryPoint == "" {
				t.Errorf("member %s lacks stable id / entry point", m.FindingID)
			}
		}
		if primaries != 1 {
			t.Errorf("group %s has %d primaries", gr.ID, primaries)
		}
	}
	if sum != g.RawSupported {
		t.Errorf("Σ members = %d, want raw_supported %d", sum, g.RawSupported)
	}
	for id, n := range seen {
		if n != 1 {
			t.Errorf("finding %s appears in %d groups", id, n)
		}
	}
	if len(seen) != 31 {
		t.Errorf("%d findings grouped, want 31", len(seen))
	}

	byFamily := map[string]map[string]bool{}
	for _, f := range findings {
		fam := f.CWEFamily
		if fam == "" {
			fam = f.NormalizedCWE
		}
		gr := groupOf(g, f.ID)
		if gr == nil {
			t.Fatalf("finding %s not grouped", f.ID)
		}
		if byFamily[fam] == nil {
			byFamily[fam] = map[string]bool{}
		}
		byFamily[fam][gr.ID] = true
	}
	for fam, want := range map[string]int{"xss": 1, "nosql-injection": 1, "xxe": 1, "deserialization": 1, "open-redirect": 1, "path-traversal": 2} {
		if got := len(byFamily[fam]); got != want {
			t.Errorf("family %s forms %d group(s), want %d", fam, got, want)
		}
	}
	for _, fam := range []string{"xss", "nosql-injection", "xxe", "deserialization", "open-redirect"} {
		for gid := range byFamily[fam] {
			for _, gr := range g.Groups {
				if gr.ID == gid && gr.Status != GroupEstablished {
					t.Errorf("%s group %s is %s, want established (same sink anchor)", fam, gid, gr.Status)
				}
			}
		}
	}
	// Distinct defects on one endpoint: CWE-284 and CWE-943 both cite 128-134; CWE-90
	// overlaps CWE-943 — different families never merge.
	a, b, c := groupOf(g, "CAND-221c3bf8"), groupOf(g, "CAND-ff9dd994"), groupOf(g, "CAND-82306cca")
	if a == nil || b == nil || c == nil || a.ID == b.ID || b.ID == c.ID {
		t.Errorf("different families on one endpoint merged: %v %v %v", a, b, c)
	}
	// Access-control findings in different functions never group (fixes are absent, so
	// only an identical anchor could justify it).
	if x, y := groupOf(g, "CAND-78ad0391"), groupOf(g, "CAND-ee4cc418"); x == nil || y == nil || x.ID == y.ID {
		t.Error("same family + same file + different function with no fix evidence must not group")
	}

	// Stability: removing a non-primary member of the XSS group keeps the group id.
	var xss *Group
	for i := range g.Groups {
		if g.Groups[i].Family == "xss" {
			xss = &g.Groups[i]
		}
	}
	if xss == nil || len(xss.Members) != 5 {
		t.Fatalf("xss group = %+v", xss)
	}
	drop := xss.Members[len(xss.Members)-1].FindingID
	var fewer []Finding
	for _, f := range findings {
		if f.ID != drop {
			fewer = append(fewer, f)
		}
	}
	g2 := BuildGroups(fewer, repo)
	var xss2 *Group
	for i := range g2.Groups {
		if g2.Groups[i].Family == "xss" {
			xss2 = &g2.Groups[i]
		}
	}
	if xss2 == nil || xss2.ID != xss.ID || len(xss2.Members) != 4 {
		t.Errorf("group id must survive removing an occurrence: %+v vs %+v", xss, xss2)
	}
	// Determinism.
	g3 := BuildGroups(findings, repo)
	j1, _ := json.Marshal(g)
	j3, _ := json.Marshal(g3)
	if string(j1) != string(j3) {
		t.Error("BuildGroups is not deterministic")
	}
}

func mk(id, cwe, fam, name, loc, entry, fix string) Finding {
	return Finding{ID: id, CWE: cwe, NormalizedCWE: cwe, CWEFamily: fam, CanonicalName: name, Location: loc, EntryPoint: entry, Fix: fix,
		Title: name + " at " + loc, Classification: "statically_supported", VerificationStatus: "supported", StableIdentity: "sid-" + id}
}

// T055 (C-B10): the rules on synthetic findings over the replay stub tree — shared
// CWE / title / overlapping range / route alone never group; same function with
// different sinks or same file with a compatible fix is only suggested.
func TestGroupRules(t *testing.T) {
	_, repo := groupingFixture(t)
	const f = "backend/app/dispatch_operations.py"
	ids := func(g Groups) []string {
		var out []string
		for _, gr := range g.Groups {
			out = append(out, gr.ID)
		}
		sort.Strings(out)
		return out
	}
	t.Run("same anchor + same fix ⇒ established", func(t *testing.T) {
		g := BuildGroups([]Finding{
			mk("A", "CWE-79", "xss", "Cross-Site Scripting", f+":87", "GET /ops/blurb", "escape card with markupsafe"),
			mk("B", "CWE-79", "xss", "Cross-Site Scripting", f+":88", "GET /ops/blurb", "escape the card parameter with markupsafe"),
		}, repo)
		if len(g.Groups) != 1 || g.Groups[0].Status != GroupEstablished {
			t.Errorf("groups = %+v", g.Groups)
		}
	})
	t.Run("same CWE only (different files) ⇒ separate", func(t *testing.T) {
		g := BuildGroups([]Finding{
			mk("A", "CWE-22", "path-traversal", "Path Traversal", f+":118", "POST /ops/dock", ""),
			mk("B", "CWE-22", "path-traversal", "Path Traversal", "backend/app/routers/io_csv.py:133", "POST /api/io", ""),
		}, repo)
		if len(g.Groups) != 2 {
			t.Errorf("CWE alone grouped: %v", ids(g))
		}
	})
	t.Run("same title only ⇒ separate", func(t *testing.T) {
		a := mk("A", "CWE-79", "xss", "Cross-Site Scripting", f+":88", "GET /ops/blurb", "")
		b := mk("B", "CWE-601", "open-redirect", "Open Redirect", f+":39", "GET /ops/after", "")
		b.Title = a.Title
		if g := BuildGroups([]Finding{a, b}, repo); len(g.Groups) != 2 {
			t.Errorf("title alone grouped: %v", ids(g))
		}
	})
	t.Run("overlapping range, different family ⇒ separate", func(t *testing.T) {
		g := BuildGroups([]Finding{
			mk("A", "CWE-943", "nosql-injection", "NoSQL Injection", f+":128-134", "POST /ops/mongo", ""),
			mk("B", "CWE-90", "", "", f+":130-134", "POST /ops/mongo", ""),
		}, repo)
		if len(g.Groups) != 2 {
			t.Errorf("overlap alone grouped: %v", ids(g))
		}
	})
	// Synthetic handler with TWO distinct path sinks six lines apart (distinct
	// statements in one function) — the fixture stub has no such function.
	twoSinks := func(t *testing.T) string {
		repo := t.TempDir()
		os.MkdirAll(filepath.Join(repo, "svc"), 0o755)
		src := "import os\n\ndef handler(request):\n    a = request.args.get(\"a\")\n    x = open(a).read()\n    log(x)\n    y = 1\n    z = 2\n    w = 3\n    q = 4\n    return send_file(request.args.get(\"b\"))\n"
		os.WriteFile(filepath.Join(repo, "svc", "files.py"), []byte(src), 0o644)
		return repo
	}
	t.Run("shared route, different sinks and preconditions (same family) ⇒ separate", func(t *testing.T) {
		repo := twoSinks(t)
		a := mk("A", "CWE-22", "path-traversal", "Path Traversal", "svc/files.py:5", "GET /files", "validate name")
		b := mk("B", "CWE-22", "path-traversal", "Path Traversal", "svc/files.py:11", "GET /files", "validate name")
		a.VerificationRecord = map[string]any{"preconditions": "attacker controls the a query parameter"}
		b.VerificationRecord = map[string]any{"preconditions": "attacker uploads a raw body to a shared export dir with symlinks"}
		g := BuildGroups([]Finding{a, b}, repo)
		if len(g.Groups) != 2 {
			t.Errorf("different sinks + preconditions on one route grouped: %+v", g.Groups)
		}
		for _, gr := range g.Groups {
			if gr.Anchor.Function != "handler" {
				t.Errorf("anchor function = %q, want handler", gr.Anchor.Function)
			}
		}
	})
	t.Run("same function, different statement, compatible fix ⇒ suggested", func(t *testing.T) {
		repo := twoSinks(t)
		a := mk("A", "CWE-22", "path-traversal", "Path Traversal", "svc/files.py:5", "GET /files", "reject path separators in name")
		b := mk("B", "CWE-22", "path-traversal", "Path Traversal", "svc/files.py:11", "GET /files", "reject path separators in the name parameter")
		g := BuildGroups([]Finding{a, b}, repo)
		if len(g.Groups) != 1 || g.Groups[0].Status != GroupSuggested {
			t.Errorf("groups = %+v", g.Groups)
		}
	})
	t.Run("same file, different function, compatible fix ⇒ suggested", func(t *testing.T) {
		a := mk("A", "CWE-22", "path-traversal", "Path Traversal", f+":71", "POST /ops/vault", "resolve under BASE_EXPORT_DIR and reject escapes")
		b := mk("B", "CWE-22", "path-traversal", "Path Traversal", f+":118", "POST /ops/dock", "resolve under BASE_EXPORT_DIR and reject escapes")
		g := BuildGroups([]Finding{a, b}, repo)
		if len(g.Groups) != 1 || g.Groups[0].Status != GroupSuggested {
			t.Errorf("groups = %+v", g.Groups)
		}
	})
	t.Run("same file, different function, no fix evidence ⇒ separate", func(t *testing.T) {
		g := BuildGroups([]Finding{
			mk("A", "CWE-22", "path-traversal", "Path Traversal", f+":71", "POST /ops/vault", ""),
			mk("B", "CWE-22", "path-traversal", "Path Traversal", f+":118", "POST /ops/dock", ""),
		}, repo)
		if len(g.Groups) != 2 {
			t.Errorf("no fix evidence yet grouped: %v", ids(g))
		}
	})
	t.Run("only supported non-duplicate findings", func(t *testing.T) {
		a := mk("A", "CWE-79", "xss", "Cross-Site Scripting", f+":88", "GET /ops/blurb", "")
		rej := mk("R", "CWE-79", "xss", "Cross-Site Scripting", f+":88", "GET /ops/blurb", "")
		rej.VerificationStatus, rej.Classification = "rejected", "rejected"
		dup := mk("D", "CWE-79", "xss", "Cross-Site Scripting", f+":88", "GET /ops/blurb", "")
		of := "A"
		dup.DuplicateOf = &of
		g := BuildGroups([]Finding{a, rej, dup}, repo)
		if g.RawSupported != 1 || len(g.Groups) != 1 || len(g.Groups[0].Members) != 1 {
			t.Errorf("rejected/duplicate leaked into groups: %+v", g)
		}
	})
	t.Run("likely groups for the manifest use the established rule only", func(t *testing.T) {
		keys := GroupKeys([]Finding{
			mk("A", "CWE-79", "xss", "Cross-Site Scripting", f+":87", "GET /ops/blurb", ""),
			mk("B", "CWE-79", "xss", "Cross-Site Scripting", f+":88", "GET /ops/blurb", ""),
			mk("C", "CWE-22", "path-traversal", "Path Traversal", f+":71", "POST /ops/vault", "same fix"),
			mk("D", "CWE-22", "path-traversal", "Path Traversal", f+":118", "POST /ops/dock", "same fix"),
		}, repo)
		if keys["A"] == "" || keys["A"] != keys["B"] || keys["C"] == keys["D"] {
			t.Errorf("likely groups = %v", keys)
		}
	})
}
