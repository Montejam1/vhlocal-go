package inventory

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"vhlocal/internal/recognize"
)

// repoRoot locates the module root from this test file's location, so the test
// can read the bundled testdata/vulnapp fixture (the parity oracle).
func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate caller")
	}
	// internal/inventory/inventory_test.go -> module root is three dirs up.
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}

func TestEnumerateVulnappRoutes(t *testing.T) {
	repo := filepath.Join(repoRoot(t), "testdata", "vulnapp")
	routes, err := EnumerateRoutes(repo)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, r := range routes {
		got[r.Path] = true
	}
	want := []string{
		"/api/search", "/api/orders/<order_id>", "/api/invoice",
		"/api/invoice/render", "/api/users",
	}
	for _, w := range want {
		if !got[w] {
			t.Errorf("route %q not enumerated; got %v", w, keys(got))
		}
	}
	if len(routes) < len(want) {
		t.Fatalf("expected >= %d routes, got %d", len(want), len(routes))
	}
	// A method-less @app.route is labelled ROUTE (the reference sentinel), NOT GET —
	// the real methods are undeclared, so the denominator does not assume GET.
	for _, r := range routes {
		if r.Method != "ROUTE" {
			t.Errorf("method-less @app.route %s expected ROUTE, got %s", r.Path, r.Method)
		}
	}
}

// C-4a (feature 006, FR-012): router/blueprint prefixes are applied, websocket
// routes are included, and a method-less route/api_route defaults to ROUTE.
func TestDenominatorPrefixesWebsocketAndRouteDefault(t *testing.T) {
	repo := t.TempDir()
	os.MkdirAll(filepath.Join(repo, "app"), 0o755)
	src := "from fastapi import APIRouter\n" + // 1
		"router = APIRouter(prefix='/ops')\n" + // 2
		"bp = Blueprint('bp', __name__, url_prefix='/admin')\n" + // 3
		"@router.get('/status')\n" + // 4  -> GET /ops/status
		"def status():\n    return 1\n" + // 5,6
		"@router.websocket('/live')\n" + // 7  -> WS /ops/live
		"async def live():\n    return 2\n" + // 8,9
		"@bp.route('/purge')\n" + // 10 -> ROUTE /admin/purge (method-less)
		"def purge():\n    return 3\n" + // 11,12
		"@bp.route('/set', methods=['POST'])\n" + // 13 -> POST /admin/set
		"def setter():\n    return 4\n" // 14,15
	os.WriteFile(filepath.Join(repo, "app", "r.py"), []byte(src), 0o644)

	routes, err := EnumerateRoutes(repo)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{
		"GET /ops/status":    false,
		"WS /ops/live":       false,
		"ROUTE /admin/purge": false,
		"POST /admin/set":    false,
	}
	for _, r := range routes {
		k := r.Method + " " + r.Path
		if _, ok := want[k]; ok {
			want[k] = true
		}
	}
	for k, ok := range want {
		if !ok {
			var got []string
			for _, r := range routes {
				got = append(got, r.Method+" "+r.Path)
			}
			t.Errorf("expected route %q; got %v", k, got)
		}
	}
}

func TestBuildLedgerDispositionsAndCompleteness(t *testing.T) {
	repo := filepath.Join(repoRoot(t), "testdata", "vulnapp")
	routes, err := EnumerateRoutes(repo)
	if err != nil {
		t.Fatal(err)
	}
	// No findings -> everything not_reviewed, NOT complete.
	lg := BuildLedger(routes, nil, repo)
	if lg.Complete {
		t.Error("a run reviewing nothing must NOT be complete (honesty)")
	}
	if lg.NotReviewed != lg.Total || lg.Total == 0 {
		t.Fatalf("expected all not_reviewed; total=%d not_reviewed=%d", lg.Total, lg.NotReviewed)
	}

	// Evidence-backed (feature 012, T048/FR-025/026): a finding INSIDE one route's
	// handler span marks ONLY that route finding_emitted; sibling handlers in the
	// same file stay not_reviewed, and the run is still incomplete.
	r0 := routes[0]
	b, err := os.ReadFile(filepath.Join(repo, r0.File))
	if err != nil {
		t.Fatal(err)
	}
	lang := recognize.Language(r0.Language)
	if lang == "" {
		lang = recognize.LangPython
	}
	sc := recognize.EnclosingScope(lang, b, r0.Line)
	inSpanLine := r0.Line
	if sc.Found {
		inSpanLine = sc.End // a line inside r0's handler body
	}
	lg2 := BuildLedger(routes, []FindingLoc{{File: r0.File, Line: inSpanLine}}, repo)
	if lg2.Counts[DispFindingEmitted] != 1 {
		t.Fatalf("a single in-span finding must mark exactly ONE route finding_emitted; counts=%v", lg2.Counts)
	}
	if lg2.NotReviewed != lg2.Total-1 {
		t.Fatalf("sibling routes must stay not_reviewed; total=%d not_reviewed=%d", lg2.Total, lg2.NotReviewed)
	}
	if lg2.Complete {
		t.Error("coverage must remain incomplete while siblings are unreviewed")
	}

	// A bare filename match (finding in the same file but OUTSIDE any route handler)
	// must NOT mark a route reviewed — a filename mention is not completed review (#3).
	lg3 := BuildLedger(routes, []FindingLoc{{File: r0.File, Line: 1}}, repo) // line 1 = imports, not a handler
	if lg3.Counts[DispFindingEmitted] != 0 {
		t.Fatalf("a finding outside every handler span must not mark any route reviewed; counts=%v", lg3.Counts)
	}
}

func TestFallbackPartitions(t *testing.T) {
	routes := []Route{
		{Subsystem: "app"}, {Subsystem: "app"}, {Subsystem: "api"},
	}
	got, uncovered := FallbackPartitions(routes, 8)
	if len(got) != 2 {
		t.Fatalf("expected 2 subsystems, got %v", got)
	}
	if len(uncovered) != 0 {
		t.Fatalf("expected no uncovered under a generous cap, got %v", uncovered)
	}
	// A tight cap records the dropped scope as uncovered (never silently drops it).
	capped, uncov := FallbackPartitions(routes, 1)
	if len(capped) != 1 {
		t.Fatalf("expected cap to 1, got %v", capped)
	}
	if len(uncov) != 1 {
		t.Fatalf("expected 1 uncovered subsystem past the cap, got %v", uncov)
	}
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestEnumerateExcludesTestsAndDedups(t *testing.T) {
	repo := t.TempDir()
	os.MkdirAll(filepath.Join(repo, "app"), 0o755)
	os.MkdirAll(filepath.Join(repo, "tests"), 0o755)
	os.WriteFile(filepath.Join(repo, "app", "r.py"),
		[]byte("@app.get('/a')\ndef a():\n    pass\n@app.get('/a')\ndef a2():\n    pass\n"), 0o644)
	os.WriteFile(filepath.Join(repo, "tests", "test_r.py"),
		[]byte("@app.get('/t')\ndef t():\n    pass\n"), 0o644)
	rs, _ := EnumerateRoutes(repo)
	na := 0
	for _, r := range rs {
		if r.Path == "/t" {
			t.Error("a route in a test file must be excluded from the denominator")
		}
		if r.Path == "/a" {
			na++
		}
	}
	if na != 1 {
		t.Errorf("duplicate /a routes must dedup to 1, got %d", na)
	}
}
