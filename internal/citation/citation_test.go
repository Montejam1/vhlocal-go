package citation

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"vhlocal/internal/inventory"
	"vhlocal/internal/recognize"
)

func repoRoot(t *testing.T) string {
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

// T062 (C-C2): the three audited strings behave exactly as the contract says, and
// every normalization is recorded with provenance while the original is kept.
func TestParseAuditedStrings(t *testing.T) {
	_, err := Parse("confirm_password_reset function, line 224-242 in backend/app/routers/auth.py")
	if err == nil || err.Code != ECitationAmbiguous {
		t.Fatalf("function+line phrase must be ambiguous: %+v", err)
	}
	c, err := Parse("backend/app/security.py:40 - hash_token uses a fast hash for tokens")
	if err != nil || c.String() != "backend/app/security.py:40" {
		t.Fatalf("trailing commentary: %+v %v", c, err)
	}
	if len(c.Normalization) != 1 || c.Normalization[0].Rule != "trailing_commentary" || c.OriginalText == c.String() {
		t.Errorf("normalization provenance missing: %+v", c.Normalization)
	}
	c, err = Parse("backend/app/routers/customers.py:49-55, 62-64")
	if err != nil || c.Start != 49 || c.End != 55 || len(c.Supplementary) != 1 || c.Supplementary[0] != (Range{62, 64}) {
		t.Fatalf("supplementary ranges: %+v %v", c, err)
	}
	if !c.Primary {
		t.Error("the first range is primary")
	}
}

func TestParseNormalizationsAndErrors(t *testing.T) {
	cases := []struct {
		in   string
		want string
		rule string
		code string
	}{
		{"`app/x.py:12`", "app/x.py:12", "strip_backticks", ""},
		{"app/x.py, line 12", "app/x.py:12", "line_phrase", ""},
		{"app/x.py (lines 12-14)", "app/x.py:12-14", "line_phrase", ""},
		{"app/x.py:12–14", "app/x.py:12-14", "range_dash", ""},
		{"app/x.py:12-14 (the sink)", "app/x.py:12-14", "trailing_commentary", ""},
		{"app/x.py", "", "", ECitationNoLine},
		{"", "", "", ECitationFormat},
		{"just words", "", "", ECitationFormat},
		{"app/x.py:0", "", "", ECitationFormat},
		{"app/x.py:20-10", "", "", ECitationFormat},
		{"line 12 in app/x.py", "", "", ECitationAmbiguous},
		{"app/x.py:12abc", "", "", ECitationFormat},
	}
	for _, c := range cases {
		got, err := Parse(c.in)
		if c.code != "" {
			if err == nil || err.Code != c.code {
				t.Errorf("%q: want %s, got %+v (%v)", c.in, c.code, got, err)
			} else if !err.Repairable || err.Field != "location" || err.Received != c.in {
				t.Errorf("%q: error must be repairable and carry field/received: %+v", c.in, err)
			}
			continue
		}
		if err != nil || got.String() != c.want {
			t.Errorf("%q: want %s, got %s (%v)", c.in, c.want, got.String(), err)
			continue
		}
		found := false
		for _, n := range got.Normalization {
			if n.Rule == c.rule {
				found = true
			}
		}
		if c.rule != "" && !found {
			t.Errorf("%q: normalization %s not recorded: %+v", c.in, c.rule, got.Normalization)
		}
		if got.OriginalText != c.in {
			t.Errorf("%q: original text must be retained", c.in)
		}
	}
	// A canonical citation has no normalization at all.
	if c, _ := Parse("app/x.py:5-9"); len(c.Normalization) != 0 {
		t.Errorf("canonical text normalized: %+v", c.Normalization)
	}
}

// T062 (C-C4): Resolve reports confinement, existence, bounds (with the file
// length) and staleness precisely — and never clamps.
func TestResolveErrors(t *testing.T) {
	repo := t.TempDir()
	outside := t.TempDir()
	os.MkdirAll(filepath.Join(repo, "app"), 0o755)
	os.WriteFile(filepath.Join(repo, "app", "x.py"), []byte("a\nb\nc\nd\ne\n"), 0o644)
	os.WriteFile(filepath.Join(outside, "secret.py"), []byte("s\n"), 0o644)
	if err := os.Symlink(filepath.Join(outside, "secret.py"), filepath.Join(repo, "app", "link.py")); err != nil {
		t.Skip("symlinks unavailable")
	}
	check := func(text, code, field string) *Error {
		t.Helper()
		c, perr := Parse(text)
		if perr != nil {
			t.Fatalf("%q parse: %v", text, perr)
		}
		_, err := Resolve(repo, "rev1", &c)
		if code == "" {
			if err != nil {
				t.Errorf("%q: unexpected %v", text, err)
			}
			return nil
		}
		if err == nil || err.Code != code || err.Field != field {
			t.Errorf("%q: want %s/%s, got %+v", text, code, field, err)
		}
		return err
	}
	check("app/x.py:2-4", "", "")
	check("/etc/passwd:1", EPathAbsolute, "path")
	check("../outside.py:1", EPathEscape, "path")
	check("app/link.py:1", EPathEscape, "path")
	check("app/missing.py:1", EFileNotFound, "path")
	if err := check("app/x.py:4-9", ERangeOutOfBounds, "lines"); err != nil && (err.Aids.FileLength != 5 || !strings.Contains(err.Expected, "1..5")) {
		t.Errorf("out-of-bounds must state the file length: %+v", err)
	}
	c, _ := Parse("app/x.py:4-9")
	if n, err := Resolve(repo, "rev1", &c); err == nil || c.End != 9 || n != 5 {
		t.Errorf("Resolve must never clamp: end=%d n=%d err=%v", c.End, n, err)
	}
	// Stale revision: a citation recorded at rev1 checked against rev2.
	c2, _ := Parse("app/x.py:2")
	c2.Revision = "rev1"
	if _, err := Resolve(repo, "rev2", &c2); err == nil || err.Code != ERevisionStale || err.Repairable {
		t.Errorf("stale revision: %+v", err)
	}
	c3, _ := Parse("app/x.py:2")
	if n, err := Resolve(repo, "rev9", &c3); err != nil || c3.Revision != "rev9" || n != 5 {
		t.Errorf("resolve records the revision: %+v %v", c3, err)
	}
}

// T062 (C-C5 facts): Bind resolves the route guard + handler span for Python and
// Go handlers of the coverage fixture, gives a handler-only binding for JS (no
// route recognizer — disclosed as unsupported), and reports non-HTTP honestly.
func TestBindAcrossLanguages(t *testing.T) {
	repo := filepath.Join(repoRoot(t), "testdata", "coverage100")
	routes, err := inventory.EnumerateRoutes(repo)
	if err != nil || len(routes) != 100 {
		t.Fatalf("fixture routes = %d (%v)", len(routes), err)
	}
	b := NewBinder(repo)
	var py, goR inventory.Route
	for _, r := range routes {
		if py.File == "" && r.Language == "python" {
			py = r
		}
		if goR.File == "" && r.Language == "go" && r.Handler != "" {
			goR = r
		}
	}
	// Python: cite a line inside the handler body (decorator line + 2).
	pc, _ := Parse(py.File + ":" + itoa(py.Line+2))
	pb := b.Bind(pc)
	if pb.Certainty != CertaintyResolved || pb.Route == nil || pb.Route.String() != py.Method+" "+py.Path || pb.Handler == nil || pb.Handler.Span[0] > py.Line || pb.Handler.Span[1] < py.Line+2 || pb.FileLength == 0 {
		t.Errorf("python binding = %+v (route %s)", pb, py)
	}
	// Go: cite the handler function body (found by name), not the registration line.
	src, _ := os.ReadFile(filepath.Join(repo, goR.File))
	decl := inventory.HandlerDeclLine(src, goR.Handler)
	if decl == 0 {
		t.Fatalf("handler %s not found in %s", goR.Handler, goR.File)
	}
	gc, _ := Parse(goR.File + ":" + itoa(decl+1))
	gb := b.Bind(gc)
	if gb.Certainty != CertaintyResolved || gb.Route == nil || gb.Route.String() != goR.Method+" "+goR.Path || gb.Handler == nil || gb.Handler.Name != goR.Handler {
		t.Errorf("go binding = %+v (route %s)", gb, goR)
	}
	// A Go line outside any handler (package clause) is unsupported, never guessed.
	oc, _ := Parse(goR.File + ":1")
	if ob := b.Bind(oc); ob.Certainty != CertaintyUnsupported || ob.Route != nil {
		t.Errorf("out-of-function citation must not bind: %+v", ob)
	}
	// JS: handler span resolves by braces; no route recognizer ⇒ unsupported route.
	js := t.TempDir()
	os.WriteFile(filepath.Join(js, "server.js"), []byte("const app = require('express')();\napp.get('/items', function (req, res) {\n  const q = req.query.q;\n  res.send(q);\n});\n"), 0o644)
	jc, _ := Parse("server.js:3")
	jb := NewBinder(js).Bind(jc)
	if jb.Handler == nil || jb.Handler.Span[0] > 3 || jb.Handler.Span[1] < 3 || jb.Certainty != CertaintyUnsupported || jb.Route != nil {
		t.Errorf("js binding = %+v", jb)
	}
	// Aids carry the facts a repair needs.
	a := AidsFor(pb)
	if a.FileLength == 0 || a.Handler == "" || a.Route == "" || a.RequiredSpan == "" {
		t.Errorf("aids = %+v", a)
	}
	_ = recognize.LangGo
}

func itoa(n int) string { return strings.TrimSpace(strings.Repeat(" ", 0) + intStr(n)) }

func intStr(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var d []byte
	for n > 0 {
		d = append([]byte{byte('0' + n%10)}, d...)
		n /= 10
	}
	if neg {
		return "-" + string(d)
	}
	return string(d)
}
