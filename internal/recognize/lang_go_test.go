package recognize

import "testing"

const goFixture = `package app

import (
	"net/http"
	"github.com/gin-gonic/gin"
	"github.com/go-chi/chi/v5"
	"github.com/spf13/cobra"
)

// A fake route in a comment must NOT be recognized: mux.HandleFunc("GET /comment", h)
const fakeInString = "POST /not-a-route"

func register(mux *http.ServeMux, r *gin.Engine, c chi.Router) {
	http.HandleFunc("/health", healthHandler)
	mux.HandleFunc("GET /users/{id}", getUser)
	r.POST("/login", loginHandler)
	c.Get("/items", listItems)
}

var rootCmd = &cobra.Command{
	Use: "serve [flags]",
	Run: runServe,
}

func healthHandler(w http.ResponseWriter, req *http.Request) {}
func getUser(w http.ResponseWriter, req *http.Request)      {}
func loginHandler(ctx *gin.Context)                          {}
func listItems(w http.ResponseWriter, req *http.Request)     {}
func runServe(cmd *cobra.Command, args []string)             {}
`

func recognizeGo(t *testing.T, src string) []InvestigationUnit {
	t.Helper()
	r, ok := For(LangGo)
	if !ok {
		t.Fatal("Go recognizer not registered")
	}
	units, lims := r.Recognize(Module{Path: "app", Files: []SourceFile{{RelPath: "app/routes.go", Content: []byte(src)}}})
	for _, l := range lims {
		if l.Kind == "parse-error" {
			t.Fatalf("unexpected parse error: %s", l.Reason)
		}
	}
	return units
}

// find returns the unit whose surface_attrs method+path (or command) match.
func find(units []InvestigationUnit, key string) *InvestigationUnit {
	for i := range units {
		a := units[i].SurfaceAttrs
		if a["method"]+" "+a["path"] == key || a["command"] == key {
			return &units[i]
		}
	}
	return nil
}

// T016 (FR-008/010/011, SC-003): Go recognizer finds net/http (incl. Go 1.22
// method-path), Gin, Chi routes and Cobra commands with correct method/path/handler.
func TestGoRecognizerRoutesAndCLI(t *testing.T) {
	units := recognizeGo(t, goFixture)

	// net/http HandleFunc (no method → ANY)
	if u := find(units, "ANY /health"); u == nil || u.Framework != "net/http" || u.HandlerRef != "healthHandler" {
		t.Fatalf("net/http /health not recognized correctly: %+v", u)
	}
	// Go 1.22 method-path on a ServeMux var
	if u := find(units, "GET /users/{id}"); u == nil || u.Framework != "net/http" || u.HandlerRef != "getUser" {
		t.Fatalf("net/http method-path not recognized: %+v", u)
	}
	// Gin (all-caps verb)
	if u := find(units, "POST /login"); u == nil || u.Framework != "gin" || u.HandlerRef != "loginHandler" {
		t.Fatalf("gin route not recognized: %+v", u)
	}
	// Chi (Title-case verb)
	if u := find(units, "GET /items"); u == nil || u.Framework != "chi" || u.HandlerRef != "listItems" {
		t.Fatalf("chi route not recognized: %+v", u)
	}
	// Cobra command
	if u := find(units, "serve"); u == nil || u.AppType != AppCLI || u.HandlerRef != "runServe" {
		t.Fatalf("cobra command not recognized: %+v", u)
	}
}

// T016 (SC-004): negative controls — a route in a comment or a string literal
// yields NO unit (only real call expressions are recognized).
func TestGoRecognizerNegativeControls(t *testing.T) {
	units := recognizeGo(t, goFixture)
	if u := find(units, "GET /comment"); u != nil {
		t.Fatal("a route in a comment must not be recognized")
	}
	if u := find(units, "POST /not-a-route"); u != nil {
		t.Fatal("a route string in a const must not be recognized")
	}
	// Exactly the 5 real units (4 routes + 1 command).
	if len(units) != 5 {
		t.Fatalf("expected 5 units, got %d: %+v", len(units), units)
	}
}

// C-R3: recognition is deterministic (same ids/order on re-run).
func TestGoRecognizerDeterministic(t *testing.T) {
	a := recognizeGo(t, goFixture)
	b := recognizeGo(t, goFixture)
	if len(a) != len(b) {
		t.Fatalf("nondeterministic count: %d vs %d", len(a), len(b))
	}
	for i := range a {
		if a[i].ID != b[i].ID {
			t.Fatalf("nondeterministic id at %d: %s vs %s", i, a[i].ID, b[i].ID)
		}
	}
}

// A malformed file yields a parse-error Limitation, not a dropped module (C-U5).
func TestGoRecognizerParseErrorIsolated(t *testing.T) {
	r, _ := For(LangGo)
	mod := Module{Path: "app", Files: []SourceFile{
		{RelPath: "app/bad.go", Content: []byte("package app\nfunc (\n")},
		{RelPath: "app/ok.go", Content: []byte("package app\nimport \"net/http\"\nfunc reg(){ http.HandleFunc(\"/ok\", h) }\nfunc h(w http.ResponseWriter, r *http.Request){}\n")},
	}}
	units, lims := r.Recognize(mod)
	if find(units, "ANY /ok") == nil {
		t.Fatal("a good file must still be recognized when a sibling is malformed")
	}
	var sawParseErr bool
	for _, l := range lims {
		if l.Kind == "parse-error" {
			sawParseErr = true
		}
	}
	if !sawParseErr {
		t.Fatal("malformed file must yield a parse-error limitation")
	}
}

// Feature 015 (FR-030, C-C15, T068): request/header/values `.Get(...)` chains are
// not routes; genuine Gin/Chi/ServeMux/echo registrations (including Group/Route
// closure params and package-level http.HandleFunc) stay recognized with handler
// refs; an unknown receiver with a "/path" argument is ambiguous (disclosed) and a
// non-path argument is dropped.
const goReceiverFixture = `package app

import (
	"net/http"
	"net/url"
	"github.com/gin-gonic/gin"
	"github.com/go-chi/chi/v5"
	"github.com/labstack/echo/v4"
)

type server struct{ router *gin.Engine }

func wire(mux *http.ServeMux) {
	http.HandleFunc("/health", healthHandler)
	mux.HandleFunc("GET /users/{id}", getUser)
	g := gin.Default()
	g.POST("/login", loginHandler)
	api := g.Group("/api")
	api.GET("/items", listItems)
	c := chi.NewRouter()
	c.Get("/things", listThings)
	c.Route("/admin", func(r chi.Router) {
		r.Delete("/users/{id}", deleteUser)
	})
	e := echo.New()
	e.PUT("/echo", echoHandler)
	s := &server{router: gin.New()}
	s.router.PATCH("/patched", patchHandler)
	_ = unknownThing.Get("/looks-like-a-path", nil)
	_ = unknownThing.Get("q", nil)
}

func getUser(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q")
	h := r.Header.Get("X-Trace")
	w.Header().Get("Y")
	values := url.Values{}
	_ = values.Get("z")
	_, _ = q, h
}
func healthHandler(w http.ResponseWriter, r *http.Request) {}
func loginHandler(ctx *gin.Context)                          {}
func listItems(ctx *gin.Context)                             {}
func listThings(w http.ResponseWriter, r *http.Request)      {}
func deleteUser(w http.ResponseWriter, r *http.Request)      {}
func patchHandler(ctx *gin.Context)                          {}
func echoHandler(c echo.Context) error                       { return nil }
`

func TestGoRecognizerReceiverInference(t *testing.T) {
	units := recognizeGo(t, goReceiverFixture)
	for _, key := range []string{"GET q", "GET X-Trace", "GET Y", "GET z", "GET /looks-like-a-path"} {
		if u := find(units, key); u != nil && u.Certainty != Ambiguous {
			t.Errorf("%q must not be a resolved route: %+v", key, u)
		}
	}
	amb := find(units, "GET /looks-like-a-path")
	if amb == nil || amb.Certainty != Ambiguous {
		t.Errorf("unknown receiver with a path-like argument must be disclosed as ambiguous: %+v", amb)
	}
	if u := find(units, "GET q"); u != nil {
		t.Errorf("a non-path argument on an unknown receiver must be dropped: %+v", u)
	}
	want := map[string]string{
		"ANY /health": "healthHandler", "GET /users/{id}": "getUser", "POST /login": "loginHandler",
		"GET /items": "listItems", "GET /things": "listThings", "DELETE /users/{id}": "deleteUser",
		"PUT /echo": "echoHandler", "PATCH /patched": "patchHandler",
	}
	for key, handler := range want {
		u := find(units, key)
		if u == nil || u.HandlerRef != handler || u.Certainty != Resolved {
			t.Errorf("%s: %+v (want handler %s, resolved)", key, u, handler)
		}
	}
	resolved := 0
	for _, u := range units {
		if u.Certainty == Resolved {
			resolved++
		}
	}
	if resolved != len(want) {
		t.Errorf("resolved units = %d, want %d: %+v", resolved, len(want), units)
	}
}
