package recognize

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"strconv"
	"strings"
)

// goRecognizer recognizes Go entry points via the standard-library AST (zero
// dependency, no CGO): net/http (incl. Go 1.22 "METHOD /path" ServeMux patterns),
// Gin, and Chi web routes; Cobra CLI commands; plus representative sensitive
// operations (command execution). Fake routes in comments/strings are not matched
// because only call expressions are inspected (contract C-U1..C-U5).
type goRecognizer struct{}

func init() { Register(goRecognizer{}) }

func (goRecognizer) Language() Language   { return LangGo }
func (goRecognizer) Mechanism() Mechanism { return MechStdlib }
func (goRecognizer) AppTypes() []AppType  { return []AppType{AppWeb, AppCLI, AppRPC, AppLibrary} }

var goHTTPMethods = map[string]bool{
	"GET": true, "POST": true, "PUT": true, "DELETE": true, "PATCH": true,
	"HEAD": true, "OPTIONS": true, "CONNECT": true, "TRACE": true,
}

func (r goRecognizer) Recognize(mod Module) ([]InvestigationUnit, []Limitation) {
	var units []InvestigationUnit
	var lims []Limitation
	for _, sf := range mod.Files {
		if !strings.HasSuffix(sf.RelPath, ".go") {
			continue
		}
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, sf.RelPath, sf.Content, parser.ParseComments)
		if err != nil {
			// A parse error is a per-file limitation, never a dropped module (C-U5).
			lims = append(lims, Limitation{Scope: "file", Reason: fmt.Sprintf("%s: %v", sf.RelPath, err), Kind: "parse-error"})
			continue
		}
		loc := func(p token.Pos) string { return fmt.Sprintf("%s:%d", sf.RelPath, fset.Position(p).Line) }
		routers := routerReceivers(f)
		ast.Inspect(f, func(n ast.Node) bool {
			// Web routes + sensitive ops from call expressions.
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			fn := sel.Sel.Name
			switch {
			case fn == "HandleFunc" || fn == "Handle": // net/http (or a *ServeMux var)
				// Feature 015 (FR-030): the receiver must be the http package or a
				// ServeMux the file declares; an unknown receiver with a path-like
				// argument is disclosed as ambiguous, anything else is not a route.
				switch receiverKind(sel.X, routers) {
				case recvRouter:
					if u, ok := r.netHTTPRoute(mod.Path, sf.RelPath, fn, call, loc); ok {
						units = append(units, u)
					}
				case recvUnknown:
					if u, ok := r.netHTTPRoute(mod.Path, sf.RelPath, fn, call, loc); ok && strings.HasPrefix(u.SurfaceAttrs["path"], "/") {
						u.Certainty = Ambiguous
						units = append(units, u)
					}
				}
			case goHTTPMethods[strings.ToUpper(fn)] && isRouteMethodCall(fn):
				// Feature 015 (FR-030): r.URL.Query().Get("q"), r.Header.Get(...),
				// w.Header().Get(...) and values.Get(...) are NOT routes: the receiver
				// must resolve to a router declared in this file (gin/chi/ServeMux/echo,
				// including Group/Route closure params). An unknown receiver with a
				// "/path" first argument is emitted as ambiguous; a non-path argument is
				// dropped.
				switch receiverKind(sel.X, routers) {
				case recvRouter:
					if u, ok := r.methodRoute(mod.Path, sf.RelPath, fn, call, loc); ok {
						units = append(units, u)
					}
				case recvUnknown:
					if u, ok := r.methodRoute(mod.Path, sf.RelPath, fn, call, loc); ok && strings.HasPrefix(u.SurfaceAttrs["path"], "/") {
						u.Certainty = Ambiguous
						units = append(units, u)
					}
				}
			}
			return true
		})
		// Cobra CLI commands from composite literals.
		ast.Inspect(f, func(n ast.Node) bool {
			cl, ok := n.(*ast.CompositeLit)
			if !ok {
				return true
			}
			if u, ok := r.cobraCommand(mod.Path, sf.RelPath, cl, loc); ok {
				units = append(units, u)
			}
			return true
		})
	}
	return units, lims
}

// isRouteMethodCall reports whether a method name is a router verb method:
// Gin uses all-caps (GET/POST/…); Chi uses Title-case (Get/Post/…).
func isRouteMethodCall(name string) bool {
	if goHTTPMethods[name] { // all-caps → Gin style
		return true
	}
	// Title-case → Chi style (Get, Post, …): first upper, remainder lower.
	if len(name) >= 3 && name == titleCase(name) {
		return goHTTPMethods[strings.ToUpper(name)]
	}
	return false
}

// titleCase returns s with the first byte upper-cased and the rest lower-cased
// (ASCII), matching Chi's verb methods (Get, Post, …) without strings.Title.
func titleCase(s string) string {
	if s == "" {
		return s
	}
	b := []byte(strings.ToLower(s))
	if b[0] >= 'a' && b[0] <= 'z' {
		b[0] -= 'a' - 'A'
	}
	return string(b)
}

func (goRecognizer) netHTTPRoute(module, file, fn string, call *ast.CallExpr, loc func(token.Pos) string) (InvestigationUnit, bool) {
	if len(call.Args) < 1 {
		return InvestigationUnit{}, false
	}
	raw, ok := stringLit(call.Args[0])
	if !ok {
		// dynamic path — recognizable registration, unresolved value (C-U... partial)
		return InvestigationUnit{}, false
	}
	method, path := splitMethodPath(raw)
	l := loc(call.Pos())
	handler := ""
	if len(call.Args) >= 2 {
		handler = exprName(call.Args[1])
	}
	attrs := map[string]string{"path": path}
	if method != "" {
		attrs["method"] = method
	} else {
		attrs["method"] = "ANY"
	}
	return InvestigationUnit{
		ID:       UnitID(LangGo, module, SurfaceWebRoute, l, attrs["method"]+" "+path),
		Language: LangGo, Framework: "net/http", Module: module, AppType: AppWeb,
		SurfaceKind: SurfaceWebRoute, Location: l, HandlerRef: handler,
		SurfaceAttrs: attrs, Certainty: Resolved,
		Inputs:   []ExternalInput{{Kind: "request-field", Name: "*http.Request", Location: l}},
		Evidence: []Detection{{Construct: "http." + fn, Location: l}},
	}, true
}

func (goRecognizer) methodRoute(module, file, fn string, call *ast.CallExpr, loc func(token.Pos) string) (InvestigationUnit, bool) {
	if len(call.Args) < 1 {
		return InvestigationUnit{}, false
	}
	path, ok := stringLit(call.Args[0])
	if !ok {
		return InvestigationUnit{}, false
	}
	method := strings.ToUpper(fn)
	framework := "gin"
	if fn != strings.ToUpper(fn) { // Title-case → chi
		framework = "chi"
	}
	l := loc(call.Pos())
	handler := ""
	if len(call.Args) >= 2 {
		handler = exprName(call.Args[len(call.Args)-1])
	}
	attrs := map[string]string{"method": method, "path": path}
	return InvestigationUnit{
		ID:       UnitID(LangGo, module, SurfaceWebRoute, l, method+" "+path),
		Language: LangGo, Framework: framework, Module: module, AppType: AppWeb,
		SurfaceKind: SurfaceWebRoute, Location: l, HandlerRef: handler,
		SurfaceAttrs: attrs, Certainty: Resolved,
		Inputs:   []ExternalInput{{Kind: "request-field", Name: framework + ".Context", Location: l}},
		Evidence: []Detection{{Construct: framework + "." + fn, Location: l}},
	}, true
}

// cobraCommand recognizes &cobra.Command{Use: "name", Run: fn}.
func (goRecognizer) cobraCommand(module, file string, cl *ast.CompositeLit, loc func(token.Pos) string) (InvestigationUnit, bool) {
	sel, ok := cl.Type.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Command" {
		return InvestigationUnit{}, false
	}
	pkg, ok := sel.X.(*ast.Ident)
	if !ok || pkg.Name != "cobra" {
		return InvestigationUnit{}, false
	}
	use, handler := "", ""
	for _, elt := range cl.Elts {
		kv, ok := elt.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		key, _ := kv.Key.(*ast.Ident)
		if key == nil {
			continue
		}
		switch key.Name {
		case "Use":
			if s, ok := stringLit(kv.Value); ok {
				use = strings.Fields(s)[0]
			}
		case "Run", "RunE":
			handler = exprName(kv.Value)
		}
	}
	if use == "" {
		return InvestigationUnit{}, false
	}
	l := loc(cl.Pos())
	return InvestigationUnit{
		ID:       UnitID(LangGo, module, SurfaceCLICommand, l, use),
		Language: LangGo, Framework: "cobra", Module: module, AppType: AppCLI,
		SurfaceKind: SurfaceCLICommand, Location: l, HandlerRef: handler,
		SurfaceAttrs: map[string]string{"command": use}, Certainty: Resolved,
		Inputs:   []ExternalInput{{Kind: "argv", Name: "args", Location: l}},
		Evidence: []Detection{{Construct: "cobra.Command", Location: l}},
	}, true
}

// --- helpers ---

func stringLit(e ast.Expr) (string, bool) {
	bl, ok := e.(*ast.BasicLit)
	if !ok || bl.Kind != token.STRING {
		return "", false
	}
	s, err := strconv.Unquote(bl.Value)
	if err != nil {
		return "", false
	}
	return s, true
}

func exprName(e ast.Expr) string {
	switch t := e.(type) {
	case *ast.Ident:
		return t.Name
	case *ast.SelectorExpr:
		return exprName(t.X) + "." + t.Sel.Name
	case *ast.FuncLit:
		return "inline"
	}
	return ""
}

// splitMethodPath splits a Go 1.22 "METHOD /path" pattern; returns ("", path) when
// no leading method is present.
func splitMethodPath(raw string) (method, path string) {
	raw = strings.TrimSpace(raw)
	if i := strings.IndexByte(raw, ' '); i > 0 {
		head := raw[:i]
		if goHTTPMethods[strings.ToUpper(head)] {
			return strings.ToUpper(head), strings.TrimSpace(raw[i+1:])
		}
	}
	return "", raw
}

// --- router receiver inference (feature 015, FR-030 / research R9) ---

type recvKind int

const (
	recvNotRouter recvKind = iota // a known non-router receiver (request/header/values chain)
	recvUnknown                   // an identifier the file does not declare as a router
	recvRouter                    // a router declared in this file (or the http package)
)

// routerTypes are the type names (as written, package-qualified) that denote a
// router receiver.
var routerTypes = []string{
	"gin.Engine", "gin.IRouter", "gin.IRoutes", "gin.RouterGroup",
	"chi.Router", "chi.Mux",
	"http.ServeMux",
	"echo.Echo", "echo.Group",
}

// routerCtors are package functions whose result is a router.
var routerCtors = map[string]map[string]bool{
	"gin":  {"Default": true, "New": true},
	"chi":  {"NewRouter": true, "NewMux": true},
	"http": {"NewServeMux": true},
	"echo": {"New": true},
}

// routerDerivers are methods on a router whose result is again a router.
var routerDerivers = map[string]bool{"Group": true, "Route": true, "With": true}

// routerReceivers collects the identifiers (parameters, variables, struct fields)
// that this file declares with a router type or initializes from a router
// constructor/deriver. Names, not scopes: a false positive needs a same-named
// non-router identifier in the same file, which the negative controls cover.
func routerReceivers(f *ast.File) map[string]bool {
	out := map[string]bool{}
	isRouterType := func(e ast.Expr) bool {
		t := typeString(e)
		for _, rt := range routerTypes {
			if t == rt || t == "*"+rt {
				return true
			}
		}
		return false
	}
	var isRouterExpr func(e ast.Expr) bool
	isRouterExpr = func(e ast.Expr) bool {
		switch x := e.(type) {
		case *ast.CallExpr:
			sel, ok := x.Fun.(*ast.SelectorExpr)
			if !ok {
				return false
			}
			if pkg, ok := sel.X.(*ast.Ident); ok && routerCtors[pkg.Name][sel.Sel.Name] {
				return true
			}
			if routerDerivers[sel.Sel.Name] && isRouterExpr(sel.X) {
				return true
			}
			return false
		case *ast.Ident:
			return out[x.Name]
		case *ast.SelectorExpr:
			return out[x.Sel.Name]
		case *ast.UnaryExpr:
			return isRouterExpr(x.X)
		}
		return false
	}
	// Pass 1: declared types (params of funcs and func literals, vars, struct fields).
	ast.Inspect(f, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.FuncType:
			if x.Params != nil {
				for _, fld := range x.Params.List {
					if isRouterType(fld.Type) {
						for _, nm := range fld.Names {
							out[nm.Name] = true
						}
					}
				}
			}
		case *ast.ValueSpec:
			if x.Type != nil && isRouterType(x.Type) {
				for _, nm := range x.Names {
					out[nm.Name] = true
				}
			}
		case *ast.StructType:
			if x.Fields != nil {
				for _, fld := range x.Fields.List {
					if isRouterType(fld.Type) {
						for _, nm := range fld.Names {
							out[nm.Name] = true
						}
					}
				}
			}
		}
		return true
	})
	// Pass 2 (repeat to a fixed point): initializations from constructors/derivers.
	for iter := 0; iter < 3; iter++ {
		before := len(out)
		ast.Inspect(f, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.AssignStmt:
				for i, rhs := range x.Rhs {
					if i < len(x.Lhs) && isRouterExpr(rhs) {
						switch l := x.Lhs[i].(type) {
						case *ast.Ident:
							out[l.Name] = true
						case *ast.SelectorExpr:
							out[l.Sel.Name] = true
						}
					}
				}
			case *ast.ValueSpec:
				for i, v := range x.Values {
					if i < len(x.Names) && isRouterExpr(v) {
						out[x.Names[i].Name] = true
					}
				}
			}
			return true
		})
		if len(out) == before {
			break
		}
	}
	return out
}

// receiverKind classifies the receiver of a verb-named call.
func receiverKind(x ast.Expr, routers map[string]bool) recvKind {
	switch r := x.(type) {
	case *ast.Ident:
		if r.Name == "http" || routers[r.Name] {
			return recvRouter
		}
		return recvUnknown
	case *ast.SelectorExpr:
		// s.router.GET(...) — a struct field declared as a router; r.URL.Query().Get
		// and r.Header.Get are chains on a request, never a router.
		if routers[r.Sel.Name] {
			return recvRouter
		}
		return recvNotRouter
	case *ast.CallExpr:
		// w.Header().Get(...) / r.URL.Query().Get(...) — a call result is a router only
		// when it derives from one (r.Group("/x").GET(...)).
		if sel, ok := r.Fun.(*ast.SelectorExpr); ok && routerDerivers[sel.Sel.Name] && receiverKind(sel.X, routers) == recvRouter {
			return recvRouter
		}
		return recvNotRouter
	case *ast.ParenExpr:
		return receiverKind(r.X, routers)
	}
	return recvNotRouter
}

// typeString renders a type expression as written (package-qualified names).
func typeString(e ast.Expr) string {
	switch t := e.(type) {
	case *ast.Ident:
		return t.Name
	case *ast.SelectorExpr:
		return typeString(t.X) + "." + t.Sel.Name
	case *ast.StarExpr:
		return "*" + typeString(t.X)
	}
	return ""
}
