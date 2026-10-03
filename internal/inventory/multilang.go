package inventory

import (
	"os"
	"path/filepath"
	"sort"
	"strings"

	"vhlocal/internal/recognize"
	"vhlocal/internal/tools"
)

// recognizeRoutes enumerates non-Python entry points via internal/recognize and
// converts recognized investigation units into coverage Routes (feature 012,
// T047/T008). It groups first-party source by module (top-level directory) and
// runs each registered non-Python recognizer. Reads are confined to the repo; no
// target code is executed and no target toolchain is required. Python remains the
// responsibility of EnumerateRoutes' native walk, so behavior there is unchanged.
func recognizeRoutes(repo string) []Route {
	routes, _ := recognizeRoutesDetailed(repo)
	return routes
}

// ExcludedRoute is a recognized construct kept OUT of the coverage denominator
// with the reason (feature 015, FR-030): today an ambiguous Go receiver.
type ExcludedRoute struct {
	Route  Route  `json:"route"`
	Reason string `json:"reason"`
}

// recognizeRoutesDetailed is recognizeRoutes plus the excluded constructs.
func recognizeRoutesDetailed(repo string) ([]Route, []ExcludedRoute) {
	// Collect first-party source files grouped by (language, module).
	type key struct {
		lang   recognize.Language
		module string
	}
	groups := map[key][]recognize.SourceFile{}
	_ = filepath.WalkDir(repo, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if tools.SkipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if d.Type()&os.ModeSymlink != 0 {
			return nil
		}
		lang, ok := recognize.LanguageFor(p)
		if !ok || lang == recognize.LangPython {
			return nil // Python handled by the native enumerator; others via recognize
		}
		if _, registered := recognize.For(lang); !registered {
			return nil // no recognizer yet for this language (a documented limitation)
		}
		rel, _ := filepath.Rel(repo, p)
		rel = filepath.ToSlash(rel)
		b, rerr := os.ReadFile(p)
		if rerr != nil {
			return nil
		}
		k := key{lang: lang, module: moduleDir(rel)}
		groups[k] = append(groups[k], recognize.SourceFile{RelPath: rel, Content: b})
		return nil
	})

	var out []Route
	var excluded []ExcludedRoute
	for k, files := range groups {
		r, _ := recognize.For(k.lang)
		units, _ := r.Recognize(recognize.Module{Path: k.module, Files: files})
		for _, u := range units {
			if u.Certainty == recognize.Ambiguous {
				construct := ""
				if len(u.Evidence) > 0 {
					construct = u.Evidence[0].Construct
				}
				excluded = append(excluded, ExcludedRoute{Route: unitToRoute(u), Reason: "ambiguous receiver: " + construct + " on an identifier this file does not declare as a router"})
				continue
			}
			out = append(out, unitToRoute(u))
		}
	}
	sort.Slice(excluded, func(i, j int) bool {
		if excluded[i].Route.File != excluded[j].Route.File {
			return excluded[i].Route.File < excluded[j].Route.File
		}
		return excluded[i].Route.Line < excluded[j].Route.Line
	})
	return out, excluded
}

// unitToRoute projects a recognized unit onto the route-shaped coverage record.
// Web routes carry method+path; other surface kinds (CLI commands, etc.) are
// modeled honestly without a fake HTTP method (Method names the surface kind).
func unitToRoute(u recognize.InvestigationUnit) Route {
	file, line := splitLoc(u.Location)
	switch u.SurfaceKind {
	case recognize.SurfaceWebRoute:
		return Route{
			Method: orAny(u.SurfaceAttrs["method"]), Path: u.SurfaceAttrs["path"],
			File: file, Line: line, Subsystem: u.Module, Language: string(u.Language),
			Handler: u.HandlerRef, // feature 014: per-handler span for registration-style routes
		}
	case recognize.SurfaceCLICommand:
		return Route{
			Method: "CLI", Path: u.SurfaceAttrs["command"],
			File: file, Line: line, Subsystem: u.Module, Language: string(u.Language),
		}
	default:
		return Route{
			Method: strings.ToUpper(string(u.SurfaceKind)), Path: u.HandlerRef,
			File: file, Line: line, Subsystem: u.Module, Language: string(u.Language),
		}
	}
}

func moduleDir(rel string) string {
	if i := strings.IndexByte(rel, '/'); i >= 0 {
		return rel[:i]
	}
	return "."
}

func splitLoc(loc string) (string, int) {
	i := strings.LastIndexByte(loc, ':')
	if i < 0 {
		return loc, 0
	}
	n := 0
	for _, c := range loc[i+1:] {
		if c < '0' || c > '9' {
			return loc, 0
		}
		n = n*10 + int(c-'0')
	}
	return loc[:i], n
}

func orAny(m string) string {
	if m == "" {
		return "ANY"
	}
	return m
}
