package verification

import (
	"os"
	"path/filepath"
	"strings"

	"vhlocal/internal/inventory"
)

// routeGuardFor resolves the route handler containing a cited location to its
// guard identity (METHOD PATH), for the supported-verdict entry-point match
// (FR-010; parity with the reference authz.guard_for_location).
//
// Documented approximation (plan Complexity #2): Go's inventory carries no handler
// end-line, so the handler span is recovered by an indentation/`def` scan
// (functionSpans) and the cited line must fall INSIDE the handler's span — mirroring
// the reference's exact [start_line, end_line] bound rather than merely resolving to
// the nearest route above. An ambiguous file match yields no route (the caller then
// imposes no entry-point requirement).
func routeGuardFor(repo, location string) (method, path string, ok bool) {
	file, cited := fileAndLine(location)
	if repo == "" || file == "" || cited == 0 {
		return "", "", false
	}
	routes, _ := inventory.EnumerateRoutes(repo)

	var inFile []inventory.Route
	for _, r := range routes {
		if r.File == file {
			inFile = append(inFile, r)
		}
	}
	if len(inFile) == 0 { // fall back to a suffix match, but require it to be unambiguous
		for _, r := range routes {
			if strings.HasSuffix(r.File, "/"+file) || strings.HasSuffix(file, "/"+r.File) {
				inFile = append(inFile, r)
			}
		}
	}
	files := map[string]bool{}
	for _, r := range inFile {
		files[r.File] = true
	}
	if len(files) != 1 {
		return "", "", false
	}
	resolved := ""
	for f := range files {
		resolved = f
	}
	if filepath.IsAbs(resolved) || strings.Contains(resolved, "..") {
		return "", "", false
	}
	b, err := os.ReadFile(filepath.Join(repo, resolved))
	if err != nil {
		return "", "", false
	}
	spans := functionSpans(strings.Split(string(b), "\n"))
	// The cited line must be inside the handler whose span begins at (or just above,
	// across decorators) the route's decorator line.
	for _, r := range inFile {
		for _, s := range spans {
			if s.start <= r.Line && r.Line <= s.end && s.start <= cited && cited <= s.end {
				return r.Method, r.Path, true
			}
		}
	}
	return "", "", false
}
