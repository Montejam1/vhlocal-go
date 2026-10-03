// Package inventory is the harness-owned coverage denominator: it enumerates
// entry points deterministically from source (the model dispositions this fixed
// inventory, it does not define it). This is honesty-critical — a run cannot be
// called "complete" while any enumerated route is not_reviewed (constitution
// Principle II; the gvisor "0 entry points but complete" bug).
//
// Recognition covers the two frameworks these scans target: FastAPI
// (@app.get/@router.post/... and APIRouter + include_router prefixes) and Flask
// (@app.route / blueprint .route). Non-Python entry points are a documented
// limitation, reported rather than silently dropped.
//
// NOTE (research R16): the Python original parses with CPython's `ast`. Go cannot
// reuse that, so recognition here is a purpose-built source parser. This is the
// highest fidelity-risk area of the port; behavior is pinned by tests against the
// same fixtures and any divergence is a stated limitation.
package inventory

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"vhlocal/internal/recognize"
	"vhlocal/internal/tools"
)

// Dispositions (parity with Python inventory.py).
const (
	DispFindingEmitted  = "finding_emitted"
	DispReviewedNoIssue = "reviewed_no_issue"
	DispCoveredByParent = "covered_by_parent_analysis"
	DispExcluded        = "excluded_with_reason"
	DispNotReviewed     = "not_reviewed"
)

// Route is one enumerated entry point.
type Route struct {
	Method    string
	Path      string
	File      string // repo-relative
	Line      int
	Subsystem string
	// Language is the source language of the entry point (feature 012). "" is
	// treated as "python" for backward compatibility with pre-012 callers.
	Language string
	// Handler is the recognizer's handler reference when the route is REGISTERED
	// somewhere other than its handler body (e.g. Go `mux.HandleFunc("GET /x", fn)`):
	// Line points at the registration, Handler names the function whose span is the
	// honest per-handler review/evidence span (feature 014). Empty = Line is the handler.
	Handler string
}

// LedgerEntry is one route with its disposition (serialized in coverage_ledger.json).
type LedgerEntry struct {
	Method      string `json:"method"`
	Path        string `json:"path"`
	File        string `json:"file"`
	Line        int    `json:"line"`
	Subsystem   string `json:"subsystem"`
	Disposition string `json:"disposition"`
	Evidence    string `json:"evidence"`
	Language    string `json:"language,omitempty"` // feature 012 (additive)
	// Feature 014 (additive): the unit that evidenced review, the reason for a
	// non-reviewed/excluded disposition, and a pointer to the observed evidence.
	UnitID      string `json:"unit_id,omitempty"`
	Reason      string `json:"reason,omitempty"`
	EvidenceRef string `json:"evidence_ref,omitempty"`
}

// CoverageLedger is the coverage denominator with dispositions.
type CoverageLedger struct {
	// SemanticsVersion (feature 015): the review-units evidence standard the ledger
	// was built from (1 read-overlap, 2 validated dispositions); 0 = pre-015 record.
	SemanticsVersion int            `json:"semantics_version,omitempty"`
	Total            int            `json:"total"`
	Reviewed         int            `json:"reviewed"`
	NotReviewed      int            `json:"not_reviewed"`
	Excluded         int            `json:"excluded"` // feature 014: explained exclusions (neither reviewed nor not_reviewed)
	Complete         bool           `json:"complete"`
	Counts           map[string]int `json:"counts"`
	Entries          []LedgerEntry  `json:"entries"`
	// ExcludedWithReason (feature 015, FR-030): recognized constructs outside the
	// denominator (Total) with the reason — disclosed, never counted as reviewed.
	ExcludedWithReason []LedgerEntry `json:"excluded_with_reason,omitempty"`
}

// AddExcluded lists excluded constructs on the ledger (outside Total).
func (lg *CoverageLedger) AddExcluded(ex []ExcludedRoute) {
	for _, e := range ex {
		r := e.Route
		lg.ExcludedWithReason = append(lg.ExcludedWithReason, LedgerEntry{
			Method: r.Method, Path: r.Path, File: r.File, Line: r.Line, Subsystem: r.Subsystem,
			Disposition: DispExcluded, Language: r.Language, Reason: e.Reason,
		})
	}
	if lg.Counts != nil {
		lg.Counts["ambiguous_excluded"] = len(lg.ExcludedWithReason)
	}
}

// EnumerateRoutesDetailed is EnumerateRoutes plus the constructs excluded from
// the denominator with their reasons (feature 015, FR-030).
func EnumerateRoutesDetailed(repo string) ([]Route, []ExcludedRoute, error) {
	routes, err := EnumerateRoutes(repo)
	_, excluded := recognizeRoutesDetailed(repo)
	return routes, excluded, err
}

// RouteEvidence is per-route review evidence supplied by the engine's review units
// (feature 014, FR-012/013): a `reviewed_no_issue` disposition backed by a
// validated unit that READ the handler span, or an `excluded_with_reason`.
// Keyed by the stable route id "file:line METHOD PATH".
type RouteEvidence struct {
	Disposition string // DispReviewedNoIssue | DispExcluded
	UnitID      string
	Reason      string
	EvidenceRef string
}

var httpMethods = map[string]bool{
	"get": true, "post": true, "put": true, "delete": true,
	"patch": true, "options": true, "head": true, "trace": true,
}

// FastAPI/Flask method-decorator: @app.get("/x") / @router.post('/y') / etc.
var reMethodDecorator = regexp.MustCompile(`^\s*@(\w+)\.(get|post|put|delete|patch|options|head|trace)\s*\(\s*['"]([^'"]*)['"]`)

// Flask/FastAPI route decorator carrying methods in a kwarg:
// @app.route("/x", methods=["POST"]) or @app.route("/x")
var reRouteDecorator = regexp.MustCompile(`^\s*@(\w+)\.(route|api_route)\s*\(\s*['"]([^'"]*)['"](.*)`)

// FastAPI websocket route: @app.websocket("/ws") — method labelled WS.
var reWSDecorator = regexp.MustCompile(`^\s*@(\w+)\.(websocket)\s*\(\s*['"]([^'"]*)['"]`)

var reMethodsKwarg = regexp.MustCompile(`methods\s*=\s*\[([^\]]*)\]`)

// Router/blueprint construction carrying a URL prefix:
// router = APIRouter(prefix="/ops") / bp = Blueprint("bp", __name__, url_prefix="/admin").
var rePrefixAssign = regexp.MustCompile(`^\s*(\w+)\s*=\s*(?:APIRouter|Blueprint|Router)\s*\((.*)`)
var rePrefixKwarg = regexp.MustCompile(`(?:prefix|url_prefix)\s*=\s*['"]([^'"]*)['"]`)

// EnumerateRoutes walks the repo's .py files and returns recognized routes,
// sorted deterministically. Vendored/skip dirs are excluded.
func EnumerateRoutes(repo string) ([]Route, error) {
	var routes []Route
	err := filepath.WalkDir(repo, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if tools.SkipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(p, ".py") {
			return nil
		}
		rel, _ := filepath.Rel(repo, p)
		if isTestFile(rel) { // FR-031: test files are not attack surface (denominator fidelity)
			return nil
		}
		for _, r := range routesInFile(p, rel) {
			r.Language = "python"
			routes = append(routes, r)
		}
		return nil
	})
	// Feature 012: augment the denominator with non-Python entry points recognized
	// deterministically via internal/recognize (Go today), so a mixed-language or
	// non-Python repo is not scanned against a Python-empty denominator.
	routes = append(routes, recognizeRoutes(repo)...)
	routes = dedupRoutes(routes)
	sort.Slice(routes, func(i, j int) bool {
		if routes[i].File != routes[j].File {
			return routes[i].File < routes[j].File
		}
		return routes[i].Line < routes[j].Line
	})
	return routes, err
}

// isTestFile reports whether rel is a test file (excluded from the attack-surface
// denominator — mirrors the reference inventory exclusions).
func isTestFile(rel string) bool {
	rel = filepath.ToSlash(rel)
	base := filepath.Base(rel)
	if base == "conftest.py" || strings.HasPrefix(base, "test_") || strings.HasSuffix(base, "_test.py") {
		return true
	}
	for _, seg := range strings.Split(rel, "/") {
		if seg == "tests" || seg == "test" {
			return true
		}
	}
	return false
}

// dedupRoutes removes duplicate (method, path, file) entries so the denominator is
// not inflated by repeated decorators (FR-031).
func dedupRoutes(routes []Route) []Route {
	seen := map[string]bool{}
	out := routes[:0]
	for _, r := range routes {
		k := r.Method + " " + r.Path + " " + r.File
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, r)
	}
	return out
}

func routesInFile(absPath, rel string) []Route {
	data, err := os.ReadFile(absPath)
	if err != nil {
		return nil
	}
	subsystem := subsystemOf(rel)
	lines := strings.Split(string(data), "\n")
	// First pass: map router/blueprint variable -> its declared URL prefix, so a
	// decorated path is resolved to its real path (FR-012, parity with the
	// reference _router_prefixes).
	prefixes := map[string]string{}
	for _, line := range lines {
		if m := rePrefixAssign.FindStringSubmatch(line); m != nil {
			prefix := ""
			if pm := rePrefixKwarg.FindStringSubmatch(m[2]); pm != nil {
				prefix = pm[1]
			}
			prefixes[m[1]] = prefix
		}
	}
	applyPrefix := func(obj, path string) string {
		if p := prefixes[obj] + path; p != "" {
			return p
		}
		if path != "" {
			return path
		}
		return "/"
	}
	var out []Route
	for i, line := range lines {
		if m := reMethodDecorator.FindStringSubmatch(line); m != nil {
			out = append(out, Route{
				Method: strings.ToUpper(m[2]), Path: applyPrefix(m[1], m[3]),
				File: rel, Line: i + 1, Subsystem: subsystem,
			})
			continue
		}
		if m := reWSDecorator.FindStringSubmatch(line); m != nil {
			out = append(out, Route{
				Method: "WS", Path: applyPrefix(m[1], m[3]),
				File: rel, Line: i + 1, Subsystem: subsystem,
			})
			continue
		}
		if m := reRouteDecorator.FindStringSubmatch(line); m != nil {
			for _, meth := range parseMethods(m[4]) {
				out = append(out, Route{
					Method: meth, Path: applyPrefix(m[1], m[3]),
					File: rel, Line: i + 1, Subsystem: subsystem,
				})
			}
		}
	}
	return out
}

// parseMethods extracts HTTP methods from a route/api_route decorator's tail;
// defaults to the ROUTE sentinel (not GET) when no methods= kwarg is present — the
// real methods are undeclared, so the denominator does not assume GET (FR-012,
// parity with the reference _methods_from_decorator).
func parseMethods(tail string) []string {
	m := reMethodsKwarg.FindStringSubmatch(tail)
	if m == nil {
		return []string{"ROUTE"}
	}
	var out []string
	for _, tok := range strings.Split(m[1], ",") {
		tok = strings.Trim(strings.TrimSpace(tok), `'"`)
		if tok != "" && httpMethods[strings.ToLower(tok)] {
			out = append(out, strings.ToUpper(tok))
		}
	}
	if len(out) == 0 {
		return []string{"ROUTE"}
	}
	return out
}

// subsystemOf derives a coarse subsystem label from the file's top-level dir.
func subsystemOf(rel string) string {
	parts := strings.Split(filepath.ToSlash(rel), "/")
	if len(parts) > 1 {
		return parts[0]
	}
	return "root"
}

// BuildLedger assigns a disposition to each route. findingFiles is the set of
// repo-relative files that produced a finding; analyzedText is the concatenated
// analysis corpus (per-agent hunt outputs etc.) used to detect "reviewed".
func BuildLedger(routes []Route, findings []FindingLoc, repo string) CoverageLedger {
	return BuildLedgerWithEvidence(routes, findings, repo, nil)
}

// BuildLedgerWithEvidence is BuildLedger plus the engine's review-unit evidence
// (feature 014, FR-012..014). The in-span-finding rule is unchanged and takes
// precedence; absent a finding, a route is `reviewed_no_issue` ONLY with evidence
// that a validated unit read its handler span, `excluded_with_reason` with an
// explicit exclusion, else `not_reviewed`. Handler binding stays span-exact — never
// whole-file. Reviewed counts finding_emitted + reviewed_no_issue (+ covered_by_parent);
// exclusions are neither reviewed nor not_reviewed; Complete requires zero not_reviewed.
func BuildLedgerWithEvidence(routes []Route, findings []FindingLoc, repo string, evidence map[string]RouteEvidence) CoverageLedger {
	lg := CoverageLedger{Counts: map[string]int{}}
	lg.Counts["source_exposed"] = 0 // feature 015 axis: filled by the engine from review units (never derived here)
	spans := &spanCache{repo: repo, cache: map[string]recognize.Scope{}}
	for _, r := range routes {
		disp, ev := disposition(r, findings, spans)
		e := LedgerEntry{
			Method: r.Method, Path: r.Path, File: r.File, Line: r.Line,
			Subsystem: r.Subsystem, Disposition: disp, Evidence: ev, Language: r.Language,
		}
		if disp == DispNotReviewed && evidence != nil {
			if re, ok := evidence[fmt.Sprintf("%s:%d %s %s", r.File, r.Line, r.Method, r.Path)]; ok {
				switch re.Disposition {
				case DispReviewedNoIssue, DispExcluded:
					e.Disposition = re.Disposition
					e.UnitID, e.Reason, e.EvidenceRef = re.UnitID, re.Reason, re.EvidenceRef
					if e.Evidence == "" {
						e.Evidence = re.EvidenceRef
					}
				}
			}
		}
		lg.Entries = append(lg.Entries, e)
		lg.Counts[e.Disposition]++
		switch e.Disposition {
		case DispNotReviewed:
			lg.NotReviewed++
		case DispExcluded:
			lg.Excluded++
		case DispFindingEmitted, DispReviewedNoIssue, DispCoveredByParent:
			lg.Reviewed++
		}
	}
	lg.Total = len(lg.Entries)
	lg.Complete = lg.Total > 0 && lg.NotReviewed == 0
	return lg
}

// FindingLoc is a finding's resolved source location, used to disposition routes
// with real evidence (feature 012, T048/FR-025/026).
type FindingLoc struct {
	File string
	Line int
}

// disposition is EVIDENCE-BACKED (feature 012, replacing the prior mention-based
// heuristic): a route is `finding_emitted` only when a finding's resolved location
// falls inside that route's handler function span (so a finding in a *sibling*
// handler in the same file does NOT mark this route, FR-026); a bare filename or
// path mention in the analysis corpus NEVER marks a route reviewed (FR-025, #3).
// Absent an in-span finding, the route is `not_reviewed` — the current pipeline
// emits no per-unit "reviewed, no issue" records, so coverage does not claim review
// it cannot evidence (a stricter, honest denominator).
func disposition(r Route, findings []FindingLoc, spans *spanCache) (string, string) {
	sc := spans.scopeFor(r)
	for _, f := range findings {
		if f.File != r.File {
			continue
		}
		if inHandler(f.Line, r.Line, sc) {
			return DispFindingEmitted, fmt.Sprintf("finding at %s:%d within handler", f.File, f.Line)
		}
	}
	return DispNotReviewed, ""
}

// inHandler reports whether a finding line belongs to the route's handler. When the
// handler span resolved, the finding must fall within it; otherwise (unresolved
// span) only an exact declaration-line match counts — never the whole file.
func inHandler(findingLine, routeLine int, sc recognize.Scope) bool {
	if sc.Found {
		return findingLine >= sc.Start && findingLine <= sc.End
	}
	return findingLine == routeLine
}

// spanCache resolves and memoizes handler spans per route file.
type spanCache struct {
	repo  string
	cache map[string]recognize.Scope
}

func (s *spanCache) scopeFor(r Route) recognize.Scope {
	key := fmt.Sprintf("%s#%d", r.File, r.Line)
	if v, ok := s.cache[key]; ok {
		return v
	}
	sc := recognize.Scope{}
	if s.repo != "" && r.File != "" {
		if b, err := os.ReadFile(filepath.Join(s.repo, r.File)); err == nil {
			lang := recognize.Language(r.Language)
			if lang == "" {
				lang = recognize.LangPython
			}
			// Feature 014: a registration-style route (Go HandleFunc) names its handler;
			// the honest span is the HANDLER function, not the registration block — so a
			// finding in one handler never marks its siblings, and the review-evidence
			// span (engine) and this ledger span are the same span.
			line := r.Line
			if r.Handler != "" {
				if hl := HandlerDeclLine(b, r.Handler); hl > 0 {
					line = hl
				}
			}
			sc = recognize.EnclosingScope(lang, b, line)
		}
	}
	s.cache[key] = sc
	return sc
}

// HandlerDeclLine finds the 1-based line declaring `func <name>(` (or a method
// `func (recv) <name>(`) in src; 0 when absent. Textual; the recognizer already
// validated the reference. Shared by the ledger and the engine's review evidence.
func HandlerDeclLine(src []byte, name string) int {
	if i := strings.LastIndex(name, "."); i >= 0 {
		name = name[i+1:]
	}
	for i, ln := range strings.Split(string(src), "\n") {
		t := strings.TrimSpace(ln)
		if !strings.HasPrefix(t, "func ") {
			continue
		}
		rest := strings.TrimPrefix(t, "func ")
		if strings.HasPrefix(rest, "(") {
			if j := strings.Index(rest, ")"); j >= 0 {
				rest = strings.TrimSpace(rest[j+1:])
			}
		}
		if strings.HasPrefix(rest, name+"(") {
			return i + 1
		}
	}
	return 0
}

// FallbackPartitions synthesises subsystem partitions from enumerated routes,
// used when the model's Phase-1 partition table cannot be parsed (so Phase 2
// still fans out instead of collapsing to one whole-repo pass). Deterministic and
// bounded by max. Scope beyond the cap is RETURNED as `uncovered` (subsystem names
// past the ceiling) rather than silently dropped, so coverage can name what was
// not hunted (FR-012; fixes the prior silent `subs[:max]`).
func FallbackPartitions(routes []Route, max int) (partitions, uncovered []string) {
	seen := map[string]bool{}
	var subs []string
	for _, r := range routes {
		if !seen[r.Subsystem] {
			seen[r.Subsystem] = true
			subs = append(subs, r.Subsystem)
		}
	}
	sort.Strings(subs)
	if max > 0 && len(subs) > max {
		return subs[:max], subs[max:]
	}
	return subs, nil
}

// String renders a stable id for a route (used in logs/partitions).
func (r Route) String() string {
	return r.Method + " " + r.Path + " @" + r.File + ":" + strconv.Itoa(r.Line)
}
