// Package citation validates source citations at ingestion and in verification
// sessions (feature 015, FR-025, research R8, contracts C-C1..C-C4).
//
// Grammar: `path:start[-end]`. A small set of UNAMBIGUOUS normalizations is applied
// with provenance (the original text is always retained): surrounding backticks,
// `path, line N` / `path (lines N-M)` phrasing, trailing commentary after a valid
// range, an en/figure dash in the range, and a comma list of ranges (the first is
// primary, the rest supplementary). Anything else is an error with a code, the
// field, what was received and what was expected — never a guess: no helper shifts
// a citation to nearby code, clamps a range, or picks a handler.
package citation

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"vhlocal/internal/inventory"
	"vhlocal/internal/recognize"
	"vhlocal/internal/source"
)

// Error codes (data-model "Citation").
const (
	ECitationFormat         = "E_CITATION_FORMAT"
	ECitationNoLine         = "E_CITATION_NO_LINE"
	ECitationAmbiguous      = "E_CITATION_AMBIGUOUS"
	ECitationDisjoint       = "E_CITATION_DISJOINT"
	EPathEscape             = "E_PATH_ESCAPE"
	EPathAbsolute           = "E_PATH_ABSOLUTE"
	EFileNotFound           = "E_FILE_NOT_FOUND"
	ERangeOutOfBounds       = "E_RANGE_OUT_OF_BOUNDS"
	ERevisionStale          = "E_REVISION_STALE"
	EHandlerMismatch        = "E_HANDLER_MISMATCH"
	EEvidenceSpanIncomplete = "E_EVIDENCE_SPAN_INCOMPLETE"
	ERepeatedSubmission     = "E_REPEATED_SUBMISSION"
	EToolArgsJSON           = "E_TOOL_ARGS_JSON"
	EToolArgsType           = "E_TOOL_ARGS_TYPE"
)

// Certainty of a binding.
const (
	CertaintyResolved    = "resolved"
	CertaintyAmbiguous   = "ambiguous"
	CertaintyUnsupported = "unsupported"
)

// Normalization records one applied rule with before/after text.
type Normalization struct {
	Rule   string `json:"rule"`
	Before string `json:"before"`
	After  string `json:"after"`
}

// Range is a supplementary line range in the same file.
type Range struct {
	Start int `json:"start"`
	End   int `json:"end"`
}

// Citation is a parsed (and optionally resolved) source citation.
type Citation struct {
	Path          string          `json:"path"`
	Start         int             `json:"start"`
	End           int             `json:"end"`
	Primary       bool            `json:"primary"`
	Revision      string          `json:"revision,omitempty"`
	OriginalText  string          `json:"original_text"`
	Normalization []Normalization `json:"normalization"`
	Supplementary []Range         `json:"supplementary,omitempty"`
}

// String renders the canonical form.
func (c Citation) String() string {
	if c.Start == c.End {
		return fmt.Sprintf("%s:%d", c.Path, c.Start)
	}
	return fmt.Sprintf("%s:%d-%d", c.Path, c.Start, c.End)
}

// Aids are the concrete facts a model needs to repair a citation.
type Aids struct {
	FileLength   int    `json:"file_length,omitempty"`
	Handler      string `json:"handler,omitempty"`
	Route        string `json:"route,omitempty"`
	RequiredSpan string `json:"required_span,omitempty"`
}

// Error is a structured, repairable validation failure.
type Error struct {
	Code       string `json:"code"`
	Field      string `json:"field"`
	Received   string `json:"received"`
	Expected   string `json:"expected"`
	Repairable bool   `json:"repairable"`
	Aids       Aids   `json:"aids"`
}

func (e *Error) Error() string {
	return fmt.Sprintf("%s: %s=%q, expected %s", e.Code, e.Field, e.Received, e.Expected)
}

// RouteRef is the resolved route guard (identity: METHOD PATH).
type RouteRef struct {
	Method string `json:"method"`
	Path   string `json:"path"`
}

// String is the identity form used by evidence rules ("METHOD PATH").
func (r RouteRef) String() string { return r.Method + " " + r.Path }

// HandlerRef is the enclosing handler function of a citation.
type HandlerRef struct {
	File     string `json:"file"`
	Name     string `json:"name,omitempty"`
	DeclLine int    `json:"decl_line"`
	Span     [2]int `json:"span"`
}

// Binding is what the harness could resolve around a citation.
type Binding struct {
	Route      *RouteRef   `json:"route,omitempty"`
	Handler    *HandlerRef `json:"handler,omitempty"`
	FileLength int         `json:"file_length"`
	Certainty  string      `json:"certainty"` // resolved | ambiguous | unsupported
	Reason     string      `json:"reason,omitempty"`
}

var (
	reCanonical = regexp.MustCompile(`^([^\s:` + "`" + `]+):(\d+)(?:\s*([-–‑—])\s*(\d+))?`)
	// "path, line N" / "path line N-M" / "path (lines N-M)" — path FIRST.
	reLinePhrase = regexp.MustCompile(`^([^\s,:(]+)\s*[,(]?\s*lines?\s+(\d+)(?:\s*[-–‑—]\s*(\d+))?\)?\s*$`)
	// "line N in path" / "function X, line N in path" — the anchor is ambiguous.
	reLineInPath = regexp.MustCompile(`(?i)\blines?\s+\d+(?:\s*[-–‑—]\s*\d+)?\s+(?:in|of|at)\s+\S+`)
	reFileOnly   = regexp.MustCompile(`^[^\s:]+\.[A-Za-z0-9]+$`)
	reRangeList  = regexp.MustCompile(`^\s*,\s*(\d+)(?:\s*[-–‑—]\s*(\d+))?`)
)

// Parse parses text into a Citation, applying only the unambiguous normalizations.
func Parse(text string) (Citation, *Error) {
	c := Citation{OriginalText: text, Primary: true, Normalization: []Normalization{}}
	s := strings.TrimSpace(text)
	if s == "" {
		return c, &Error{Code: ECitationFormat, Field: "location", Received: text, Expected: "path:start[-end]", Repairable: true}
	}
	if t := strings.Trim(s, "`"); t != s {
		t = strings.TrimSpace(t)
		c.Normalization = append(c.Normalization, Normalization{Rule: "strip_backticks", Before: s, After: t})
		s = t
	}
	if reLineInPath.MatchString(s) && !reCanonical.MatchString(s) {
		return c, &Error{Code: ECitationAmbiguous, Field: "location", Received: text,
			Expected: "one canonical citation path:start[-end] naming the sink lines (not a function name with a line phrase)", Repairable: true}
	}
	if m := reLinePhrase.FindStringSubmatch(s); m != nil && !reCanonical.MatchString(s) {
		after := m[1] + ":" + m[2]
		if m[3] != "" {
			after += "-" + m[3]
		}
		c.Normalization = append(c.Normalization, Normalization{Rule: "line_phrase", Before: s, After: after})
		s = after
	}
	m := reCanonical.FindStringSubmatch(s)
	if m == nil {
		if reFileOnly.MatchString(s) {
			return c, &Error{Code: ECitationNoLine, Field: "location", Received: text, Expected: "path:start[-end] with the sink line(s)", Repairable: true}
		}
		return c, &Error{Code: ECitationFormat, Field: "location", Received: text, Expected: "path:start[-end]", Repairable: true}
	}
	c.Path = m[1]
	c.Start, _ = strconv.Atoi(m[2])
	c.End = c.Start
	if m[4] != "" {
		c.End, _ = strconv.Atoi(m[4])
		if m[3] != "-" {
			canon := fmt.Sprintf("%s:%d-%d", c.Path, c.Start, c.End)
			c.Normalization = append(c.Normalization, Normalization{Rule: "range_dash", Before: s[:len(m[0])], After: canon})
		}
	}
	rest := s[len(m[0]):]
	// Supplementary ranges: ", 62-64" (same file).
	for {
		rm := reRangeList.FindStringSubmatch(rest)
		if rm == nil {
			break
		}
		r := Range{}
		r.Start, _ = strconv.Atoi(rm[1])
		r.End = r.Start
		if rm[2] != "" {
			r.End, _ = strconv.Atoi(rm[2])
		}
		c.Supplementary = append(c.Supplementary, r)
		rest = rest[len(rm[0]):]
	}
	if len(c.Supplementary) > 0 {
		c.Normalization = append(c.Normalization, Normalization{Rule: "supplementary_ranges", Before: s, After: c.String()})
	}
	if t := strings.TrimSpace(rest); t != "" {
		// Trailing commentary is only accepted after a separator (space, dash, colon,
		// paren, comma); "path:40abc" is a format error, not a citation plus prose.
		if !(strings.HasPrefix(rest, " ") || strings.HasPrefix(rest, "\t") || strings.HasPrefix(t, "(") || strings.HasPrefix(t, ",") || strings.HasPrefix(t, "—") || strings.HasPrefix(t, "-")) {
			return c, &Error{Code: ECitationFormat, Field: "location", Received: text, Expected: "path:start[-end]", Repairable: true}
		}
		c.Normalization = append(c.Normalization, Normalization{Rule: "trailing_commentary", Before: s, After: c.String()})
	}
	if c.Start < 1 || c.End < c.Start {
		return c, &Error{Code: ECitationFormat, Field: "location", Received: text, Expected: "1-based start ≤ end", Repairable: true}
	}
	for _, r := range c.Supplementary {
		if r.Start < 1 || r.End < r.Start {
			return c, &Error{Code: ECitationFormat, Field: "location", Received: text, Expected: "1-based supplementary ranges start ≤ end", Repairable: true}
		}
	}
	return c, nil
}

// Resolve checks the citation against the repository: path form, confinement,
// existence, bounds, and revision (when both are known). On success it records the
// revision and returns the file length. Nothing is clamped or shifted.
func Resolve(repo, revision string, c *Citation) (int, *Error) {
	if c.Path == "" {
		return 0, &Error{Code: ECitationFormat, Field: "path", Received: c.OriginalText, Expected: "path:start[-end]", Repairable: true}
	}
	if filepath.IsAbs(c.Path) || strings.HasPrefix(c.Path, "~") {
		return 0, &Error{Code: EPathAbsolute, Field: "path", Received: c.Path, Expected: "a repository-relative path", Repairable: true}
	}
	if repo == "" {
		return 0, &Error{Code: EFileNotFound, Field: "path", Received: c.Path, Expected: "a file inside the scanned repository", Repairable: false}
	}
	clean := filepath.ToSlash(filepath.Clean(c.Path))
	if clean == ".." || strings.HasPrefix(clean, "../") {
		return 0, &Error{Code: EPathEscape, Field: "path", Received: c.Path, Expected: "a path inside the repository (no ..)", Repairable: true}
	}
	resolved, err := source.Resolve(repo, clean)
	if err != nil {
		if strings.Contains(err.Error(), "escapes") {
			return 0, &Error{Code: EPathEscape, Field: "path", Received: c.Path, Expected: "a path that stays inside the repository (symlinks resolved)", Repairable: true}
		}
		return 0, &Error{Code: EFileNotFound, Field: "path", Received: c.Path, Expected: "an existing file inside the repository", Repairable: true}
	}
	b, err := os.ReadFile(resolved)
	if err != nil {
		return 0, &Error{Code: EFileNotFound, Field: "path", Received: c.Path, Expected: "a readable file inside the repository", Repairable: true}
	}
	n := len(strings.Split(strings.TrimRight(string(b), "\n"), "\n"))
	if len(b) == 0 {
		n = 0
	}
	if c.End > n || c.Start > n {
		return n, &Error{Code: ERangeOutOfBounds, Field: "lines", Received: fmt.Sprintf("%d-%d", c.Start, c.End),
			Expected: fmt.Sprintf("a range within 1..%d", n), Repairable: true, Aids: Aids{FileLength: n}}
	}
	for _, r := range c.Supplementary {
		if r.End > n {
			return n, &Error{Code: ERangeOutOfBounds, Field: "supplementary", Received: fmt.Sprintf("%d-%d", r.Start, r.End),
				Expected: fmt.Sprintf("a range within 1..%d", n), Repairable: true, Aids: Aids{FileLength: n}}
		}
	}
	if c.Revision != "" && revision != "" && c.Revision != revision {
		return n, &Error{Code: ERevisionStale, Field: "revision", Received: c.Revision, Expected: revision, Repairable: false}
	}
	c.Path = clean
	c.Revision = revision
	return n, nil
}

// Binder resolves handler spans and route guards; routes are enumerated once.
type Binder struct {
	repo   string
	routes []inventory.Route
	loaded bool
}

// NewBinder prepares a binder for repo (routes are enumerated lazily, once).
func NewBinder(repo string) *Binder { return &Binder{repo: repo} }

func (b *Binder) routesFor(file string) []inventory.Route {
	if !b.loaded {
		b.routes, _ = inventory.EnumerateRoutes(b.repo)
		b.loaded = true
	}
	var out []inventory.Route
	for _, r := range b.routes {
		if r.File == file {
			out = append(out, r)
		}
	}
	return out
}

// Bind resolves the handler span and route guard of a citation. It reports
// certainty honestly: resolved (one route owns the span), ambiguous (a handler span
// but no or several routes), unsupported (no language/scope support, or a
// non-HTTP surface).
func (b *Binder) Bind(c Citation) Binding {
	out := Binding{Certainty: CertaintyUnsupported}
	if b.repo == "" || c.Path == "" {
		out.Reason = "no repository or path"
		return out
	}
	src, err := source.ReadFile(b.repo, c.Path)
	if err != nil {
		out.Reason = "file unreadable"
		return out
	}
	out.FileLength = len(strings.Split(strings.TrimRight(string(src), "\n"), "\n"))
	lang, ok := recognize.LanguageFor(c.Path)
	if !ok {
		out.Reason = "unsupported language: " + filepath.Ext(c.Path)
		return out
	}
	sc := recognize.EnclosingScope(lang, src, c.Start)
	if !sc.Found {
		out.Reason = "no enclosing function at the cited line"
		return out
	}
	h := &HandlerRef{File: c.Path, DeclLine: sc.Start, Span: [2]int{sc.Start, sc.End}}
	if len(sc.Owner) > 0 {
		h.Name = sc.Owner[len(sc.Owner)-1]
	}
	out.Handler = h
	var owners []inventory.Route
	for _, r := range b.routesFor(c.Path) {
		switch {
		case r.Method == "CLI":
			continue
		case r.Handler != "" && h.Name != "":
			if r.Handler == h.Name {
				owners = append(owners, r)
			}
		case r.Line >= sc.Start && r.Line <= sc.End:
			owners = append(owners, r)
		}
	}
	switch len(owners) {
	case 1:
		out.Route = &RouteRef{Method: owners[0].Method, Path: owners[0].Path}
		out.Certainty = CertaintyResolved
	case 0:
		if _, registered := recognize.For(lang); !registered && lang != recognize.LangPython {
			out.Certainty = CertaintyUnsupported
			out.Reason = "no route recognizer for " + string(lang) + "; handler span only"
		} else {
			out.Certainty = CertaintyAmbiguous
			out.Reason = "no route registers this handler (non-HTTP or unregistered function)"
		}
	default:
		out.Certainty = CertaintyAmbiguous
		out.Reason = fmt.Sprintf("%d routes own this handler span", len(owners))
	}
	return out
}

// Bind is the one-shot convenience (enumerates routes for this call).
func Bind(repo string, c Citation) Binding { return NewBinder(repo).Bind(c) }

// AidsFor summarizes a binding as repair aids.
func AidsFor(b Binding) Aids {
	a := Aids{FileLength: b.FileLength}
	if b.Handler != nil {
		a.Handler = fmt.Sprintf("%s:%d-%d", b.Handler.File, b.Handler.Span[0], b.Handler.Span[1])
		if b.Handler.Name != "" {
			a.Handler = b.Handler.Name + " @ " + a.Handler
		}
		a.RequiredSpan = fmt.Sprintf("%d-%d", b.Handler.Span[0], b.Handler.Span[1])
	}
	if b.Route != nil {
		a.Route = b.Route.String()
	}
	return a
}
