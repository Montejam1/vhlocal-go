// Package threatmodel validates Mermaid flowchart diagrams in threat_model.md as
// structured artifacts (feature 015, FR-011..014): a deliberately small subset
// parser (nodes, edges with labels, subgraph trust boundaries, comments), a
// deterministic serializer, bounded and RECORDED repairs that never change
// topology, and honest error states. Anything outside the subset is reported as
// unsupported — never guessed. The browser-side mermaid.parse (pinned renderer)
// remains the authoritative check; this package makes the structure inspectable
// and the failure explainable offline.
package threatmodel

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Version is the threat_model_diagram.json schema version.
const Version = 1

// RendererVersion is the Mermaid version embedded in both UIs (vhlocal/web/mermaid.min.js
// and web-react's lockfile); the artifact records what the structure was validated for.
const RendererVersion = "11.17.2"

// ArtifactFile is written next to threat_model.md.
const ArtifactFile = "threat_model_diagram.json"

// Diagram states.
const (
	StateValid       = "valid"
	StateRepaired    = "repaired"
	StateInvalid     = "invalid"
	StateUnsupported = "unsupported"
	StateMissing     = "missing"
)

// Repair rule ids (the only changes ever applied; each is recorded).
const (
	RCloseLabelQuote = "R_CLOSE_LABEL_QUOTE" // `F["SQL DB (x)"` → append the missing `]`
	RQuoteGap        = "R_QUOTE_GAP"         // `A["x" ]` → `A["x"]`
	RQuoteLabel      = "R_QUOTE_LABEL"       // unquoted node/edge label with special chars → quoted
	RStripDirective  = "R_STRIP_DIRECTIVE"   // style/classDef/class/click/linkStyle lines removed
	RASCIILabel      = "R_ASCII_LABEL"       // → – ‑ inside a quoted label → -> - -
)

// Error codes.
const (
	EEdgeLabelUnterminated = "E_EDGE_LABEL_UNTERMINATED"
	ENodeBracket           = "E_NODE_BRACKET"
	ESubgraphID            = "E_SUBGRAPH_ID"
	ESyntax                = "E_SYNTAX"
	EUnsupportedDiagram    = "E_UNSUPPORTED_DIAGRAM"
	EEmpty                 = "E_EMPTY"
)

// Artifact is threat_model_diagram.json.
type Artifact struct {
	Version         int       `json:"version"`
	RendererVersion string    `json:"renderer_version"`
	Source          string    `json:"source"`
	Diagrams        []Diagram `json:"diagrams"`
}

// Diagram is one ```mermaid fence's validation result.
type Diagram struct {
	Index      int        `json:"index"`
	FenceLine  int        `json:"fence_line"` // 1-based line of the opening fence in the Markdown
	Kind       string     `json:"kind"`       // flowchart | <other, unsupported> | ""
	Direction  string     `json:"direction,omitempty"`
	State      string     `json:"state"`
	Original   string     `json:"original,omitempty"`
	Normalized string     `json:"normalized,omitempty"` // deterministic serialization (valid/repaired)
	Structure  *Structure `json:"structure,omitempty"`
	Repairs    []Repair   `json:"repairs"`
	Errors     []Error    `json:"errors"`
}

type Structure struct {
	Nodes      []Node     `json:"nodes"`
	Edges      []Edge     `json:"edges"`
	Boundaries []Boundary `json:"boundaries"`
}

type Node struct {
	ID    string `json:"id"`
	Label string `json:"label"`
	Shape string `json:"shape"` // rect | round | diamond | cylinder | circle | flag | plain
}

type Edge struct {
	From  string `json:"from"`
	To    string `json:"to"`
	Style string `json:"style"` // solid | dotted | thick
	Label string `json:"label,omitempty"`
}

type Boundary struct {
	ID    string   `json:"id"`
	Label string   `json:"label"`
	Nodes []string `json:"nodes"`
}

// Repair records one applied rule (line is 1-based within the fence body).
type Repair struct {
	Rule   string `json:"rule"`
	Line   int    `json:"line"`
	Before string `json:"before"`
	After  string `json:"after"`
}

// Error is one validation failure (line is 1-based within the fence body).
type Error struct {
	Line    int    `json:"line"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

var (
	reFenceOpen  = regexp.MustCompile("^\\s*```\\s*mermaid\\s*$")
	reFenceAny   = regexp.MustCompile("^\\s*```")
	reHeader     = regexp.MustCompile(`^(flowchart|graph)\b\s*([A-Za-z]{2})?\s*;?$`)
	reOtherKind  = regexp.MustCompile(`^(sequenceDiagram|classDiagram|stateDiagram(?:-v2)?|erDiagram|gantt|pie|journey|gitGraph|mindmap|timeline|quadrantChart|requirementDiagram|C4Context|sankey-beta|xychart-beta|block-beta)\b`)
	reDirective  = regexp.MustCompile(`^\s*(style|classDef|class|click|linkStyle)\b`)
	reSubgraph   = regexp.MustCompile(`^subgraph\s+(.*)$`)
	reSubgraphID = regexp.MustCompile(`^([A-Za-z_][A-Za-z0-9_-]*)\s*(?:\[\s*"([^"]*)"\s*\]|\["([^"]*)"\])?\s*$`)
	reIdent      = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_-]*$`)
	reArrow      = regexp.MustCompile(`^(-->|-\.->|==>|---|-\.-|===)`)
	reNonASCII   = regexp.MustCompile("[→–‑—‐]")
)

// Validate parses every ```mermaid fence in a threat-model Markdown document.
func Validate(markdown string) Artifact {
	art := Artifact{Version: Version, RendererVersion: RendererVersion, Source: "threat_model.md", Diagrams: []Diagram{}}
	lines := strings.Split(strings.ReplaceAll(markdown, "\r\n", "\n"), "\n")
	idx := 0
	for i := 0; i < len(lines); i++ {
		if !reFenceOpen.MatchString(lines[i]) {
			continue
		}
		start := i + 1
		j := start
		for j < len(lines) && !reFenceAny.MatchString(lines[j]) {
			j++
		}
		body := lines[start:j]
		d := ParseFence(strings.Join(body, "\n"))
		d.Index = idx
		d.FenceLine = i + 1
		art.Diagrams = append(art.Diagrams, d)
		idx++
		i = j
	}
	if len(art.Diagrams) == 0 {
		art.Diagrams = append(art.Diagrams, Diagram{Index: 0, State: StateMissing, Repairs: []Repair{}, Errors: []Error{}})
	}
	return art
}

// ParseFence validates one fence body: repair (recorded) → parse → serialize.
func ParseFence(src string) Diagram {
	d := Diagram{Original: src, Repairs: []Repair{}, Errors: []Error{}}
	lines := strings.Split(strings.TrimRight(src, "\n"), "\n")
	if strings.TrimSpace(src) == "" {
		d.State = StateInvalid
		d.Errors = append(d.Errors, Error{Line: 1, Code: EEmpty, Message: "empty diagram"})
		return d
	}
	// Header.
	first := strings.TrimSpace(stripComment(lines[0]))
	if m := reOtherKind.FindStringSubmatch(first); m != nil {
		d.Kind, d.State = m[1], StateUnsupported
		d.Errors = append(d.Errors, Error{Line: 1, Code: EUnsupportedDiagram, Message: "only flowchart/graph diagrams are supported; " + m[1] + " is rendered as source"})
		return d
	}
	hm := reHeader.FindStringSubmatch(first)
	if hm == nil {
		d.State = StateInvalid
		d.Errors = append(d.Errors, Error{Line: 1, Code: ESyntax, Message: "expected `flowchart <direction>` or `graph <direction>`"})
		return d
	}
	d.Kind, d.Direction = "flowchart", strings.ToUpper(hm[2])
	if d.Direction == "" {
		d.Direction = "TD"
	}

	// Bounded repairs, per line, in a fixed order; every change is recorded.
	repaired := make([]string, len(lines))
	for i, ln := range lines {
		out, reps := repairLine(ln)
		for _, r := range reps {
			r.Line = i + 1
			d.Repairs = append(d.Repairs, r)
		}
		repaired[i] = out
	}

	// Parse.
	st := &Structure{Nodes: []Node{}, Edges: []Edge{}, Boundaries: []Boundary{}}
	nodes := map[string]*Node{}
	var order []string
	var stack []*Boundary
	declare := func(id, label, shape string) {
		if n, ok := nodes[id]; ok {
			if label != "" && (n.Label == n.ID || n.Label == "") {
				n.Label, n.Shape = label, shape
			}
		} else {
			if label == "" {
				label = id
				shape = "plain"
			}
			nodes[id] = &Node{ID: id, Label: label, Shape: shape}
			order = append(order, id)
		}
		if len(stack) > 0 {
			b := stack[len(stack)-1]
			found := false
			for _, x := range b.Nodes {
				if x == id {
					found = true
				}
			}
			if !found {
				b.Nodes = append(b.Nodes, id)
			}
		}
	}
	for i := 1; i < len(repaired); i++ {
		lineNo := i + 1
		raw := stripComment(repaired[i])
		text := strings.TrimSpace(raw)
		if text == "" {
			continue
		}
		for _, stmt := range splitStatements(text) {
			stmt = strings.TrimSpace(stmt)
			if stmt == "" {
				continue
			}
			switch {
			case stmt == "end":
				if len(stack) > 0 {
					st.Boundaries = append(st.Boundaries, *stack[len(stack)-1])
					stack = stack[:len(stack)-1]
				}
			case strings.HasPrefix(stmt, "subgraph"):
				m := reSubgraph.FindStringSubmatch(stmt)
				rest := strings.TrimSpace(m[1])
				sm := reSubgraphID.FindStringSubmatch(rest)
				if sm == nil {
					d.Errors = append(d.Errors, Error{Line: lineNo, Code: ESubgraphID, Message: "subgraph id must be a bare identifier, optionally followed by [\"label\"]: " + rest})
					// keep a placeholder so `end` stays balanced
					stack = append(stack, &Boundary{ID: "?", Label: rest, Nodes: []string{}})
					continue
				}
				label := sm[2]
				if label == "" {
					label = sm[3]
				}
				if label == "" {
					label = sm[1]
				}
				stack = append(stack, &Boundary{ID: sm[1], Label: label, Nodes: []string{}})
			default:
				if err := parseChain(stmt, lineNo, st, declare); err != nil {
					d.Errors = append(d.Errors, *err)
				}
			}
		}
	}
	for len(stack) > 0 { // unterminated subgraphs still count as boundaries
		st.Boundaries = append(st.Boundaries, *stack[len(stack)-1])
		stack = stack[:len(stack)-1]
	}
	for _, id := range order {
		st.Nodes = append(st.Nodes, *nodes[id])
	}
	switch {
	case len(d.Errors) > 0:
		d.State = StateInvalid
		// The structure is partial and never presented as valid — omitted.
	case len(d.Repairs) > 0:
		d.State = StateRepaired
		d.Structure = st
	default:
		d.State = StateValid
		d.Structure = st
	}
	if d.Structure != nil {
		d.Normalized = Serialize(d.Direction, d.Structure)
	}
	return d
}

// repairLine applies the enumerated rules to one line, returning the repaired
// text and the repairs (without line numbers).
func repairLine(ln string) (string, []Repair) {
	var reps []Repair
	orig := ln
	record := func(rule, before, after string) {
		if before != after {
			reps = append(reps, Repair{Rule: rule, Before: strings.TrimSpace(before), After: strings.TrimSpace(after)})
		}
	}
	// 1. Directives are outside the subset: strip (recorded).
	if reDirective.MatchString(ln) {
		record(RStripDirective, orig, "")
		return "", reps
	}
	// 2. `"  ]` gap.
	if strings.Contains(ln, `" ]`) || strings.Contains(ln, `" }`) || strings.Contains(ln, `" )`) {
		before := ln
		ln = regexp.MustCompile(`"\s+([\]\)\}])`).ReplaceAllString(ln, `"$1`)
		record(RQuoteGap, before, ln)
	}
	// 3. Unterminated node bracket after a closed quoted label: `F["x (y)"` → `]`.
	if m := regexp.MustCompile(`^(\s*[A-Za-z_][A-Za-z0-9_-]*)(\[\(|\(\(|\[|\(|\{)"([^"]*)"\s*$`).FindStringSubmatch(ln); m != nil {
		closer := map[string]string{"[(": ")]", "((": "))", "[": "]", "(": ")", "{": "}"}[m[2]]
		before := ln
		ln = m[1] + m[2] + `"` + m[3] + `"` + closer
		record(RCloseLabelQuote, before, ln)
	}
	// 4. Unquoted labels with special characters → quoted (node brackets and
	//    complete |…| edge labels only; a lone `|` is left for the parser to reject).
	{
		before := ln
		ln = regexp.MustCompile(`([A-Za-z_][A-Za-z0-9_-]*)\[([^\]"\[]+)\]`).ReplaceAllStringFunc(ln, func(s string) string {
			m := regexp.MustCompile(`^([A-Za-z_][A-Za-z0-9_-]*)\[([^\]"\[]+)\]$`).FindStringSubmatch(s)
			if m == nil || isSimpleLabel(m[2]) {
				return s
			}
			return m[1] + `["` + m[2] + `"]`
		})
		ln = regexp.MustCompile(`([A-Za-z_][A-Za-z0-9_-]*)\{([^}"{]+)\}`).ReplaceAllStringFunc(ln, func(s string) string {
			m := regexp.MustCompile(`^([A-Za-z_][A-Za-z0-9_-]*)\{([^}"{]+)\}$`).FindStringSubmatch(s)
			if m == nil || isSimpleLabel(m[2]) {
				return s
			}
			return m[1] + `{"` + m[2] + `"}`
		})
		ln = regexp.MustCompile(`\|([^|"\n]+)\|`).ReplaceAllStringFunc(ln, func(s string) string {
			inner := strings.TrimSpace(s[1 : len(s)-1])
			if isSimpleLabel(inner) {
				return s
			}
			return `|"` + inner + `"|`
		})
		record(RQuoteLabel, before, ln)
	}
	// 5. Non-ASCII arrows/dashes inside quoted labels → ASCII.
	if reNonASCII.MatchString(ln) {
		before := ln
		ln = replaceInQuotes(ln, func(s string) string {
			s = strings.ReplaceAll(s, "→", "->")
			s = strings.ReplaceAll(s, "–", "-")
			s = strings.ReplaceAll(s, "—", "-")
			s = strings.ReplaceAll(s, "‑", "-")
			s = strings.ReplaceAll(s, "‐", "-")
			return s
		})
		record(RASCIILabel, before, ln)
	}
	return ln, reps
}

func isSimpleLabel(s string) bool {
	return regexp.MustCompile(`^[A-Za-z0-9_ .-]*$`).MatchString(s) && !strings.ContainsAny(s, "→–‑—")
}

// replaceInQuotes applies f to every "…" segment of the line.
func replaceInQuotes(ln string, f func(string) string) string {
	var b strings.Builder
	in := false
	seg := strings.Builder{}
	for _, r := range ln {
		if r == '"' {
			if in {
				b.WriteString(f(seg.String()))
				seg.Reset()
			}
			in = !in
			b.WriteRune(r)
			continue
		}
		if in {
			seg.WriteRune(r)
		} else {
			b.WriteRune(r)
		}
	}
	if in { // unterminated quote: emit as is
		b.WriteString(seg.String())
	}
	return b.String()
}

// stripComment removes a %% comment that is outside quotes.
func stripComment(ln string) string {
	in := false
	for i := 0; i+1 < len(ln); i++ {
		if ln[i] == '"' {
			in = !in
		}
		if !in && ln[i] == '%' && ln[i+1] == '%' {
			return ln[:i]
		}
	}
	return ln
}

// splitStatements splits on `;` outside quotes.
func splitStatements(s string) []string {
	var out []string
	in := false
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '"' {
			in = !in
		}
		if !in && s[i] == ';' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	return append(out, s[start:])
}

// parseChain parses `node (arrow [|label|] node)*` where node is `id`,
// `id["label"]`, `id("label")`, `id{"label"}`, `id[("label")]`, `id(("label"))`,
// `id>"label"]` (also unquoted simple labels).
func parseChain(stmt string, line int, st *Structure, declare func(id, label, shape string)) *Error {
	rest := stmt
	prev, err := parseNode(&rest, line, declare)
	if err != nil {
		return err
	}
	for {
		rest = strings.TrimSpace(rest)
		if rest == "" {
			return nil
		}
		am := reArrow.FindStringSubmatch(rest)
		if am == nil {
			// `-- label -->` form
			if strings.HasPrefix(rest, "--") || strings.HasPrefix(rest, "-.") || strings.HasPrefix(rest, "==") {
				if m := regexp.MustCompile(`^(--|-\.|==)\s*([^-.=]+?)\s*(-->|-\.->|==>)`).FindStringSubmatch(rest); m != nil {
					rest = strings.TrimSpace(rest[len(m[0]):])
					to, e := parseNode(&rest, line, declare)
					if e != nil {
						return e
					}
					st.Edges = append(st.Edges, Edge{From: prev, To: to, Style: styleOf(m[3]), Label: strings.Trim(strings.TrimSpace(m[2]), `"`)})
					prev = to
					continue
				}
			}
			return &Error{Line: line, Code: ESyntax, Message: "unexpected text after node " + prev + ": " + truncate(rest)}
		}
		style := styleOf(am[1])
		rest = strings.TrimSpace(rest[len(am[1]):])
		label := ""
		if strings.HasPrefix(rest, "|") {
			end := strings.IndexByte(rest[1:], '|')
			if end < 0 {
				return &Error{Line: line, Code: EEdgeLabelUnterminated, Message: "edge label opened with | but never closed: " + truncate(rest)}
			}
			label = strings.Trim(strings.TrimSpace(rest[1:end+1]), `"`)
			rest = strings.TrimSpace(rest[end+2:])
		}
		to, e := parseNode(&rest, line, declare)
		if e != nil {
			return e
		}
		st.Edges = append(st.Edges, Edge{From: prev, To: to, Style: style, Label: label})
		prev = to
	}
}

func styleOf(arrow string) string {
	switch arrow {
	case "-.->", "-.-":
		return "dotted"
	case "==>", "===":
		return "thick"
	}
	return "solid"
}

// parseNode consumes one node token from *rest.
func parseNode(rest *string, line int, declare func(id, label, shape string)) (string, *Error) {
	s := strings.TrimSpace(*rest)
	m := regexp.MustCompile(`^([A-Za-z_][A-Za-z0-9_-]*)`).FindString(s)
	if m == "" {
		return "", &Error{Line: line, Code: ESyntax, Message: "expected a node id: " + truncate(s)}
	}
	id := m
	s = s[len(m):]
	shape, label := "", ""
	openers := []struct{ open, close, shape string }{
		{`[(`, `)]`, "cylinder"}, {`((`, `))`, "circle"}, {`[`, `]`, "rect"}, {`(`, `)`, "round"}, {`{`, `}`, "diamond"}, {`>`, `]`, "flag"},
	}
	for _, o := range openers {
		if strings.HasPrefix(s, o.open) {
			body := s[len(o.open):]
			end := -1
			if strings.HasPrefix(body, `"`) {
				q := strings.IndexByte(body[1:], '"')
				if q < 0 {
					return "", &Error{Line: line, Code: ENodeBracket, Message: "node " + id + ": unterminated quoted label"}
				}
				label = body[1 : q+1]
				after := body[q+2:]
				if !strings.HasPrefix(after, o.close) {
					return "", &Error{Line: line, Code: ENodeBracket, Message: "node " + id + ": label not closed with " + o.close}
				}
				end = q + 2 + len(o.close)
			} else {
				c := strings.Index(body, o.close)
				if c < 0 {
					return "", &Error{Line: line, Code: ENodeBracket, Message: "node " + id + ": missing " + o.close}
				}
				label = strings.TrimSpace(body[:c])
				end = c + len(o.close)
			}
			shape = o.shape
			s = body[end:]
			break
		}
	}
	declare(id, label, shape)
	*rest = s
	return id, nil
}

func truncate(s string) string {
	if len(s) > 60 {
		return s[:60] + "…"
	}
	return s
}

// Serialize renders a structure deterministically: header, boundaries (sorted by
// id, member nodes sorted), remaining nodes sorted, edges sorted. Labels are
// always quoted; comments and directives never appear.
func Serialize(direction string, st *Structure) string {
	if direction == "" {
		direction = "TD"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "flowchart %s\n", direction)
	byID := map[string]Node{}
	for _, n := range st.Nodes {
		byID[n.ID] = n
	}
	inBoundary := map[string]bool{}
	bs := append([]Boundary(nil), st.Boundaries...)
	sort.Slice(bs, func(i, j int) bool { return bs[i].ID < bs[j].ID })
	for _, bd := range bs {
		fmt.Fprintf(&b, "    subgraph %s[%q]\n", bd.ID, bd.Label)
		ns := append([]string(nil), bd.Nodes...)
		sort.Strings(ns)
		for _, id := range ns {
			inBoundary[id] = true
			b.WriteString("        " + nodeDecl(byID[id]) + "\n")
		}
		b.WriteString("    end\n")
	}
	ids := make([]string, 0, len(byID))
	for id := range byID {
		if !inBoundary[id] {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	for _, id := range ids {
		b.WriteString("    " + nodeDecl(byID[id]) + "\n")
	}
	es := append([]Edge(nil), st.Edges...)
	sort.Slice(es, func(i, j int) bool {
		if es[i].From != es[j].From {
			return es[i].From < es[j].From
		}
		if es[i].To != es[j].To {
			return es[i].To < es[j].To
		}
		return es[i].Label < es[j].Label
	})
	for _, e := range es {
		arrow := map[string]string{"solid": "-->", "dotted": "-.->", "thick": "==>"}[e.Style]
		if arrow == "" {
			arrow = "-->"
		}
		if e.Label != "" {
			fmt.Fprintf(&b, "    %s %s|%q| %s\n", e.From, arrow, e.Label, e.To)
		} else {
			fmt.Fprintf(&b, "    %s %s %s\n", e.From, arrow, e.To)
		}
	}
	return b.String()
}

func nodeDecl(n Node) string {
	switch n.Shape {
	case "plain", "":
		if n.Label == "" || n.Label == n.ID {
			return n.ID
		}
		return fmt.Sprintf("%s[%q]", n.ID, n.Label)
	case "round":
		return fmt.Sprintf("%s(%q)", n.ID, n.Label)
	case "diamond":
		return fmt.Sprintf("%s{%q}", n.ID, n.Label)
	case "cylinder":
		return fmt.Sprintf("%s[(%q)]", n.ID, n.Label)
	case "circle":
		return fmt.Sprintf("%s((%q))", n.ID, n.Label)
	case "flag":
		return fmt.Sprintf("%s>%q]", n.ID, n.Label)
	}
	return fmt.Sprintf("%s[%q]", n.ID, n.Label)
}

// WriteArtifact validates <resultsDir>/threat_model.md and writes ArtifactFile
// (atomic). ok=false when threat_model.md does not exist (nothing is written).
func WriteArtifact(resultsDir string) (Artifact, bool, error) {
	b, err := os.ReadFile(filepath.Join(resultsDir, "threat_model.md"))
	if err != nil {
		return Artifact{}, false, nil
	}
	art := Validate(string(b))
	out, err := json.MarshalIndent(art, "", "  ")
	if err != nil {
		return art, true, err
	}
	p := filepath.Join(resultsDir, ArtifactFile)
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, append(out, '\n'), 0o644); err != nil {
		return art, true, err
	}
	return art, true, os.Rename(tmp, p)
}

// Load reads a persisted artifact.
func Load(resultsDir string) (Artifact, error) {
	var art Artifact
	b, err := os.ReadFile(filepath.Join(resultsDir, ArtifactFile))
	if err != nil {
		return art, err
	}
	return art, json.Unmarshal(b, &art)
}

// Summary reduces an artifact to a one-line operator statement.
func (a Artifact) Summary() string {
	if len(a.Diagrams) == 0 {
		return "no diagram"
	}
	var parts []string
	for _, d := range a.Diagrams {
		switch d.State {
		case StateValid:
			parts = append(parts, fmt.Sprintf("diagram %d valid", d.Index+1))
		case StateRepaired:
			parts = append(parts, fmt.Sprintf("diagram %d repaired (%d rule(s))", d.Index+1, len(d.Repairs)))
		case StateInvalid:
			e := d.Errors[0]
			parts = append(parts, fmt.Sprintf("diagram %d invalid (line %d, %s)", d.Index+1, e.Line, e.Code))
		case StateUnsupported:
			parts = append(parts, fmt.Sprintf("diagram %d unsupported (%s)", d.Index+1, d.Kind))
		default:
			parts = append(parts, d.State)
		}
	}
	return strings.Join(parts, "; ")
}
