// Remediation groups (feature 015, FR-020, research R5, contracts C-B9..C-B12).
//
// Supported, non-duplicate findings that share a SOURCE ANCHOR (file + enclosing
// function + sink statement), a family and a compatible fix form one ESTABLISHED
// group; same family + same file + compatible fix with a different function (or the
// same function with a different sink statement) is only SUGGESTED. A shared CWE,
// a similar title, an overlapping range or a shared route alone never groups, and
// different families on one endpoint always stay separate. Grouping reads source
// through the confined reader and never rewrites a finding, a decision or a review
// record: it writes one additive record, remediation_groups.json.
package consolidate

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"vhlocal/internal/recognize"
	"vhlocal/internal/source"
)

const (
	GroupsFile    = "remediation_groups.json"
	GroupsVersion = 1

	GroupEstablished = "established"
	GroupSuggested   = "suggested"
	RolePrimary      = "primary"
	RoleOccurrence   = "occurrence"

	// Fix compatibility: Jaccard over normalized fix tokens (R5).
	fixJaccardMin = 0.6
	// Precondition compatibility for suggested groups on one function.
	precondJaccardMin = 0.5
	// A sink line this close to a cited range (that contains no sink itself) is the
	// statement the finding is about.
	sinkNearLines = 3
)

// GroupAnchor is the resolved sink anchor of a member (data-model "anchor").
type GroupAnchor struct {
	File      string `json:"file"`
	Function  string `json:"function"`
	Statement string `json:"statement"`
	Line      int    `json:"line"`
}

// GroupMember is one supported finding inside a group.
type GroupMember struct {
	FindingID  string `json:"finding_id"`
	StableID   string `json:"stable_id"`
	Role       string `json:"role"` // primary | occurrence
	EntryPoint string `json:"entry_point"`
}

// Group is one remediation group.
type Group struct {
	ID                  string        `json:"id"`
	Family              string        `json:"family"`
	CanonicalName       string        `json:"canonical_name,omitempty"`
	Anchor              GroupAnchor   `json:"anchor"`
	Status              string        `json:"status"` // established | suggested
	Members             []GroupMember `json:"members"`
	Fix                 string        `json:"fix,omitempty"`
	Preconditions       string        `json:"preconditions,omitempty"`
	DecisionStatus      string        `json:"decision_status"` // all-decided | mixed | undecided
	MembersChangedSince bool          `json:"members_changed_since"`
}

// Groups is remediation_groups.json.
type Groups struct {
	Version      int     `json:"version"`
	Groups       []Group `json:"groups"`
	RawSupported int     `json:"raw_supported"`
	Grouped      int     `json:"grouped"`
}

// anchored is a finding with its resolved anchor and normalized comparison keys.
type anchored struct {
	f       Finding
	family  string
	anchor  GroupAnchor
	found   bool // enclosing function resolved
	fixTok  map[string]bool
	preTok  map[string]bool
	order   int
	groupIx int
}

var reLocRange = regexp.MustCompile(`^\s*([^\s:]+):(\d+)(?:\s*[-–]\s*(\d+))?`)

// parseLocationRange splits "file:start[-end]" (first cited range wins).
func parseLocationRange(loc string) (file string, start, end int, ok bool) {
	m := reLocRange.FindStringSubmatch(strings.TrimSpace(loc))
	if m == nil {
		return "", 0, 0, false
	}
	start, _ = strconv.Atoi(m[2])
	end = start
	if m[3] != "" {
		end, _ = strconv.Atoi(m[3])
	}
	if end < start {
		start, end = end, start
	}
	return filepath.ToSlash(filepath.Clean(m[1])), start, end, true
}

// familyOf is the grouping family: the normalized CWE family, else the normalized
// CWE, else the raw CWE (upper-cased). Distinct families never group.
func familyOf(f Finding) string {
	for _, c := range []string{f.CWEFamily, f.NormalizedCWE, f.CWE} {
		if s := strings.TrimSpace(c); s != "" {
			return strings.ToUpper(s)
		}
	}
	return "UNCLASSIFIED"
}

var reWord = regexp.MustCompile(`[a-z0-9_]+`)

var stopTokens = map[string]bool{
	"the": true, "and": true, "with": true, "for": true, "that": true, "this": true, "from": true, "into": true,
	"use": true, "using": true, "should": true, "must": true, "all": true, "any": true, "are": true, "not": true,
	"before": true, "after": true, "when": true, "then": true, "than": true, "them": true, "its": true, "via": true,
	"can": true, "only": true, "also": true, "each": true, "such": true, "which": true, "where": true, "will": true,
	"parameter": true, "parameters": true, "value": true, "values": true, "input": true, "user": true, "request": true,
}

// tokens normalizes prose into a comparable token set (lower-case words ≥ 3 chars,
// stop words removed, trailing plural 's' folded).
func tokens(s string) map[string]bool {
	out := map[string]bool{}
	for _, w := range reWord.FindAllString(strings.ToLower(s), -1) {
		if len(w) < 3 || stopTokens[w] {
			continue
		}
		if len(w) > 4 && strings.HasSuffix(w, "s") {
			w = w[:len(w)-1]
		}
		out[w] = true
	}
	return out
}

func jaccard(a, b map[string]bool) float64 {
	if len(a) == 0 && len(b) == 0 {
		return 1
	}
	inter, union := 0, len(a)
	for k := range b {
		if a[k] {
			inter++
		} else {
			union++
		}
	}
	if union == 0 {
		return 0
	}
	return float64(inter) / float64(union)
}

// fixCompat: +1 compatible, -1 incompatible, 0 unknown (a side has no fix text).
func fixCompat(a, b *anchored) int {
	if len(a.fixTok) == 0 || len(b.fixTok) == 0 {
		return 0
	}
	if jaccard(a.fixTok, b.fixTok) >= fixJaccardMin {
		return 1
	}
	return -1
}

// precondCompat: preconditions agree when both are absent or their token sets overlap.
func precondCompat(a, b *anchored) bool {
	if len(a.preTok) == 0 || len(b.preTok) == 0 {
		return len(a.preTok) == len(b.preTok)
	}
	return jaccard(a.preTok, b.preTok) >= precondJaccardMin
}

func preconditionsOf(f Finding) string {
	switch v := f.VerificationRecord["preconditions"].(type) {
	case string:
		return v
	case []any:
		parts := make([]string, 0, len(v))
		for _, p := range v {
			parts = append(parts, fmt.Sprint(p))
		}
		return strings.Join(parts, " ")
	}
	return ""
}

// resolveAnchor locates the sink statement the finding is about: the contiguous run
// of family sink-pattern lines inside the enclosing function that intersects the
// cited range (or lies within sinkNearLines of it); without a sink pattern hit the
// last non-blank cited line is the statement. Reads are confined to the repo.
func resolveAnchor(f Finding, repo string) (GroupAnchor, bool) {
	file, start, end, ok := parseLocationRange(f.Location)
	if !ok {
		return GroupAnchor{File: strings.TrimSpace(f.Location), Statement: "unparsed location"}, false
	}
	a := GroupAnchor{File: file, Line: start}
	var src []byte
	if repo != "" {
		src, _ = source.ReadFile(repo, file)
	}
	if src == nil {
		a.Statement = fmt.Sprintf("lines %d-%d (source unavailable)", start, end)
		return a, false
	}
	lines := strings.Split(string(src), "\n")
	clamp := func(n int) int {
		if n < 1 {
			return 1
		}
		if n > len(lines) {
			return len(lines)
		}
		return n
	}
	start, end = clamp(start), clamp(end)
	fnStart, fnEnd, found := start, end, false
	lang, hasLang := recognize.LanguageFor(file)
	scopeAt := func(line int) (string, int, int, bool) {
		if !hasLang {
			return "", 0, 0, false
		}
		sc := recognize.EnclosingScope(lang, src, line)
		if !sc.Found {
			return "", 0, 0, false
		}
		name := strings.Join(sc.Owner, ".")
		if name == "" {
			name = fmt.Sprintf("@%d", sc.Start) // unnamed span: identified by its start line
		}
		return name, clamp(sc.Start), clamp(sc.End), true
	}
	if name, s, e, ok := scopeAt(start); ok {
		a.Function, fnStart, fnEnd, found = name, s, e, true
	}
	if !found {
		// No resolvable function: search a bounded window around the citation.
		fnStart, fnEnd = clamp(start-sinkNearLines), clamp(end+sinkNearLines)
	}
	cwe := f.NormalizedCWE
	if cwe == "" {
		cwe = f.CWE
	}
	pats, _ := sinkPatterns(cwe)
	var res []*regexp.Regexp
	for _, p := range pats {
		if re, err := regexp.Compile(p); err == nil {
			res = append(res, re)
		}
	}
	var sinkLines []int
	for ln := fnStart; ln <= fnEnd; ln++ {
		for _, re := range res {
			if re.MatchString(lines[ln-1]) {
				sinkLines = append(sinkLines, ln)
				break
			}
		}
	}
	pick := 0
	for _, ln := range sinkLines {
		if ln >= start && ln <= end {
			pick = ln
			break
		}
	}
	if pick == 0 {
		best := sinkNearLines + 1
		for _, ln := range sinkLines {
			d := 0
			if ln < start {
				d = start - ln
			} else if ln > end {
				d = ln - end
			}
			if d < best {
				best, pick = d, ln
			}
		}
	}
	if pick != 0 {
		isSink := map[int]bool{}
		for _, ln := range sinkLines {
			isSink[ln] = true
		}
		lo, hi := pick, pick
		for isSink[lo-1] {
			lo--
		}
		for isSink[hi+1] {
			hi++
		}
		// A citation just outside its handler (a blank line after the return) still
		// belongs to the function that owns the sink statement.
		if !found {
			if name, _, _, ok := scopeAt(lo); ok {
				a.Function, found = name, true
			}
		}
		var stmt []string
		for ln := lo; ln <= hi; ln++ {
			stmt = append(stmt, strings.Join(strings.Fields(lines[ln-1]), " "))
		}
		a.Line, a.Statement = lo, strings.Join(stmt, " ⏎ ")
		return a, found
	}
	for ln := end; ln >= start; ln-- {
		if s := strings.Join(strings.Fields(lines[ln-1]), " "); s != "" {
			a.Line, a.Statement = ln, s
			return a, found
		}
	}
	a.Statement = fmt.Sprintf("lines %d-%d (blank)", start, end)
	return a, found
}

func anchorKey(a GroupAnchor) string { return a.File + "|" + a.Function + "|" + a.Statement }

func groupID(family string, a GroupAnchor) string {
	sum := sha256.Sum256([]byte(family + "|" + anchorKey(a)))
	return "RG-" + hex.EncodeToString(sum[:])[:16]
}

func prepare(findings []Finding, repo string, supportedOnly bool) []*anchored {
	var out []*anchored
	for i, f := range findings {
		if supportedOnly && ClassifyFinding(f) != ClassSupported {
			continue
		}
		a, found := resolveAnchor(f, repo)
		out = append(out, &anchored{f: f, family: familyOf(f), anchor: a, found: found,
			fixTok: tokens(f.Fix), preTok: tokens(preconditionsOf(f)), order: i, groupIx: -1})
	}
	return out
}

// establishedWith reports whether b belongs to a's established group.
func establishedWith(a, b *anchored) bool {
	if a.family != b.family || anchorKey(a.anchor) != anchorKey(b.anchor) {
		return false
	}
	switch fixCompat(a, b) {
	case 1:
		return true
	case -1:
		return false
	}
	return strings.EqualFold(a.f.CanonicalName, b.f.CanonicalName)
}

// suggestedWith reports whether two established clusters (represented by members)
// may be joined as a suggested group: same family, same file, and either the same
// resolved function with different sink statements (compatible fix or same
// canonical name, agreeing preconditions) or a different function with explicitly
// compatible fixes. An unresolved function never supports a suggestion.
func suggestedWith(a, b *anchored) bool {
	if a.family != b.family || a.anchor.File != b.anchor.File || !a.found || !b.found {
		return false
	}
	fc := fixCompat(a, b)
	if a.anchor.Function == b.anchor.Function {
		if !precondCompat(a, b) {
			return false
		}
		return fc == 1 || (fc == 0 && strings.EqualFold(a.f.CanonicalName, b.f.CanonicalName))
	}
	return fc == 1
}

// BuildGroups groups the supported, non-duplicate findings (C-B9/C-B10). Order is
// the findings order, so the record is deterministic for a given findings.json.
func BuildGroups(findings []Finding, repo string) Groups {
	items := prepare(findings, repo, true)
	out := Groups{Version: GroupsVersion, Groups: []Group{}, RawSupported: len(items)}
	// Pass 1: established clusters (union by anchor + family + fix).
	var clusters [][]*anchored
	for _, it := range items {
		placed := false
		for ci, c := range clusters {
			if establishedWith(c[0], it) {
				clusters[ci] = append(c, it)
				it.groupIx = ci
				placed = true
				break
			}
		}
		if !placed {
			it.groupIx = len(clusters)
			clusters = append(clusters, []*anchored{it})
		}
	}
	// Pass 2: suggested merges between clusters (pairwise on representatives).
	status := make([]string, len(clusters))
	for i := range status {
		status[i] = GroupEstablished
	}
	parent := make([]int, len(clusters))
	for i := range parent {
		parent[i] = i
	}
	find := func(i int) int {
		for parent[i] != i {
			parent[i] = parent[parent[i]]
			i = parent[i]
		}
		return i
	}
	for i := 0; i < len(clusters); i++ {
		for j := i + 1; j < len(clusters); j++ {
			if find(i) == find(j) {
				continue
			}
			if suggestedWith(clusters[i][0], clusters[j][0]) {
				ri, rj := find(i), find(j)
				if ri < rj {
					parent[rj] = ri
				} else {
					parent[ri] = rj
				}
				status[find(i)] = GroupSuggested
			}
		}
	}
	merged := map[int][]*anchored{}
	var roots []int
	for i, c := range clusters {
		r := find(i)
		if _, ok := merged[r]; !ok {
			roots = append(roots, r)
		}
		merged[r] = append(merged[r], c...)
	}
	sort.Ints(roots)
	for _, r := range roots {
		members := merged[r]
		sort.SliceStable(members, func(i, j int) bool { return members[i].order < members[j].order })
		first := members[0]
		g := Group{ID: groupID(first.family, first.anchor), Family: strings.ToLower(first.family), CanonicalName: first.f.CanonicalName,
			Anchor: first.anchor, Status: status[r], Members: []GroupMember{}, Fix: first.f.Fix, Preconditions: preconditionsOf(first.f),
			DecisionStatus: "undecided"}
		for i, m := range members {
			role := RoleOccurrence
			if i == 0 {
				role = RolePrimary
			}
			if g.Fix == "" && m.f.Fix != "" {
				g.Fix = m.f.Fix
			}
			g.Members = append(g.Members, GroupMember{FindingID: m.f.ID, StableID: m.f.StableIdentity, Role: role, EntryPoint: strings.TrimSpace(m.f.EntryPoint)})
		}
		out.Groups = append(out.Groups, g)
	}
	out.Grouped = len(out.Groups)
	return out
}

// GroupKeys reports the ESTABLISHED-rule group id for every finding (supported or
// not) — the pre-verification "likely_group" hint on the candidate manifest. It is
// reporting only: no candidate is skipped or merged because of it.
func GroupKeys(findings []Finding, repo string) map[string]string {
	items := prepare(findings, repo, false)
	out := map[string]string{}
	var clusters [][]*anchored
	for _, it := range items {
		placed := false
		for ci, c := range clusters {
			if establishedWith(c[0], it) {
				clusters[ci] = append(c, it)
				placed = true
				break
			}
		}
		if !placed {
			clusters = append(clusters, []*anchored{it})
		}
	}
	for _, c := range clusters {
		id := groupID(c[0].family, c[0].anchor)
		for _, m := range c {
			out[m.f.ID] = id
		}
	}
	return out
}

// WriteGroups persists remediation_groups.json (pretty, stable key order).
func WriteGroups(dir string, g Groups) error {
	if g.Groups == nil {
		g.Groups = []Group{}
	}
	b, err := json.MarshalIndent(g, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, GroupsFile), append(b, '\n'), 0o644)
}

// LoadGroups reads the record; ok is false when absent or unreadable.
func LoadGroups(dir string) (Groups, bool) {
	b, err := os.ReadFile(filepath.Join(dir, GroupsFile))
	if err != nil {
		return Groups{}, false
	}
	var g Groups
	if json.Unmarshal(b, &g) != nil || g.Version != GroupsVersion {
		return Groups{}, false
	}
	return g, true
}

// AnchorOf resolves a finding's sink anchor (file + enclosing function + sink
// statement) — the identity rule shared by remediation groups and citation
// amendments (feature 015, FR-026): the same anchor keeps a candidate's identity.
func AnchorOf(f Finding, repo string) (GroupAnchor, bool) { return resolveAnchor(f, repo) }
