// Package evidence serves a finding's source excerpt and narrative bound to the
// scanned revision (feature 010, US2). It is read-only and static: it NEVER
// executes target code and NEVER silently substitutes the current working tree
// for a different recorded revision (FR-012, Principle III). Source is returned
// only when the repository on disk is verifiably at the finding's recorded
// commit (HEAD matches and the tree was not dirty at scan time); otherwise the
// excerpt is marked unavailable with a reason, and the finding's other evidence
// (narrative, citations) is still returned.
package evidence

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// Reasons for an unavailable source excerpt.
const (
	ReasonOK                  = ""
	ReasonNoLocation          = "no-location"
	ReasonRevisionUnavailable = "revision-unavailable" // repo not at the recorded commit
	ReasonSourceUnavailable   = "source-unavailable"   // repo/file not readable
)

// Line is one numbered source line in an excerpt.
type Line struct {
	Number    int    `json:"number"`
	Text      string `json:"text"`
	Highlight bool   `json:"highlight"` // the finding's own line(s)
}

// Source is the revision-bound excerpt (or an explicit unavailable state).
type Source struct {
	Available bool   `json:"available"`
	Reason    string `json:"reason"`
	Path      string `json:"path"`
	Revision  string `json:"revision"`
	StartLine int    `json:"start_line"`
	EndLine   int    `json:"end_line"`
	FocusLine int    `json:"focus_line"`
	Lines     []Line `json:"lines"`
}

// Narrative is the finding's reviewable explanation (FR-013), sourced from the
// verification record where present and the finding fields otherwise. Absent
// fields stay empty rather than invented.
type Narrative struct {
	EntryPoint       string `json:"entry_point"`
	AttackerControl  string `json:"attacker_control"`
	DataFlow         string `json:"data_flow"`
	Preconditions    string `json:"preconditions"`
	DefensesReviewed string `json:"defenses_reviewed"`
	SecurityImpact   string `json:"security_impact"`
	Rationale        string `json:"rationale"`
	Remediation      string `json:"remediation"`
}

// View is the evidence bundle for one occurrence.
type View struct {
	Location  string    `json:"location"`
	Source    Source    `json:"source"`
	Narrative Narrative `json:"narrative"`
}

// Meta carries the recorded scan provenance needed to bind source to a revision.
type Meta struct {
	Repo   string
	Commit string // git_commit recorded at scan time
	Dirty  bool   // git_dirty recorded at scan time
}

const defaultWindow = 12 // lines of context on each side of the focus line

// Build assembles the evidence view for a finding. raw is the finding's
// findings.json map; meta is its scan's recorded provenance.
func Build(meta Meta, raw map[string]any) View {
	loc := str(raw["location"])
	return View{
		Location:  loc,
		Source:    buildSource(meta, loc),
		Narrative: buildNarrative(raw),
	}
}

func buildSource(meta Meta, location string) Source {
	file, line := parseLocation(location)
	if file == "" {
		return Source{Available: false, Reason: ReasonNoLocation, Revision: meta.Commit}
	}
	// Bind to the recorded revision: only read the repo when it is verifiably at
	// that commit (HEAD matches and the scan tree was not dirty). Otherwise refuse
	// to read — the working tree is a DIFFERENT revision and must not be
	// substituted (FR-012).
	if meta.Repo == "" || meta.Commit == "" || meta.Dirty || !repoAtCommit(meta.Repo, meta.Commit) {
		return Source{Available: false, Reason: ReasonRevisionUnavailable, Path: file, Revision: meta.Commit}
	}
	abs, ok := containedPath(meta.Repo, file)
	if !ok {
		return Source{Available: false, Reason: ReasonSourceUnavailable, Path: file, Revision: meta.Commit}
	}
	b, err := os.ReadFile(abs)
	if err != nil {
		return Source{Available: false, Reason: ReasonSourceUnavailable, Path: file, Revision: meta.Commit}
	}
	all := strings.Split(string(b), "\n")
	start := line - defaultWindow
	if start < 1 {
		start = 1
	}
	end := line + defaultWindow
	if end > len(all) {
		end = len(all)
	}
	var lines []Line
	for n := start; n <= end; n++ {
		lines = append(lines, Line{Number: n, Text: all[n-1], Highlight: n == line})
	}
	return Source{
		Available: true, Reason: ReasonOK, Path: file, Revision: meta.Commit,
		StartLine: start, EndLine: end, FocusLine: line, Lines: lines,
	}
}

func buildNarrative(raw map[string]any) Narrative {
	n := Narrative{
		EntryPoint:  str(raw["entry_point"]),
		DataFlow:    str(raw["data_flow"]),
		Remediation: str(raw["fix"]),
		Rationale:   str(raw["assessment_reason"]),
	}
	// The verification record (when present) carries the reviewed narrative and
	// takes precedence over the raw finding fields.
	if vr, ok := raw["verification_record"].(map[string]any); ok {
		n.EntryPoint = orStr(str(vr["entry_point"]), n.EntryPoint)
		n.AttackerControl = str(vr["attacker_control"])
		n.Preconditions = str(vr["preconditions"])
		n.DefensesReviewed = str(vr["defenses_reviewed"])
		n.SecurityImpact = str(vr["security_impact"])
		n.Rationale = orStr(str(vr["rationale"]), n.Rationale)
	}
	return n
}

var locRE = regexp.MustCompile(`^(.*?):(\d+)`)

// parseLocation splits "path/to/file.go:123" (or ":123-140", ":123:5") into a
// path and its focus line. Returns "",0 when no file:line is present.
func parseLocation(loc string) (string, int) {
	loc = strings.TrimSpace(loc)
	if loc == "" {
		return "", 0
	}
	m := locRE.FindStringSubmatch(loc)
	if m == nil {
		return "", 0
	}
	n, _ := strconv.Atoi(m[2])
	return strings.TrimSpace(m[1]), n
}

// containedPath resolves file within repo and rejects any escape (Principle III
// path containment). file may be repo-relative or an absolute path inside repo.
func containedPath(repo, file string) (string, bool) {
	rabs, err := filepath.Abs(repo)
	if err != nil {
		return "", false
	}
	cand := file
	if !filepath.IsAbs(cand) {
		cand = filepath.Join(rabs, file)
	}
	cand = filepath.Clean(cand)
	if cand != rabs && !strings.HasPrefix(cand, rabs+string(os.PathSeparator)) {
		return "", false
	}
	return cand, true
}

// repoAtCommit reports whether the git repository at repo currently points at
// commit. It reads .git metadata only — no process is executed. A short recorded
// commit is matched as a prefix of the resolved HEAD.
func repoAtCommit(repo, commit string) bool {
	head := repoHead(repo)
	if head == "" || commit == "" {
		return false
	}
	return head == commit || strings.HasPrefix(head, commit) || strings.HasPrefix(commit, head)
}

// repoHead resolves the current commit sha from .git without executing git.
func repoHead(repo string) string {
	gitDir := filepath.Join(repo, ".git")
	b, err := os.ReadFile(filepath.Join(gitDir, "HEAD"))
	if err != nil {
		return ""
	}
	head := strings.TrimSpace(string(b))
	if !strings.HasPrefix(head, "ref:") {
		return head // detached HEAD: the sha directly
	}
	ref := strings.TrimSpace(strings.TrimPrefix(head, "ref:"))
	if rb, err := os.ReadFile(filepath.Join(gitDir, filepath.FromSlash(ref))); err == nil {
		return strings.TrimSpace(string(rb))
	}
	// packed-refs fallback.
	if pb, err := os.ReadFile(filepath.Join(gitDir, "packed-refs")); err == nil {
		for _, ln := range strings.Split(string(pb), "\n") {
			ln = strings.TrimSpace(ln)
			if ln == "" || strings.HasPrefix(ln, "#") || strings.HasPrefix(ln, "^") {
				continue
			}
			parts := strings.Fields(ln)
			if len(parts) == 2 && parts[1] == ref {
				return parts[0]
			}
		}
	}
	return ""
}

func str(v any) string { s, _ := v.(string); return s }

func orStr(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	return b
}
