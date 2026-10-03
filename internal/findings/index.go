package findings

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"vhlocal/internal/reports"
)

// Row is one finding occurrence projected for the queue (feature 010, US1). It
// carries only display/filter fields; full evidence is fetched per-occurrence.
type Row struct {
	Occurrence   string  `json:"occurrence"`  // scan id + stable identity
	StableID     string  `json:"stable_id"`   // cross-scan identity ("" if none)
	Application  string  `json:"application"` // application name
	Slug         string  `json:"slug"`        // application slug
	Repo         string  `json:"repo"`        // repository path
	ScanID       string  `json:"scan_id"`     // report directory name
	Revision     string  `json:"revision"`    // scanned git commit where recorded
	Title        string  `json:"title"`
	Severity     string  `json:"severity"`
	SeverityRank int     `json:"severity_rank"` // lower = worse (consolidate convention)
	CWE          string  `json:"cwe"`
	Location     string  `json:"location"`
	Evidence     string  `json:"evidence"`     // supported | rejected | unresolved | unknown
	Reproduction string  `json:"reproduction"` // see reproState
	Lifecycle    string  `json:"lifecycle"`    // new | recurring | regressed | "" (unknown/no baseline)
	Review       string  `json:"review"`       // head human disposition (default needs-review)
	Created      float64 `json:"created"`      // scan mtime (sort tiebreak)
}

// Query filters and sorts the queue. Empty fields do not filter.
type Query struct {
	Application string   // slug
	Scan        string   // scan id
	Severity    string   // matched case-insensitively against Row.Severity
	SeverityIn  []string // matches if Row.Severity is any of these (case-insensitive); used for Critical/High queues
	Evidence    string   // supported|rejected|unresolved|unknown
	Review      string   // needs-review|investigating|accepted-risk|dismissed|resolved
	Path        string   // substring of Location
	Status      string   // lifecycle: new|recurring|regressed
	Q           string   // free text over title/location/cwe
	Sort        string   // severity|created|application|location (default severity)
	Dir         string   // asc|desc (default desc)
}

// Result wraps the queue so a filtered-empty result is distinguishable from an
// application/history with no findings at all (FR-007).
type Result struct {
	Rows          []Row `json:"rows"`
	Total         int   `json:"total"`          // rows after filtering
	Indexed       int   `json:"indexed"`        // occurrences before filtering
	FilteredEmpty bool  `json:"filtered_empty"` // Indexed>0 but Total==0
	NoFindings    bool  `json:"no_findings"`    // Indexed==0
}

// reviewLookup returns the head human disposition for a stable id (defaulting to
// "needs-review"). It is injected so the index package need not import the review
// store (avoids a cycle) and stays testable in isolation.
type reviewLookup func(stableID string) string

// Index builds the full occurrence list from every report on disk. A ledger is
// never consulted, so findings from ledger-disabled scans are included (FR-001).
// disp may be nil (all rows default to "needs-review").
func Index(reportsDir string, disp reviewLookup, extraDirs ...string) []Row {
	if disp == nil {
		disp = func(string) string { return "needs-review" }
	}
	idx, _ := reports.Index(reportsDir, extraDirs...)
	var rows []Row
	for _, r := range idx {
		doc := loadDoc(r.Path)
		if doc == nil {
			continue
		}
		rev := doc.revision
		for i, f := range doc.findings {
			sid := StableID(f)
			rows = append(rows, Row{
				Occurrence:   OccurrenceID(r.ID, f, i),
				StableID:     sid,
				Application:  orStr(r.Name, r.Slug),
				Slug:         r.Slug,
				Repo:         r.Repo,
				ScanID:       r.ID,
				Revision:     rev,
				Title:        str(f["title"]),
				Severity:     orStr(str(f["severity"]), "Unrated"),
				SeverityRank: rank(f),
				CWE:          orStr(str(f["normalized_cwe"]), str(f["cwe"])),
				Location:     str(f["location"]),
				Evidence:     evidenceAssessment(f),
				Reproduction: reproState(f),
				Lifecycle:    normalizeLifecycle(str(f["finding_lifecycle"])),
				Review:       dispDefault(disp(sid), sid),
				Created:      r.Created,
			})
		}
	}
	return rows
}

// Search applies a Query to the full index and returns a wrapped Result.
func Search(reportsDir string, q Query, disp reviewLookup, extraDirs ...string) Result {
	all := Index(reportsDir, disp, extraDirs...)
	res := Result{Indexed: len(all)}
	out := all[:0:0]
	for _, row := range all {
		if !q.match(row) {
			continue
		}
		out = append(out, row)
	}
	sortRows(out, q.Sort, q.Dir)
	res.Rows = out
	res.Total = len(out)
	res.NoFindings = res.Indexed == 0
	res.FilteredEmpty = res.Indexed > 0 && res.Total == 0
	if res.Rows == nil {
		res.Rows = []Row{}
	}
	return res
}

func (q Query) match(r Row) bool {
	if q.Application != "" && r.Slug != q.Application {
		return false
	}
	if q.Scan != "" && r.ScanID != q.Scan {
		return false
	}
	if q.Severity != "" && !strings.EqualFold(r.Severity, q.Severity) {
		return false
	}
	if len(q.SeverityIn) > 0 {
		ok := false
		for _, s := range q.SeverityIn {
			if strings.EqualFold(r.Severity, s) {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	if q.Evidence != "" && r.Evidence != q.Evidence {
		return false
	}
	if q.Review != "" && r.Review != q.Review {
		return false
	}
	if q.Status != "" && r.Lifecycle != q.Status {
		return false
	}
	if q.Path != "" && !strings.Contains(strings.ToLower(r.Location), strings.ToLower(q.Path)) {
		return false
	}
	if q.Q != "" {
		needle := strings.ToLower(q.Q)
		hay := strings.ToLower(r.Title + " " + r.Location + " " + r.CWE)
		if !strings.Contains(hay, needle) {
			return false
		}
	}
	return true
}

func sortRows(rows []Row, key, dir string) {
	desc := dir != "asc" // default desc
	less := func(i, j int) bool {
		a, b := rows[i], rows[j]
		switch key {
		case "created":
			if a.Created != b.Created {
				return a.Created < b.Created
			}
		case "application":
			if !strings.EqualFold(a.Application, b.Application) {
				return strings.ToLower(a.Application) < strings.ToLower(b.Application)
			}
		case "location":
			if a.Location != b.Location {
				return a.Location < b.Location
			}
		default: // severity — lower rank is worse; "worst first" under desc
			if a.SeverityRank != b.SeverityRank {
				// invert so a smaller rank (worse) sorts as "greater"
				return a.SeverityRank > b.SeverityRank
			}
		}
		// stable tiebreak: newest, then occurrence id
		if a.Created != b.Created {
			return a.Created < b.Created
		}
		return a.Occurrence < b.Occurrence
	}
	sort.SliceStable(rows, func(i, j int) bool {
		if desc {
			return less(j, i)
		}
		return less(i, j)
	})
}

// Detail returns one occurrence's queue row plus its raw findings.json map (the
// full evidence the detail/evidence views render), or ok=false when the
// occurrence is not found (FR-010 — the caller renders a useful missing state).
func Detail(reportsDir, occ string, disp reviewLookup, extraDirs ...string) (Row, map[string]any, bool) {
	if disp == nil {
		disp = func(string) string { return "needs-review" }
	}
	idx, _ := reports.Index(reportsDir, extraDirs...)
	for _, r := range idx {
		doc := loadDoc(r.Path)
		if doc == nil {
			continue
		}
		for i, f := range doc.findings {
			if OccurrenceID(r.ID, f, i) != occ {
				continue
			}
			sid := StableID(f)
			row := Row{
				Occurrence: occ, StableID: sid,
				Application: orStr(r.Name, r.Slug), Slug: r.Slug, Repo: r.Repo,
				ScanID: r.ID, Revision: doc.revision,
				Title: str(f["title"]), Severity: orStr(str(f["severity"]), "Unrated"),
				SeverityRank: rank(f), CWE: orStr(str(f["normalized_cwe"]), str(f["cwe"])),
				Location: str(f["location"]), Evidence: evidenceAssessment(f),
				Reproduction: reproState(f), Lifecycle: str(f["finding_lifecycle"]),
				Review: dispDefault(disp(sid), sid), Created: r.Created,
			}
			return row, f, true
		}
	}
	return Row{}, nil, false
}

// doc is the minimal projection of findings.json this package reads.
type doc struct {
	findings []map[string]any
	revision string
}

func loadDoc(dir string) *doc {
	b, err := os.ReadFile(filepath.Join(dir, "findings.json"))
	if err != nil {
		return nil
	}
	var raw struct {
		Findings []map[string]any `json:"findings"`
	}
	if json.Unmarshal(b, &raw) != nil {
		return nil
	}
	d := &doc{findings: raw.Findings}
	// Scanned revision is recorded in scan_meta.json (git_commit), where present.
	if mb, err := os.ReadFile(filepath.Join(dir, "scan_meta.json")); err == nil {
		var meta map[string]any
		if json.Unmarshal(mb, &meta) == nil {
			d.revision = str(meta["git_commit"])
		}
	}
	return d
}

// evidenceAssessment maps a finding to one of supported|rejected|unresolved|unknown
// (FR-016). It prefers the engine's verification_status, falls back to the
// deterministic assessment, and reports unknown when neither is present — never
// inventing certainty (Principle I, FR-017).
func evidenceAssessment(f map[string]any) string {
	switch strings.ToLower(str(f["verification_status"])) {
	case "supported":
		return "supported"
	case "rejected", "refuted":
		return "rejected"
	case "unresolved":
		return "unresolved"
	}
	switch strings.ToLower(str(f["assessment"])) {
	case "supported":
		return "supported"
	case "unresolved":
		return "unresolved"
	}
	return "unknown"
}

// reproState maps a finding to one of the five reproduction states (FR-016),
// without asserting execution that did not happen (Principle I): a failed test is
// "attempted-failed", authored-but-unrun code is "authored", and only a passed
// test is "reproduced".
func reproState(f map[string]any) string {
	switch strings.ToLower(str(f["test_status"])) {
	case "passed":
		return "reproduced"
	case "failed":
		return "attempted-failed"
	}
	switch strings.ToLower(str(f["poc_status"])) {
	case "authored":
		return "authored-not-executed"
	case "deferred":
		return "deferred"
	}
	return "not-requested"
}

// normalizeLifecycle maps the engine's cross-run labels onto the workspace
// vocabulary new | recurring | regressed (empty when no comparison was possible).
// "reappeared" is the engine's supersede-form of regressed; "persisting" of recurring.
func normalizeLifecycle(v string) string {
	switch strings.ToLower(v) {
	case "new":
		return "new"
	case "persisting", "recurring":
		return "recurring"
	case "regressed", "reappeared":
		return "regressed"
	}
	return ""
}

func rank(f map[string]any) int {
	switch n := f["severity_rank"].(type) {
	case float64:
		return int(n)
	case int:
		return n
	}
	return 7 // consolidate.UnknownRank
}

func dispDefault(d, sid string) string {
	if d == "" {
		return "needs-review"
	}
	return d
}

func str(v any) string {
	s, _ := v.(string)
	return s
}

func orStr(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	return b
}
