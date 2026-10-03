// Package membank is the per-target vulnerability ledger: cross-run memory of
// findings aligned to the analyzed application. Deterministic, keyed by stable
// identifiers, idempotent by run id. Mirrors the Python membank.py.
package membank

import (
	"crypto/sha1"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"vhlocal/internal/config"
	"vhlocal/internal/consolidate"
)

// Slug is the stable per-target identifier: "<basename>-<sha1(resolved)[:8]>".
func Slug(target string) string {
	abs, err := filepath.Abs(target)
	if err != nil {
		abs = target
	}
	sum := sha1.Sum([]byte(abs))
	return filepath.Base(abs) + "-" + fmt.Sprintf("%x", sum)[:8]
}

func ledgerPath(slug string) string { return filepath.Join(config.LedgerDir(), slug+".json") }

// Stamp records when/where a finding was seen.
type Stamp struct {
	Run   string  `json:"run"`
	Model string  `json:"model"`
	Date  float64 `json:"date"`
}

// Entry is one tracked finding across runs.
type Entry struct {
	Key            string   `json:"key"`
	CanonicalCWE   string   `json:"canonical_cwe"`
	Family         string   `json:"family"`
	Title          string   `json:"title"`
	Location       string   `json:"location"`
	Severity       string   `json:"severity"`
	FirstSeen      Stamp    `json:"first_seen"`
	LastSeen       Stamp    `json:"last_seen"`
	ConfirmedIn    []string `json:"confirmed_in"`
	ConfirmedCount int      `json:"confirmed_count"`
	CrossFamily    bool     `json:"cross_family"`
	Status         string   `json:"status"`     // open | fixed | regressed
	Confidence     string   `json:"confidence"` // provisional | confirmed | reliable
}

// Ledger is the on-disk per-target record.
type Ledger struct {
	Target       string   `json:"target"`
	Updated      float64  `json:"updated"`
	RunsRecorded []string `json:"runs_recorded"`
	Findings     []Entry  `json:"findings"`
}

func load(slug string) *Ledger {
	lg := &Ledger{RunsRecorded: []string{}, Findings: []Entry{}}
	b, err := os.ReadFile(ledgerPath(slug))
	if err != nil {
		return lg
	}
	_ = json.Unmarshal(b, lg)
	if lg.RunsRecorded == nil {
		lg.RunsRecorded = []string{}
	}
	return lg
}

func save(slug string, lg *Ledger) error {
	if err := os.MkdirAll(config.LedgerDir(), 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(lg, "", "  ")
	if err != nil {
		return err
	}
	tmp := ledgerPath(slug) + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, ledgerPath(slug))
}

var reFile = regexp.MustCompile(`([\w./+\-]+\.[A-Za-z0-9]{1,6})`)
var reLine = regexp.MustCompile(`:(\d+)`)
var reFunc = regexp.MustCompile(`([A-Za-z_][A-Za-z0-9_]*)\s*\(`)

// ledgerKey is the cross-run identity: sink findings key on family:file:func;
// logic/authz findings (no func) on cwe:file:@line-bucket.
func ledgerKey(f consolidate.Finding) string {
	file := reFile.FindString(f.Location)
	if i := strings.LastIndexByte(file, '/'); i >= 0 {
		file = file[i+1:]
	}
	fn := ""
	if m := reFunc.FindAllStringSubmatch(f.Location+" "+f.DataFlow, -1); len(m) > 0 {
		fn = strings.ToLower(m[len(m)-1][1])
	}
	if fn != "" {
		fam := f.CWEFamily
		if fam == "" {
			fam = f.NormalizedCWE
		}
		return fam + ":" + file + ":" + fn
	}
	// no function → bucket by line/20
	bucket := 0
	if m := reLine.FindStringSubmatch(f.Location); m != nil {
		n, _ := strconv.Atoi(m[1])
		bucket = n / 20
	}
	cwe := f.CWE
	if cwe == "" {
		cwe = f.NormalizedCWE
	}
	return cwe + ":" + file + ":@" + strconv.Itoa(bucket)
}

// Update merges a run's substantiated, non-duplicate findings into the target's
// ledger. Idempotent by run id (a re-recorded run does not double-count).
func Update(target, runID, model string, when float64, findings []consolidate.Finding) (*Ledger, error) {
	slug := Slug(target)
	lg := load(slug)
	lg.Target = target
	// idempotent by run id
	for _, r := range lg.RunsRecorded {
		if r == runID {
			return lg, nil
		}
	}
	lg.RunsRecorded = append(lg.RunsRecorded, runID)
	lg.Updated = when
	idx := map[string]int{}
	for i, e := range lg.Findings {
		idx[e.Key] = i
	}
	stamp := Stamp{Run: runID, Model: model, Date: when}
	for _, f := range findings {
		if f.DuplicateOf != nil || f.Classification == consolidate.ClassHypothesis {
			continue
		}
		key := ledgerKey(f)
		fam := f.CWEFamily
		if i, ok := idx[key]; ok {
			e := &lg.Findings[i]
			e.LastSeen = stamp
			if !contains(e.ConfirmedIn, runID) {
				e.ConfirmedIn = append(e.ConfirmedIn, runID)
			}
			e.ConfirmedCount = len(e.ConfirmedIn)
			if fam != "" && fam != e.Family {
				e.CrossFamily = true
			}
			e.Confidence = confidence(e.ConfirmedCount, e.CrossFamily)
		} else {
			e := Entry{
				Key: key, CanonicalCWE: f.NormalizedCWE, Family: fam, Title: f.Title,
				Location: f.Location, Severity: f.Severity, FirstSeen: stamp, LastSeen: stamp,
				ConfirmedIn: []string{runID}, ConfirmedCount: 1, Status: "open",
				Confidence: confidence(1, false),
			}
			lg.Findings = append(lg.Findings, e)
			idx[key] = len(lg.Findings) - 1
		}
	}
	return lg, save(slug, lg)
}

func confidence(count int, crossFamily bool) string {
	switch {
	case count >= 3 || (count >= 2 && crossFamily):
		return "reliable"
	case count >= 2 || crossFamily:
		return "confirmed"
	default:
		return "provisional"
	}
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

// Summary is the per-app ledger summary (GET /api/ledgers rows).
type Summary struct {
	Target       string         `json:"target"`
	TargetName   string         `json:"target_name"`
	RunsRecorded int            `json:"runs_recorded"`
	Total        int            `json:"total"`
	Open         int            `json:"open"`
	Fixed        int            `json:"fixed"`
	Regressed    int            `json:"regressed"`
	Reliable     int            `json:"reliable"`
	BySeverity   map[string]int `json:"by_severity"`
	Updated      float64        `json:"updated"`
	Slug         string         `json:"slug"`
}

func summarize(lg *Ledger, slug string) Summary {
	s := Summary{Target: lg.Target, RunsRecorded: len(lg.RunsRecorded),
		Total: len(lg.Findings), BySeverity: map[string]int{}, Updated: lg.Updated, Slug: slug}
	s.TargetName = filepath.Base(lg.Target)
	if s.TargetName == "" || lg.Target == "" {
		s.TargetName = "(unknown target)"
	}
	for _, e := range lg.Findings {
		switch e.Status {
		case "open":
			s.Open++
		case "fixed":
			s.Fixed++
		case "regressed":
			s.Regressed++
		}
		if e.Confidence == "reliable" {
			s.Reliable++
		}
		s.BySeverity[e.Severity]++
	}
	return s
}

// List returns summaries for every ledger on disk, newest-updated first.
func List() ([]Summary, error) {
	dir := config.LedgerDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return []Summary{}, nil
		}
		return nil, err
	}
	var out []Summary
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		slug := strings.TrimSuffix(e.Name(), ".json")
		out = append(out, summarize(load(slug), slug))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Updated > out[j].Updated })
	return out, nil
}

// LoadDetail returns the full ledger for a slug plus its summary (GET /api/ledgers/{slug}).
func LoadDetail(slug string) (map[string]any, bool) {
	if _, err := os.Stat(ledgerPath(slug)); err != nil {
		return nil, false
	}
	lg := load(slug)
	b, _ := json.Marshal(lg)
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	m["summary"] = summarize(lg, slug)
	m["slug"] = slug
	return m, true
}

// CoverageSummary is the vulnerability_ledger block embedded in findings.json.
func CoverageSummary(target, runID string, findings []consolidate.Finding) map[string]any {
	slug := Slug(target)
	lg := load(slug)
	found := map[string]bool{}
	for _, f := range findings {
		if f.DuplicateOf == nil && f.Classification != consolidate.ClassHypothesis {
			found[ledgerKey(f)] = true
		}
	}
	known := map[string]Entry{}
	for _, e := range lg.Findings {
		known[e.Key] = e
	}
	totalKnown := len(known)
	nFound := 0
	var missed []map[string]any
	for k, e := range known {
		if found[k] {
			nFound++
		} else {
			missed = append(missed, map[string]any{
				"title": e.Title, "cwe": e.CanonicalCWE, "location": e.Location,
				"confidence": e.Confidence, "confirmed_count": e.ConfirmedCount,
			})
		}
	}
	newCount := 0
	for k := range found {
		if _, ok := known[k]; !ok {
			newCount++
		}
	}
	recall := 0
	if totalKnown > 0 {
		recall = int(float64(nFound)/float64(totalKnown)*100 + 0.5)
	}
	return map[string]any{
		"ledger_file": slug + ".json", "runs_recorded": len(lg.RunsRecorded),
		"total_known": totalKnown, "open_known": totalKnown, "reliable": 0,
		"found": nFound, "new": newCount, "missed_count": len(missed),
		"recall_pct": recall, "missed": missed,
	}
}
