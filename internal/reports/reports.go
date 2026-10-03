// Package reports indexes the reports directory directly, so every scan on disk
// is listed — including CLI-run scans and those from earlier server processes.
// Each row degrades to fallbacks rather than dropping a report (FR-028).
package reports

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"vhlocal/internal/consolidate"
	"vhlocal/internal/membank"
)

// dirRE matches the results-dir naming convention external tooling globs.
var dirRE = regexp.MustCompile(`^(.*)_VULNHUNT_RESULTS_(.+)_(\d{4}-\d{2}-\d{2}-\d{6})$`)

// Report is one index row (fields mirror the Python Report.to_dict()).
type Report struct {
	Status           string         `json:"status,omitempty"`
	AmbiguousMapping bool           `json:"ambiguous_mapping,omitempty"`
	ID               string         `json:"id"`
	Path             string         `json:"path"`
	Name             string         `json:"name"`
	Repo             string         `json:"repo"`
	Model            string         `json:"model"`
	ModelReported    string         `json:"model_reported"`
	Created          float64        `json:"created"`
	Stamp            string         `json:"stamp"`
	Findings         int            `json:"findings"`
	Hypotheses       int            `json:"hypotheses"`
	Severities       map[string]int `json:"severities"`
	FindingsSummary  string         `json:"findings_summary"`
	Branch           string         `json:"branch"`
	AuditDate        string         `json:"audit_date"`
	Complete         bool           `json:"complete"`
	PhasesPresent    []string       `json:"phases_present"`
	Size             int64          `json:"size"`
	HasReport        bool           `json:"has_report"`
	HasConsolidated  bool           `json:"has_consolidated"`
	CoverageStatus   string         `json:"coverage_status"`
	CoverageDegraded bool           `json:"coverage_degraded"`
	// GitCommit is the scanned revision (scan_meta git_commit) — feature 014 artifact
	// selection cites it. ThreatModelDisabled is true when 1t was requested but
	// deliberately skipped (threat_model=false) and never completed (FR-026).
	GitCommit           string `json:"git_commit,omitempty"`
	ThreatModelDisabled bool   `json:"threat_model_disabled,omitempty"`
	// Outcome is the feature-014 completion block (run_status.outcome), passed
	// through verbatim for history drill-downs; nil for older runs.
	Outcome        any      `json:"outcome,omitempty"`
	RecallPct      *int     `json:"recall_pct"`
	LedgerSlug     string   `json:"ledger_slug"`
	Chains         int      `json:"chains"`
	SbomTotal      int      `json:"sbom_total"`
	HasSbom        bool     `json:"has_sbom"`
	HasThreatModel bool     `json:"has_threat_model"`
	ThreatModel    Material `json:"threat_model"`
	Sbom           Material `json:"sbom"`
	Slug           string   `json:"slug"`
	// CoverageSemantics (feature 015, FR-019): review_units.json semantics version
	// (1 read-overlap, 2 validated dispositions); 0 when the run has no record.
	CoverageSemantics int `json:"coverage_semantics,omitempty"`
	// Groups (feature 015, FR-020): remediation groups recorded for the run; 0 when
	// remediation_groups.json is absent.
	Groups int `json:"groups,omitempty"`
	// PresentationVersion (feature 016, FR-026, C-C8) is the reader-facing projection
	// version stamped in report_model.json. 0 means the saved report predates the
	// projection: its reader-facing figures are UNAVAILABLE rather than zero, and a
	// viewer must disclose that instead of rendering an empty redesigned report.
	PresentationVersion int `json:"presentation_version"`
	// IssuesToFix is the established-defect count from the projection. It is nil, not
	// zero, when the report carries no projection — the two mean different things.
	IssuesToFix *int `json:"issues_to_fix"`
	NeedsReview *int `json:"needs_review"`
	Dismissed   *int `json:"dismissed"`
	// Supported/Rejected/Unresolved come from the single consolidate.Classify rule
	// (feature 015, FR-002). Findings/Hypotheses above are unchanged legacy counts.
	Supported  int `json:"supported"`
	Rejected   int `json:"rejected"`
	Unresolved int `json:"unresolved"`

	// Per-run cost/time for Dashboard metrics (feature 008), from scan_meta.json.
	PromptTokens     int     `json:"prompt_tokens"`
	CompletionTokens int     `json:"completion_tokens"`
	DurationSeconds  float64 `json:"duration_seconds"`
	HasUsage         bool    `json:"has_usage"`

	threatRequested bool // 1t requested (internal; gates missing vs not_requested)
}

func exists(p string) bool { _, err := os.Stat(p); return err == nil }

// toInt reads a JSON-number field as int (tolerates float64/int).
func toInt(v any) int {
	switch n := v.(type) {
	case float64:
		return int(n)
	case int:
		return n
	}
	return 0
}

// reportDeliverables are the files whose presence marks a directory as a real
// results dir even when its name doesn't match the results-dir pattern (feature
// 008; parity with the reference is_report_dir). Prevents stray subdirectories from
// being treated as reports (→ phantom applications).
var reportDeliverables = []string{"scan_meta.json", "findings.json", "SCAN_REPORT.md", "README.md", "phase1_output.md"}

// isReportDir reports whether dir is a real results directory: its name matches the
// results-dir pattern, or it contains a recognized deliverable.
func isReportDir(dir string) bool {
	if dirRE.MatchString(filepath.Base(dir)) {
		return true
	}
	for _, d := range reportDeliverables {
		if exists(filepath.Join(dir, d)) {
			return true
		}
	}
	return false
}

// Load builds a Report from a results directory, or ok=false if it isn't one.
func Load(dir string) (Report, bool) {
	base := filepath.Base(dir)
	fi, err := os.Stat(dir)
	if err != nil || !fi.IsDir() {
		return Report{}, false
	}
	// A directory that is neither results-named nor holds a deliverable is not a
	// report — never surface it (and thus never a phantom application) (FR-008/009).
	if !isReportDir(dir) {
		return Report{}, false
	}
	r := Report{
		ID: base, Path: dir, Name: base, Severities: map[string]int{},
		PhasesPresent: []string{}, Created: float64(fi.ModTime().Unix()),
	}
	if m := dirRE.FindStringSubmatch(base); m != nil {
		r.Name = m[1]
		r.Model = m[2]
		r.Stamp = m[3]
	}

	// scan_meta.json → repo, model, git, phases.
	if b, err := os.ReadFile(filepath.Join(dir, "scan_meta.json")); err == nil {
		var meta map[string]any
		if json.Unmarshal(b, &meta) == nil {
			r.Status, _ = meta["status"].(string)
			r.Slug, _ = meta["app_slug"].(string)
			r.Repo, _ = meta["repo"].(string)
			if s, ok := meta["model"].(string); ok && s != "" {
				r.Model = s
			}
			r.Branch, _ = meta["git_branch"].(string)
			r.GitCommit, _ = meta["git_commit"].(string)
			r.ThreatModelDisabled = requestedPhase(meta, "1t") && phaseIn(meta, "phases_skipped", "1t") && !phaseIn(meta, "phases_completed", "1t")
			if pc, ok := meta["phases_completed"].([]any); ok {
				for _, p := range pc {
					if s, ok := p.(string); ok {
						r.PhasesPresent = append(r.PhasesPresent, s)
					}
				}
			}
			// Threat model + SBOM are gated on Phase 1t (research R2); a missing
			// artifact reads as "missing" only when 1t was requested.
			r.threatRequested = requestedPhase(meta, "1t")
			// Per-run usage + duration for Dashboard metrics (feature 008).
			if u, ok := meta["usage"].(map[string]any); ok {
				r.PromptTokens = toInt(u["prompt_tokens"])
				r.CompletionTokens = toInt(u["completion_tokens"])
			}
			r.HasUsage = r.PromptTokens > 0 || r.CompletionTokens > 0
			started, _ := meta["started_at"].(float64)
			finished, _ := meta["finished_at"].(float64)
			if started > 0 && finished > started {
				r.DurationSeconds = finished - started
			}
		}
	}
	if r.Slug != "" {
		// The creation-time canonical identity survives source moves/removal.
		r.LedgerSlug = r.Slug
	} else if r.Repo != "" {
		r.Slug = membank.Slug(r.Repo)
		r.LedgerSlug = r.Slug
	} else {
		// Never join unrelated legacy reports by a shared display basename.
		r.Slug = "unmapped-" + membank.Slug(dir)
		r.AmbiguousMapping = true
	}

	// findings.json → counts, run_status, sbom, lifecycle.
	if b, err := os.ReadFile(filepath.Join(dir, "findings.json")); err == nil {
		r.HasConsolidated = true
		var doc map[string]any
		if json.Unmarshal(b, &doc) == nil {
			if fs, ok := doc["findings"].([]any); ok {
				for _, fi := range fs {
					f, _ := fi.(map[string]any)
					if f["duplicate_of"] != nil {
						continue
					}
					r.Findings++
					switch consolidate.Classify(f) {
					case consolidate.ClassSupported:
						r.Supported++
					case consolidate.ClassRejected:
						r.Rejected++
					default:
						r.Unresolved++
					}
					if sev, _ := f["severity"].(string); sev != "" {
						r.Severities[sev]++
					}
					if cls, _ := f["classification"].(string); cls == "hypothesis" {
						r.Hypotheses++
					}
				}
			}
			if rs, ok := doc["run_status"].(map[string]any); ok {
				r.CoverageStatus, _ = rs["coverage_status"].(string)
				r.CoverageDegraded = r.CoverageStatus == "degraded"
				if oc, ok := rs["outcome"]; ok && oc != nil {
					r.Outcome = oc
				}
			}
			if ai, ok := doc["application_intelligence"].(map[string]any); ok {
				if sb, ok := ai["sbom"].(map[string]any); ok {
					if t, ok := sb["total"].(float64); ok {
						r.SbomTotal = int(t)
						r.HasSbom = t > 0
					}
				}
			}
		}
	}
	r.HasReport = exists(filepath.Join(dir, "README.md")) || exists(filepath.Join(dir, "SCAN_REPORT.md"))
	// Feature 015 (FR-019): coverage semantics version of the review-unit record.
	if b, err := os.ReadFile(filepath.Join(dir, "review_units.json")); err == nil {
		var ru struct {
			SemanticsVersion int `json:"semantics_version"`
		}
		r.CoverageSemantics = 1
		if json.Unmarshal(b, &ru) == nil && ru.SemanticsVersion > 0 {
			r.CoverageSemantics = ru.SemanticsVersion
		}
	}
	if b, err := os.ReadFile(filepath.Join(dir, "remediation_groups.json")); err == nil {
		var g struct {
			Grouped int `json:"grouped"`
		}
		if json.Unmarshal(b, &g) == nil {
			r.Groups = g.Grouped
		}
	}
	// Feature 016 (FR-026, C-C8): honour the presentation version. A report saved before
	// this feature has none, and its reader-facing counts stay unavailable rather than
	// being computed here — recomputing them in a lister is exactly what C-P27 forbids.
	if b, err := os.ReadFile(filepath.Join(dir, "report_model.json")); err == nil {
		var rm struct {
			Presentation *struct {
				Version int `json:"version"`
				Counts  struct {
					IssuesToFix int `json:"issues_to_fix"`
					NeedsReview int `json:"needs_review"`
					Dismissed   int `json:"dismissed"`
				} `json:"counts"`
			} `json:"presentation"`
		}
		if json.Unmarshal(b, &rm) == nil && rm.Presentation != nil && rm.Presentation.Version > 0 {
			r.PresentationVersion = rm.Presentation.Version
			issues, review, dismissed := rm.Presentation.Counts.IssuesToFix, rm.Presentation.Counts.NeedsReview, rm.Presentation.Counts.Dismissed
			r.IssuesToFix, r.NeedsReview, r.Dismissed = &issues, &review, &dismissed
		}
	}
	r.HasThreatModel = exists(filepath.Join(dir, "threat_model.md"))
	if !r.HasSbom {
		r.HasSbom = exists(filepath.Join(dir, "sbom.cdx.json"))
	}
	// Explicit availability states (feature 007, FR-018).
	// Feature 014 (FR-026): 1t requested but deliberately skipped (threat_model=false)
	// is an explained absence — classify as not_requested, never as missing.
	matReq := r.threatRequested && !r.ThreatModelDisabled
	r.ThreatModel = threatModelState(dir, matReq)
	r.Sbom = sbomState(dir, matReq)
	r.Complete = contains(r.PhasesPresent, "4")
	r.Size = dirSize(dir)
	return r, true
}

// Index lists every report under reportsDir (plus any explicit extra dirs),
// newest-first.
func Index(reportsDir string, extra ...string) ([]Report, error) {
	var out []Report
	seen := map[string]bool{}
	add := func(dir string) {
		if seen[dir] {
			return
		}
		if r, ok := Load(dir); ok {
			seen[dir] = true
			out = append(out, r)
		}
	}
	if entries, err := os.ReadDir(reportsDir); err == nil {
		for _, e := range entries {
			if e.IsDir() {
				add(filepath.Join(reportsDir, e.Name()))
			}
		}
	}
	for _, d := range extra {
		if d != "" {
			add(d)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Created > out[j].Created })
	return out, nil
}

func dirSize(dir string) int64 {
	var total int64
	filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			if fi, err := d.Info(); err == nil {
				total += fi.Size()
			}
		}
		return nil
	})
	return total
}

// requestedPhase reports whether a phase key is in scan_meta's phases_requested.
func requestedPhase(meta map[string]any, key string) bool {
	pr, ok := meta["phases_requested"].([]any)
	if !ok {
		return false
	}
	for _, p := range pr {
		if s, ok := p.(string); ok && s == key {
			return true
		}
	}
	return false
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

// SanitizeID reports whether a report id is safe (matched against the enumerated
// set by callers; this is a cheap structural guard).
func SanitizeID(id string) bool {
	return id != "" && !strings.Contains(id, "/") && !strings.Contains(id, "..")
}

// phaseIn reports whether meta[key] (a phase list) names the phase.
func phaseIn(meta map[string]any, key, phase string) bool {
	pr, ok := meta[key].([]any)
	if !ok {
		return false
	}
	for _, p := range pr {
		if s, ok := p.(string); ok && s == phase {
			return true
		}
	}
	return false
}
