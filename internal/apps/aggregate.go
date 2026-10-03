package apps

import (
	"sort"

	"vhlocal/internal/membank"
	"vhlocal/internal/reports"
)

// AppSummary is one applications-list item — the registry entry joined with its
// reports and (optional) ledger (feature 007, data-model §AppSummary; parity with
// the reference _app_summary). open_findings/ledger_total are pointers so a missing
// ledger reads as null (not 0).
type AppSummary struct {
	AmbiguousMapping bool           `json:"ambiguous_mapping,omitempty"`
	Slug             string         `json:"slug"`
	Name             string         `json:"name"`
	Repo             string         `json:"repo"`
	Named            bool           `json:"named"`
	Scans            int            `json:"scans"`
	LastScanned      float64        `json:"last_scanned"`
	LatestFindings   int            `json:"latest_findings"`
	LatestSeverities map[string]int `json:"latest_severities"`
	LatestCoverage   string         `json:"latest_coverage"`
	LatestReportID   string         `json:"latest_report_id"`
	OpenFindings     *int           `json:"open_findings"`
	LedgerTotal      *int           `json:"ledger_total"`
	HasThreatModel   bool           `json:"has_threat_model"`
	HasSbom          bool           `json:"has_sbom"`
}

// ScanHistoryRow is one report row in an application detail.
type ScanHistoryRow struct {
	Status           string         `json:"status,omitempty"`
	AmbiguousMapping bool           `json:"ambiguous_mapping,omitempty"`
	ID               string         `json:"id"`
	Created          float64        `json:"created"`
	Model            string         `json:"model"`
	Findings         int            `json:"findings"`
	Hypotheses       int            `json:"hypotheses"`
	Severities       map[string]int `json:"severities"`
	CoverageStatus   string         `json:"coverage_status"`
	CoverageDegraded bool           `json:"coverage_degraded"`
	// CoverageSemantics (feature 015, FR-019): the review-unit evidence standard
	// (1 = read overlap, 2 = validated dispositions); 0 for runs without a record.
	CoverageSemantics int `json:"coverage_semantics,omitempty"`
	// Groups (feature 015, FR-020): remediation groups of the run (0 = no record).
	Groups         int  `json:"groups,omitempty"`
	HasReport      bool `json:"has_report"`
	HasThreatModel bool `json:"has_threat_model"`
	HasSbom        bool `json:"has_sbom"`
	RecallPct      *int `json:"recall_pct"`
	Chains         int  `json:"chains"`
	// Outcome is the feature-014 completion block for this scan (additive; nil
	// for older runs). Existing metric fields are unchanged.
	Outcome any `json:"outcome,omitempty"`
}

// AppDetail is the applications-detail view (AppSummary + history + ledger flag).
type AppDetail struct {
	Ambiguous []ScanHistoryRow `json:"ambiguous"`
	AppSummary
	ScanHistory []ScanHistoryRow `json:"scan_history"`
	HasLedger   bool             `json:"has_ledger"`
	// Artifacts is the newest-valid threat model / SBOM selection from THIS
	// application's history with disclosure (feature 014, FR-025/026).
	Artifacts AppArtifacts `json:"artifacts"`
}

// index joins the three sources: the raw registry (incl. hidden), reports grouped
// by slug (newest-first), and ledger summaries by slug.
func index(reportsDir string, extraDirs ...string) (reg map[string]Entry, bySlug map[string][]reports.Report, ledgers map[string]membank.Summary) {
	reg = loadAll()
	bySlug = map[string][]reports.Report{}
	rs, _ := reports.Index(reportsDir, extraDirs...)
	for _, r := range rs {
		s := r.Slug
		if s == "" {
			s = r.Name
		}
		bySlug[s] = append(bySlug[s], r)
	}
	for s := range bySlug { // reports.Index already sorts -created globally; keep per-slug newest-first
		sort.SliceStable(bySlug[s], func(i, j int) bool { return bySlug[s][i].Created > bySlug[s][j].Created })
	}
	ledgers = map[string]membank.Summary{}
	if ls, err := membank.List(); err == nil {
		for _, l := range ls {
			ledgers[l.Slug] = l
		}
	}
	return reg, bySlug, ledgers
}

func summary(slug string, reg map[string]Entry, bySlug map[string][]reports.Report, ledgers map[string]membank.Summary) AppSummary {
	entry := reg[slug]
	scans := bySlug[slug]
	var latest *reports.Report
	if len(scans) > 0 {
		latest = &scans[0]
	}
	led, hasLed := ledgers[slug]

	name := entry.Name
	if name == "" && hasLed {
		name = led.TargetName
	}
	if name == "" && latest != nil {
		if latest.Repo != "" {
			name = latest.Repo
		} else {
			name = latest.Name
		}
	}
	if name == "" {
		name = slug
	}
	repo := entry.Repo
	if repo == "" && hasLed {
		repo = led.Target
	}
	if repo == "" && latest != nil {
		repo = latest.Repo
	}

	as := AppSummary{
		Slug: slug, Name: name, Repo: repo,
		Named: registered(reg, slug), Scans: len(scans),
		LatestSeverities: map[string]int{},
	}
	switch {
	case latest != nil:
		as.AmbiguousMapping = latest.AmbiguousMapping
		as.LastScanned = latest.Created
		as.LatestFindings = latest.Findings
		if latest.Severities != nil {
			as.LatestSeverities = latest.Severities
		}
		as.LatestCoverage = latest.CoverageStatus
		as.LatestReportID = latest.ID
	default:
		as.LastScanned = entry.Updated
	}
	if hasLed {
		open, total := led.Open, led.Total
		as.OpenFindings, as.LedgerTotal = &open, &total
	}
	for _, r := range scans {
		as.HasThreatModel = as.HasThreatModel || r.HasThreatModel
		as.HasSbom = as.HasSbom || r.HasSbom
	}
	return as
}

// registered reports whether the slug has a registry entry (hidden included).
func registered(reg map[string]Entry, slug string) bool {
	_, ok := reg[slug]
	return ok
}

// ListSummaries returns the discovery union (registry ∪ reports ∪ ledgers) minus
// hidden slugs, newest-scanned first (FR-007, CA-1).
func ListSummaries(reportsDir string, extraDirs ...string) []AppSummary {
	reg, bySlug, ledgers := index(reportsDir, extraDirs...)
	slugs := map[string]bool{}
	for s := range reg {
		slugs[s] = true
	}
	for s := range bySlug {
		slugs[s] = true
	}
	for s := range ledgers {
		slugs[s] = true
	}
	var out []AppSummary
	for s := range slugs {
		if e, ok := reg[s]; ok && e.Hidden { // forgotten apps stay out of the list
			continue
		}
		out = append(out, summary(s, reg, bySlug, ledgers))
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].LastScanned > out[j].LastScanned })
	return out
}

// SummaryFor returns the summary for one repo's slug (for the ?repo= pre-fill).
func SummaryFor(repo, reportsDir string, extraDirs ...string) AppSummary {
	reg, bySlug, ledgers := index(reportsDir, extraDirs...)
	return summary(SlugFor(repo), reg, bySlug, ledgers)
}

// BuildDetail returns the full detail for a slug, or ok=false if the slug is
// unknown across all three sources. Unlike the list, a hidden slug is still
// returned when a report/ledger remains (CA-2/CA-3).
func BuildDetail(slug, reportsDir string, extraDirs ...string) (AppDetail, bool) {
	reg, bySlug, ledgers := index(reportsDir, extraDirs...)
	_, inReg := reg[slug]
	_, inLed := ledgers[slug]
	scans := bySlug[slug]
	if !inReg && !inLed && len(scans) == 0 {
		return AppDetail{}, false
	}
	d := AppDetail{AppSummary: summary(slug, reg, bySlug, ledgers), HasLedger: inLed, Ambiguous: []ScanHistoryRow{}}
	d.Artifacts = selectArtifacts(scans)
	for i := range scans {
		r := scans[i]
		d.ScanHistory = append(d.ScanHistory, ScanHistoryRow{
			Status: r.Status, AmbiguousMapping: r.AmbiguousMapping,
			ID: r.ID, Created: r.Created, Model: r.Model, Findings: r.Findings,
			Hypotheses: r.Hypotheses, Severities: r.Severities, CoverageStatus: r.CoverageStatus,
			CoverageDegraded: r.CoverageDegraded, CoverageSemantics: r.CoverageSemantics, Groups: r.Groups, HasReport: r.HasReport, HasThreatModel: r.HasThreatModel,
			HasSbom: r.HasSbom, RecallPct: r.RecallPct, Chains: r.Chains,
			Outcome: r.Outcome,
		})
		if r.AmbiguousMapping {
			d.Ambiguous = append(d.Ambiguous, d.ScanHistory[len(d.ScanHistory)-1])
		}
	}
	return d, true
}
