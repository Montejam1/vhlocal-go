package engine

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"vhlocal/internal/inventory"
	"vhlocal/internal/reports"
)

// maxSeedRoutes bounds the seeded inventory so recon context stays a bounded,
// source-grounded hint rather than an unbounded dump (feature 013, FR-008/009).
const maxSeedRoutes = 200

// reconSelected reports whether a recon phase (1 or 1t) is in the plan; route/
// prior seeding is only applicable then (FR-009).
func reconSelected(phaseList []string) bool {
	for _, k := range phaseList {
		if k == "1" || k == "1t" {
			return true
		}
	}
	return false
}

// routeSeedContext builds the bounded, source-grounded multi-language entry-point
// inventory (feature 012) to inject into Phase-1 recon (FR-008). It returns the
// context text, the number of routes included, and whether the list was truncated.
// An empty inventory yields empty text with count 0 — the caller discloses it and
// never presents it as a complete attack surface.
func routeSeedContext(repo string) (text string, count int, truncated bool) {
	routes, err := inventory.EnumerateRoutes(repo)
	if err != nil || len(routes) == 0 {
		return "", 0, false
	}
	// Deterministic order (file, line) so the seed is reproducible.
	sort.Slice(routes, func(i, j int) bool {
		if routes[i].File != routes[j].File {
			return routes[i].File < routes[j].File
		}
		return routes[i].Line < routes[j].Line
	})
	total := len(routes)
	if len(routes) > maxSeedRoutes {
		routes = routes[:maxSeedRoutes]
		truncated = true
	}
	var b strings.Builder
	b.WriteString("\n\n## Seeded entry-point inventory (deterministic, feature-012 recognizer)\n")
	b.WriteString("These are candidate entry points found statically across languages. Treat them as ")
	b.WriteString("investigation leads and additional context — NOT a complete or authoritative attack ")
	b.WriteString("surface. Verify each against the source; discover anything missing.\n\n")
	for _, r := range routes {
		lang := r.Language
		if lang == "" {
			lang = "python"
		}
		fmt.Fprintf(&b, "- [%s] %s %s (%s:%d)\n", lang, r.Method, r.Path, r.File, r.Line)
	}
	if truncated {
		fmt.Fprintf(&b, "\n(…truncated: showing %d of %d discovered entry points.)\n", maxSeedRoutes, total)
	}
	return b.String(), len(routes), truncated
}

// applyRouteSeed appends the route-seed context to a recon task and records
// provenance (requested vs applied, count, truncation, unavailability) on the run
// record (FR-008/009). It is a no-op when seeding was not requested.
func applyRouteSeed(rec *RunRecord, spec ScanSpec, task string) string {
	if !spec.SeedRoutes {
		return task
	}
	rec.SeedRoutesRequested = true
	text, count, truncated := routeSeedContext(spec.Repo)
	if count == 0 {
		rec.SeedRoutesApplied = false
		rec.SeedRoutesUnavailable = "no entry points were discovered to seed"
		return task
	}
	rec.SeedRoutesApplied = true
	rec.SeedRoutesCount = count
	rec.SeedRoutesTruncated = truncated
	return task + text
}

// maxPriorLeads bounds how many prior findings are injected as leads.
const maxPriorLeads = 100

// selectPriorReport deterministically selects an eligible prior report for the
// SAME repository as the current scan (feature 013, FR-010): a complete report
// for the same repo path, most recent (reports.Index is newest-first), never the
// current run's own directory and never another repository's report. Returns
// ok=false with a reason when none is eligible.
func selectPriorReport(spec ScanSpec) (reports.Report, string, bool) {
	if spec.ReportsDir == "" {
		return reports.Report{}, "no reports directory configured for prior-report seeding", false
	}
	rs, err := reports.Index(spec.ReportsDir, spec.ResultsDir)
	if err != nil {
		return reports.Report{}, "prior reports could not be listed: " + err.Error(), false
	}
	cur, _ := filepath.Abs(spec.ResultsDir)
	repoAbs, _ := filepath.Abs(spec.Repo)
	for _, r := range rs {
		rp, _ := filepath.Abs(r.Path)
		if rp == cur {
			continue // never seed from the run's own directory
		}
		rRepo, _ := filepath.Abs(r.Repo)
		if rRepo != repoAbs || r.Repo == "" {
			continue // same repository only — never another repo's report
		}
		if !r.Complete {
			continue // only a complete prior report is eligible
		}
		return r, "", true
	}
	return reports.Report{}, "no eligible prior report for this repository", false
}

// priorLeads reads a prior report's findings.json and returns bounded recon LEADS
// — title + class + location only. It never copies historical support, severity,
// execution claims, or human decisions; those are re-derived by the current
// verification (FR-011). Returns empty when findings cannot be read.
func priorLeads(reportPath string) (text string, count int) {
	b, err := os.ReadFile(filepath.Join(reportPath, "findings.json"))
	if err != nil {
		return "", 0
	}
	var doc struct {
		Findings []struct {
			Title       string `json:"title"`
			CWE         string `json:"cwe"`
			Location    string `json:"location"`
			DuplicateOf any    `json:"duplicate_of"`
		} `json:"findings"`
	}
	if json.Unmarshal(b, &doc) != nil {
		return "", 0
	}
	var b2 strings.Builder
	b2.WriteString("\n\n## Prior-report leads (candidates to RE-VERIFY, not accepted results)\n")
	b2.WriteString("A previous scan of this repository reported the following candidates. Treat them as ")
	b2.WriteString("leads only: independently re-verify each against the CURRENT source. Do NOT assume any ")
	b2.WriteString("prior severity, support, execution, or human decision — none is carried over.\n\n")
	for _, f := range doc.Findings {
		if f.DuplicateOf != nil || strings.TrimSpace(f.Title) == "" {
			continue
		}
		loc := f.Location
		if loc == "" {
			loc = "(location unspecified)"
		}
		fmt.Fprintf(&b2, "- %s [%s] @ %s\n", f.Title, f.CWE, loc)
		count++
		if count >= maxPriorLeads {
			break
		}
	}
	if count == 0 {
		return "", 0
	}
	return b2.String(), count
}

// applyPriorSeed appends prior-report leads to a recon task and records provenance
// (FR-010/011). A missing / mismatched / malformed / empty prior report yields an
// explained unseeded scan — never a fake seed and never another repo's report.
func applyPriorSeed(rec *RunRecord, spec ScanSpec, task string) string {
	if !spec.SeedPrior {
		return task
	}
	rec.SeedPriorRequested = true
	rep, reason, ok := selectPriorReport(spec)
	if !ok {
		rec.SeedPriorApplied = false
		rec.SeedPriorReason = reason
		return task
	}
	text, count := priorLeads(rep.Path)
	if count == 0 {
		rec.SeedPriorApplied = false
		rec.SeedPriorReport = rep.ID
		rec.SeedPriorReason = "prior report had no usable findings to seed"
		return task
	}
	rec.SeedPriorApplied = true
	rec.SeedPriorReport = rep.ID
	// Mark the run correlated so it is not treated as an independent benchmark sample.
	rec.SeededOrCorrelated = true
	rec.SeededFromPrior = rep.ID
	return task + text
}
