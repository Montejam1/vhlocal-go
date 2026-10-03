// Package report renders the consolidated report deterministically from the
// engine-built findings — no model involved (constitution Principle I; FR-014).
// It writes SCAN_REPORT.md and a single self-contained SCAN_REPORT.html with no
// external network requests (FR-008): inline CSS/JS, print stylesheet forcing
// the light palette and expanding sections, severity as glyph+word (not colour
// alone), and a "filtered view" banner when exported under an active filter.
package report

import (
	"fmt"
	"sort"
	"strings"

	"vhlocal/internal/consolidate"
)

const (
	MDFile   = "SCAN_REPORT.md"
	HTMLFile = "SCAN_REPORT.html"
)

// Input carries the facts the report renders (all engine-observed).
type Input struct {
	Target          string
	Model           string
	Host            string
	StartedAt       string // human-readable
	FinishedAt      string
	Duration        string
	Doc             consolidate.Doc
	CodeExecuted    bool // false = static-only (the default)
	VerifyModelUsed bool
	// Nav are relative links to intelligence artifacts that exist alongside the
	// report (threat model, SBOM, coverage, sweep, handoff) — feature 007, US6.
	Nav []NavLink
	// Repro maps a finding id to its reproduction disposition (kind/path/status/
	// reason) from artifact_manifest.json.
	Repro map[string]map[string]any
	// ReviewGaps are the unreviewed entry points with reasons from review_units.json
	// (feature 014, FR-016); rendered as "Review coverage". Nil for pre-014 runs.
	ReviewGaps []ReviewGap
	// Feature 015 (report model): scan identity, revision, coverage view and groups.
	ScanID        string
	Repo          string
	GitCommit     string
	GitBranch     string
	Coverage      *CoverageView
	CoverageLabel string
	Groups        []Group
	// Diagram is the threat-model diagram validation summary (feature 015); empty
	// when the run has no threat model.
	Diagram string
	// Failures are the verification-session failure aggregates (feature 015, FR-026,
	// C-C10): occurrences vs sessions vs stop reasons, which do not sum to each
	// other. Nil when the run has no session record.
	Failures *FailureAggregates
}

// FailureAggregates mirrors verification_metrics.json `session_aggregates`.
type FailureAggregates struct {
	Sessions           int            `json:"sessions"`
	Calls              int            `json:"calls"`
	OccurrencesByClass map[string]int `json:"occurrences_by_class"`
	SessionsByClass    map[string]int `json:"sessions_by_class"`
	StopReasons        map[string]int `json:"stop_reasons"`
	ExplicitUnresolved int            `json:"explicit_unresolved"`
	AmendedSessions    int            `json:"amended_sessions"`
	OverlapNote        string         `json:"overlap_note"`
}

// ReviewGap is one unreviewed entry point and why (mirrors engine.ReviewGap).
type ReviewGap struct{ RouteID, Reason string }

// NavLink is one relative navigation entry rendered when the artifact is present.
type NavLink struct{ Label, Path string }

// finding classification for report grouping (feature 007, US6).
// Feature 015 (FR-002): both predicates delegate to the single consolidate.Classify
// rule so the report can never disagree with findings.json or the UIs.
func isSupported(f map[string]any) bool { return consolidate.Classify(f) == consolidate.ClassSupported }

func isRejected(f map[string]any) bool { return consolidate.Classify(f) == consolidate.ClassRejected }

// rec reads a field from a finding's verification_record (the source-grounded
// review), returning "" when absent.
func rec(f map[string]any, key string) string {
	m, _ := f["verification_record"].(map[string]any)
	if m == nil {
		return ""
	}
	return str(m[key])
}

// evidenceExcerpt returns the first cited evidence's "path:start-end" locator.
func evidenceExcerpt(f map[string]any) string {
	m, _ := f["verification_record"].(map[string]any)
	if m == nil {
		return ""
	}
	ev, _ := m["evidence"].([]any)
	if len(ev) == 0 {
		return ""
	}
	e, _ := ev[0].(map[string]any)
	if e == nil {
		return ""
	}
	return fmt.Sprintf("%s:%d-%d", str(e["path"]), toInt(e["start_line"]), toInt(e["end_line"]))
}

// reproLine describes a finding's reproduction disposition for the report.
func (in Input) reproLine(id string) string {
	e := in.Repro[id]
	if e == nil {
		return "none authored"
	}
	switch str(e["kind"]) {
	case "deferred":
		return "deferred — " + str(e["reason"])
	case "poc", "test":
		return fmt.Sprintf("authored %s (%s) — not executed", str(e["kind"]), str(e["path"]))
	}
	return "none authored"
}

func orNR(s string) string {
	if strings.TrimSpace(s) == "" {
		return "_not recorded_"
	}
	return s
}

// partitionLine surfaces the requested-vs-actual partition relationship and
// documents that max_partitions caps the model plan, not the total (feature 007,
// US7/FR-035). Returns "" when partition metadata is absent.
func partitionLine(meta map[string]any) string {
	if meta == nil {
		return ""
	}
	req := toInt(meta["max_partitions"])
	actual := len(asSlice(meta["partitions"]))
	if req == 0 && actual == 0 {
		return ""
	}
	src := str(meta["partition_source"])
	cov := len(asSlice(meta["coverage_partitions_added"]))
	tm := len(asSlice(meta["threat_model_partitions"]))
	return fmt.Sprintf("**Partitioning**: requested cap %d, resolved %d (source: %s; +%d coverage, +%d threat-model). "+
		"`max_partitions` caps the model's plan; coverage and threat-model augmentation may exceed it.", req, actual, orNR(src), cov, tm)
}

func asSlice(v any) []any {
	s, _ := v.([]any)
	return s
}

// partition splits non-duplicate findings into supported / rejected / other,
// each severity-sorted (nonDup already sorts).
func partition(doc consolidate.Doc) (supported, rejected, other []map[string]any) {
	for _, f := range nonDup(doc) {
		switch {
		case isSupported(f):
			supported = append(supported, f)
		case isRejected(f):
			rejected = append(rejected, f)
		default:
			other = append(other, f)
		}
	}
	return
}

// severity display order + glyphs (glyph + word so colour is not the only channel).
var sevDisplay = []struct{ label, glyph string }{
	{"Critical", "▲"}, {"High+", "▲"}, {"High", "△"},
	{"Medium", "◆"}, {"Low", "•"}, {"Informational", "·"}, {"Unrated", "?"},
}

func nonDup(doc consolidate.Doc) []map[string]any {
	var out []map[string]any
	for _, f := range doc.Findings {
		if f["duplicate_of"] == nil {
			out = append(out, f)
		}
	}
	// sort by severity_rank then id
	sort.SliceStable(out, func(i, j int) bool {
		ri, _ := out[i]["severity_rank"].(int)
		rj, _ := out[j]["severity_rank"].(int)
		if ri != rj {
			return ri < rj
		}
		return str(out[i]["id"]) < str(out[j]["id"])
	})
	return out
}

func str(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

// isCleanRun reports whether the run completed cleanly (execution complete, no
// degradation reasons). A non-clean run gets a prominent banner so an empty
// findings list is never mistaken for a clean target (FR-012).
func isCleanRun(in Input) bool {
	rs := in.Doc.RunStatus
	return (rs.ExecutionStatus == "" || rs.ExecutionStatus == "complete") && len(rs.CoverageDegradedReasons) == 0
}

// phaseOutcome is one row of the per-phase outcome table.
type phaseOutcome struct {
	Phase, Label, Stop string
	Turns, PT, CT      int
	Produced           bool
}

// phaseOutcomes extracts per-agent outcomes from the embedded scan_meta agents[]
// (FR-013). Derived from engine facts, not model prose.
func phaseOutcomes(in Input) []phaseOutcome {
	agentsAny, _ := in.Doc.Meta["agents"].([]any)
	// "Produced" reflects an ACTUAL deliverable (phases_completed), not the agent
	// stop reason — an agent can end "complete" without writing its output
	// (Principle I: don't imply output that wasn't produced).
	completed := map[string]bool{}
	if pc, ok := in.Doc.Meta["phases_completed"].([]any); ok {
		for _, p := range pc {
			if s, ok := p.(string); ok {
				completed[s] = true
			}
		}
	}
	out := make([]phaseOutcome, 0, len(agentsAny))
	for _, a := range agentsAny {
		m, _ := a.(map[string]any)
		if m == nil {
			continue
		}
		out = append(out, phaseOutcome{
			Phase: str(m["phase"]), Label: str(m["label"]), Stop: str(m["stopped_reason"]),
			Turns: toInt(m["turns"]), PT: toInt(m["prompt_tokens"]), CT: toInt(m["completion_tokens"]),
			Produced: completed[str(m["phase"])],
		})
	}
	return out
}

func toInt(v any) int {
	switch n := v.(type) {
	case int:
		return n
	case float64:
		return int(n)
	}
	return 0
}

// brokenBanner is the honest incomplete-run headline: it counts REAL requested vs
// completed phases (not per-candidate agents) and only claims "zero-finding" when
// there truly are no findings. With findings present it says the run is partial —
// never "zero-finding" when findings exist.
func brokenBanner(in Input) string {
	req := 0
	if pr, ok := in.Doc.Meta["phases_requested"].([]any); ok {
		req = len(pr)
	}
	done := 0
	seen := map[string]bool{}
	if pc, ok := in.Doc.Meta["phases_completed"].([]any); ok {
		for _, p := range pc {
			if s, ok := p.(string); ok && !seen[s] {
				seen[s] = true
				done++
			}
		}
	}
	n := len(in.Doc.Findings)
	if n == 0 {
		return fmt.Sprintf("%d of %d requested phases completed. A zero-finding result here reflects an incomplete scan, not a clean target.", done, req)
	}
	return fmt.Sprintf("%d of %d requested phases completed. %d finding(s) were produced, but coverage was degraded — treat this as a partial scan, not exhaustive.", done, req, n)
}
