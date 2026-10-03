// Package attention computes the dashboard's "Needs attention" queues for the
// analyst workspace (feature 010, US4). It is a separate, additive computation
// from the preserved dashboard metrics (/api/stats): a failure here must never
// blank or block the existing dashboard (FR-037). Each queue reports its scope,
// definition, count, and a link to the matching filtered destination, counts are
// deduplicated so one item cannot inflate a queue (FR-036), and unavailable data
// is reported honestly rather than as zero.
package attention

import (
	"encoding/json"
	"os"
	"path/filepath"

	"vhlocal/internal/apps"
	"vhlocal/internal/findings"
	"vhlocal/internal/reports"
)

// Queue is one "Needs attention" bucket.
type Queue struct {
	Key        string `json:"key"`
	Label      string `json:"label"`
	Definition string `json:"definition"`
	Count      int    `json:"count"`
	Link       string `json:"link"`
	Available  bool   `json:"available"`        // false ⇒ data could not support a count
	Reason     string `json:"reason,omitempty"` // why unavailable
	Note       string `json:"note,omitempty"`   // honest caveat (e.g. no baseline)
}

// Report is the full "Needs attention" section.
type Report struct {
	Queues    []Queue `json:"queues"`
	StaleDays int     `json:"stale_days"`
}

// DispFunc returns a finding's head review disposition (injected to avoid an
// import cycle with the review store; matches findings' lookup shape).
type DispFunc func(string) string

const critHigh = "critical,high"

// Compute builds the section. now is the reference time (Unix seconds) for
// staleness, injected for testability. Each queue is computed independently; a
// per-queue failure yields an unavailable queue, never a failed section.
func Compute(reportsDir string, staleDays int, disp DispFunc, now int64) Report {
	if staleDays <= 0 {
		staleDays = 7
	}
	rep := Report{StaleDays: staleDays}
	rep.Queues = []Queue{
		findingQueue(reportsDir, disp,
			"supported_awaiting_review", "Supported Critical/High awaiting review",
			"Supported findings at Critical or High severity whose review is still needed.",
			findings.Query{Evidence: "supported", Review: "needs-review", SeverityIn: []string{"Critical", "High"}},
			"findings?evidence=supported&review=needs-review&severity_in="+critHigh),

		newSupportedQueue(reportsDir, disp),

		findingQueue(reportsDir, disp,
			"unresolved", "Unresolved findings needing review or evidence",
			"Findings whose evidence assessment is unresolved and still need review or more evidence.",
			findings.Query{Evidence: "unresolved"},
			"findings?evidence=unresolved"),

		regressionQueue(reportsDir, disp),

		incompleteScansQueue(reportsDir),

		staleAppsQueue(reportsDir, staleDays, now),
	}
	return rep
}

// findingQueue counts DISTINCT findings (by stable identity) matching q, so a
// finding recurring across scans counts once (FR-036). The link encodes the same
// filter so the count matches its destination.
func findingQueue(reportsDir string, disp DispFunc, key, label, def string, q findings.Query, link string) Queue {
	res := findings.Search(reportsDir, q, lookup(disp))
	return Queue{Key: key, Label: label, Definition: def, Count: distinct(res.Rows), Link: link, Available: true}
}

// newSupportedQueue counts new supported Critical/High findings relative to each
// application's comparable baseline (the engine's cross-run lifecycle). When no
// scan carries any comparison data, it reports an explicit no-baseline note
// rather than a misleading zero.
func newSupportedQueue(reportsDir string, disp DispFunc) Queue {
	q := findings.Query{Status: "new", Evidence: "supported", SeverityIn: []string{"Critical", "High"}}
	res := findings.Search(reportsDir, q, lookup(disp))
	queue := Queue{
		Key: "new_supported", Label: "New supported Critical/High",
		Definition: "Supported Critical/High findings that are new relative to a comparable prior scan.",
		Count:      distinct(res.Rows), Available: true,
		Link: "findings?status=new&evidence=supported&severity_in=" + critHigh,
	}
	// Honesty: if nothing in the index carries any lifecycle label, there is no
	// comparable baseline to be "new" against (FR-035 explicit no-baseline state).
	if !anyComparable(reportsDir, disp) {
		queue.Note = "No comparable baseline yet — run a second scan of an application to enable new/regressed detection."
	}
	return queue
}

func regressionQueue(reportsDir string, disp DispFunc) Queue {
	return findingQueue(reportsDir, disp,
		"regressions", "Regressions",
		"Findings the engine labeled regressed against comparable scan history.",
		findings.Query{Status: "regressed"},
		"findings?status=regressed")
}

// incompleteScansQueue counts scans whose execution did not complete OR that have
// a requested artifact in a failed/missing/unreadable/malformed state (FR-035).
func incompleteScansQueue(reportsDir string) Queue {
	q := Queue{
		Key: "incomplete_scans", Label: "Incomplete scans & failed artifacts",
		Definition: "Scans that did not finish, or whose requested artifacts failed or are missing.",
		Link:       "scans", Available: true,
	}
	idx, err := reports.Index(reportsDir)
	if err != nil {
		q.Available = false
		q.Reason = "could not read scans"
		return q
	}
	n := 0
	for _, r := range idx {
		if scanNeedsAttention(r.Path) {
			n++
		}
	}
	q.Count = n
	return q
}

func scanNeedsAttention(dir string) bool {
	if exec := executionStatus(dir); exec != "" && exec != "complete" {
		return true
	}
	for _, e := range reports.Manifest(dir) {
		switch e.State {
		case reports.MatMissing, reports.MatGenerationFailed, reports.MatUnreadable, reports.MatMalformed:
			return true
		}
	}
	return false
}

// staleAppsQueue counts applications whose latest scan is older than staleDays.
// Applications with no recorded last scan are noted as unknown, not counted as
// stale (time staleness is not proof of incomplete coverage — FR-038).
func staleAppsQueue(reportsDir string, staleDays int, now int64) Queue {
	q := Queue{
		Key: "stale_apps", Label: "Applications not scanned recently",
		Definition: "Applications whose most recent scan is older than the staleness threshold.",
		Link:       "applications", Available: true,
	}
	cutoff := float64(now - int64(staleDays)*86400)
	stale, unknown := 0, 0
	for _, a := range apps.ListSummaries(reportsDir) {
		if a.LastScanned <= 0 {
			unknown++
			continue
		}
		if a.LastScanned < cutoff {
			stale++
		}
	}
	q.Count = stale
	if unknown > 0 {
		q.Note = plural(unknown, "application has", "applications have") + " no recorded scan date (shown as unknown, not stale)."
	}
	return q
}

// --- helpers ---

func distinct(rows []findings.Row) int {
	seen := map[string]bool{}
	for _, r := range rows {
		k := r.StableID
		if k == "" {
			k = r.Occurrence // findings without a stable identity cannot be deduped
		}
		seen[k] = true
	}
	return len(seen)
}

func anyComparable(reportsDir string, disp DispFunc) bool {
	for _, r := range findings.Index(reportsDir, lookup(disp)) {
		if r.Lifecycle != "" {
			return true
		}
	}
	return false
}

func executionStatus(dir string) string {
	b, err := os.ReadFile(filepath.Join(dir, "findings.json"))
	if err != nil {
		return ""
	}
	var raw struct {
		RunStatus struct {
			ExecutionStatus string `json:"execution_status"`
		} `json:"run_status"`
	}
	if json.Unmarshal(b, &raw) != nil {
		return ""
	}
	return raw.RunStatus.ExecutionStatus
}

func lookup(d DispFunc) func(string) string {
	if d == nil {
		return func(string) string { return "needs-review" }
	}
	return func(s string) string { return d(s) }
}

func plural(n int, one, many string) string {
	if n == 1 {
		return itoa(n) + " " + one
	}
	return itoa(n) + " " + many
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
