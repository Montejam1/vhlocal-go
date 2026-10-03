// Hunt deliverable v2 handler dispositions (feature 015, FR-016/017): parse the
// "## Handler dispositions" section a unit writes and validate every block against
// what the harness observed — the unit's assignment (scope), the run revision, the
// unit's actual Read spans (evidence), the planned weakness checks and the route
// inventory (identity). A disposition the harness cannot validate is recorded and
// NOT credited; a bare "reviewed everything" sentence produces no disposition.
package engine

import (
	"fmt"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"vhlocal/internal/agent"
	"vhlocal/internal/inventory"
)

// Check statuses in a disposition (data-model "checks[].status").
const (
	CheckDone       = "done"
	CheckNA         = "n_a"
	CheckUnresolved = "unresolved"
)

// Validation outcomes (data-model "dispositions[].validation").
const (
	ValOK          = "ok"
	ValOutOfScope  = "out_of_scope"
	ValStale       = "stale"
	ValNotRead     = "not_read"
	ValOutsideSpan = "outside_span"
	ValFabricated  = "fabricated"
	ValNoEvidence  = "no_evidence"
)

// CheckResult is one weakness class's applicability/outcome for a handler.
type CheckResult struct {
	Class  string `json:"class"`
	Status string `json:"status"` // done | n_a | unresolved
	Reason string `json:"reason,omitempty"`
}

// EvidenceRange is a cited source range with the harness's verdict on it.
type EvidenceRange struct {
	Path       string `json:"path"`
	Start      int    `json:"start"`
	End        int    `json:"end"`
	ReadByUnit bool   `json:"read_by_unit"`
	InSpan     bool   `json:"in_span"`
}

// DispositionValidation is the harness's verdict on a block.
type DispositionValidation struct {
	Scope    string `json:"scope"`    // ok | out_of_scope
	Revision string `json:"revision"` // ok | stale
	Evidence string `json:"evidence"` // ok | not_read | outside_span | no_evidence
	Identity string `json:"identity"` // ok | fabricated
}

// OK reports whether every axis validated.
func (v DispositionValidation) OK() bool {
	return v.Scope == ValOK && v.Revision == ValOK && v.Evidence == ValOK && v.Identity == ValOK
}

// HandlerDisposition is one parsed (and later validated) block.
type HandlerDisposition struct {
	RouteID    string                `json:"route_id"`
	UnitID     string                `json:"unit_id,omitempty"`
	Class      string                `json:"unit_class,omitempty"`
	Revision   string                `json:"revision,omitempty"`
	Checks     []CheckResult         `json:"checks"`
	Defenses   string                `json:"defenses,omitempty"`
	Evidence   []EvidenceRange       `json:"evidence"`
	Rationale  string                `json:"rationale,omitempty"`
	Unresolved []string              `json:"unresolved"`
	Validation DispositionValidation `json:"validation"`
}

var (
	reDispSection = regexp.MustCompile(`(?m)^##\s+Handler dispositions\s*$`)
	reDispField   = regexp.MustCompile(`^\s*-\s*\*\*([A-Za-z ]+)\*\*\s*:\s*(.*)$`)
	reCheck       = regexp.MustCompile(`^([A-Za-z0-9_-]+)\s*=\s*(done|n/?a|unresolved)\s*(?:\(([^)]*)\))?$`)
	reRange       = regexp.MustCompile(`^([^\s:]+):(\d+)(?:-(\d+))?$`)
)

// parseDispositions extracts the v2 section's blocks. Anything before the section
// (the candidate list) is ignored; a missing section yields nil (no dispositions).
func parseDispositions(md string) []HandlerDisposition {
	loc := reDispSection.FindStringIndex(md)
	if loc == nil {
		return nil
	}
	body := md[loc[1]:]
	if next := regexp.MustCompile(`(?m)^##\s`).FindStringIndex(body); next != nil {
		body = body[:next[0]]
	}
	var out []HandlerDisposition
	var cur *HandlerDisposition
	flush := func() {
		if cur != nil && cur.RouteID != "" {
			if cur.Checks == nil {
				cur.Checks = []CheckResult{}
			}
			if cur.Evidence == nil {
				cur.Evidence = []EvidenceRange{}
			}
			if cur.Unresolved == nil {
				cur.Unresolved = []string{}
			}
			out = append(out, *cur)
		}
		cur = nil
	}
	for _, ln := range strings.Split(body, "\n") {
		m := reDispField.FindStringSubmatch(ln)
		if m == nil {
			continue
		}
		key, val := strings.ToLower(strings.TrimSpace(m[1])), strings.TrimSpace(m[2])
		switch key {
		case "handler":
			flush()
			cur = &HandlerDisposition{RouteID: normalizeRouteID(val)}
		case "checks":
			if cur == nil {
				continue
			}
			for _, part := range strings.Split(val, ",") {
				part = strings.TrimSpace(part)
				if part == "" {
					continue
				}
				cm := reCheck.FindStringSubmatch(part)
				if cm == nil {
					cur.Checks = append(cur.Checks, CheckResult{Class: strings.ToUpper(part), Status: "malformed"})
					continue
				}
				status := strings.ToLower(cm[2])
				if status == "na" || status == "n/a" {
					status = CheckNA
				}
				cur.Checks = append(cur.Checks, CheckResult{Class: strings.ToUpper(cm[1]), Status: status, Reason: strings.TrimSpace(cm[3])})
			}
		case "defenses reviewed", "defenses":
			if cur != nil {
				cur.Defenses = val
			}
		case "evidence":
			if cur == nil {
				continue
			}
			for _, part := range strings.Split(val, ",") {
				part = strings.Trim(strings.TrimSpace(part), "`")
				rm := reRange.FindStringSubmatch(part)
				if rm == nil {
					continue
				}
				start, _ := strconv.Atoi(rm[2])
				end := start
				if rm[3] != "" {
					end, _ = strconv.Atoi(rm[3])
				}
				cur.Evidence = append(cur.Evidence, EvidenceRange{Path: rm[1], Start: start, End: end})
			}
		case "rationale":
			if cur != nil {
				cur.Rationale = val
			}
		case "unresolved":
			if cur != nil && val != "" && !strings.EqualFold(val, "none") {
				cur.Unresolved = append(cur.Unresolved, val)
			}
		}
	}
	flush()
	return out
}

// normalizeRouteID accepts "file:line METHOD PATH" and strips surrounding
// backticks/whitespace; it never corrects the content.
func normalizeRouteID(s string) string {
	return strings.TrimSpace(strings.Trim(strings.TrimSpace(s), "`"))
}

// readDispositions parses a written deliverable (empty when unreadable/absent).
func readDispositions(path string) []HandlerDisposition {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	return parseDispositions(string(b))
}

// validateDisposition checks one block against the unit that wrote it.
//   - identity: the route id must be a known inventory route
//   - scope:    the route must be assigned to the unit's partition
//   - revision: the unit ran at the current revision
//   - evidence: every cited range was READ by the unit and intersects the handler span
func validateDisposition(d *HandlerDisposition, u unitEvidence, assigned map[string]bool, routes map[string]inventory.Route,
	spans *handlerSpans, repo, unitRevision, currentRevision string) {
	d.UnitID, d.Class, d.Revision = u.label, u.class, unitRevision
	v := DispositionValidation{Scope: ValOK, Revision: ValOK, Evidence: ValOK, Identity: ValOK}
	r, known := routes[d.RouteID]
	if !known {
		v.Identity = ValFabricated
	}
	if known && !assigned[d.RouteID] {
		v.Scope = ValOutOfScope
	}
	if unitRevision != "" && currentRevision != "" && unitRevision != currentRevision {
		v.Revision = ValStale
	}
	if len(d.Evidence) == 0 {
		v.Evidence = ValNoEvidence
	}
	var sc scopeSpan
	if known {
		s := spans.scopeFor(r)
		sc = scopeSpan{found: s.Found, start: s.Start, end: s.End, file: r.File}
	}
	for i := range d.Evidence {
		e := &d.Evidence[i]
		for _, rd := range u.reads {
			if relFile(repo, rd.File) == e.Path && rangesIntersect(rd, e.Start, e.End) {
				e.ReadByUnit = true
				break
			}
		}
		if known && sc.found && e.Path == sc.file && e.End >= sc.start && e.Start <= sc.end {
			e.InSpan = true
		}
		if !e.ReadByUnit && v.Evidence == ValOK {
			v.Evidence = ValNotRead
		} else if e.ReadByUnit && !e.InSpan && v.Evidence == ValOK {
			v.Evidence = ValOutsideSpan
		}
	}
	d.Validation = v
}

type scopeSpan struct {
	found      bool
	start, end int
	file       string
}

// rangesIntersect: a ReadSpan (End 0 = EOF) intersects [start,end].
func rangesIntersect(rd agent.ReadSpan, start, end int) bool {
	rs := rd.Start
	if rs <= 0 {
		rs = 1
	}
	re := rd.End
	if re <= 0 {
		re = 1 << 30
	}
	return re >= start && rs <= end
}

// aggregateChecks decides a route's credit from its validated dispositions. For each
// planned class the verdict must come from the unit OF that class (or a follow-up
// unit, which reviews all classes); another class's "n/a" never speaks for it.
// Returns (credited, partial, per-class statuses, unresolved reasons).
func aggregateChecks(planned []string, ds []HandlerDisposition) (bool, bool, map[string]string, []string) {
	status := map[string]string{}
	var unresolved []string
	for _, d := range ds {
		if !d.Validation.OK() {
			continue
		}
		for _, c := range d.Checks {
			owns := d.Class == "FOLLOWUP" || strings.EqualFold(d.Class, c.Class)
			if !owns {
				continue
			}
			cls := strings.ToUpper(c.Class)
			switch c.Status {
			case CheckDone:
				status[cls] = CheckDone
			case CheckNA:
				if status[cls] != CheckDone {
					status[cls] = CheckNA
				}
			case CheckUnresolved:
				if status[cls] == "" {
					status[cls] = CheckUnresolved
				}
				if c.Reason != "" {
					unresolved = append(unresolved, cls+": "+c.Reason)
				} else {
					unresolved = append(unresolved, cls)
				}
			}
		}
	}
	if len(ds) == 0 {
		return false, false, status, nil
	}
	credited, any := true, false
	for _, p := range planned {
		s := status[strings.ToUpper(p)]
		if s == CheckDone || s == CheckNA {
			any = true
			continue
		}
		credited = false
	}
	sort.Strings(unresolved)
	return credited && len(planned) > 0, !credited && (any || len(unresolved) > 0), status, unresolved
}

// dispositionSummary formats the per-class statuses for a rationale.
func dispositionSummary(status map[string]string) string {
	keys := make([]string, 0, len(status))
	for k := range status {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s=%s", k, status[k]))
	}
	return strings.Join(parts, ", ")
}
