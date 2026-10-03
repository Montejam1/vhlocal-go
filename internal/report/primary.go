package report

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"vhlocal/internal/guidance"
)

// Feature 016 (FR-007, FR-008, FR-013; C-P11, C-P12, C-P15): primary-issue accounting.
//
// The reporting unit is one established defect group, or one supported finding where no
// established group exists. Every supported, non-dismissed finding is accounted for in
// exactly one primary issue: none is lost and none is counted twice. Unresolved and
// rejected members never gain support or severity through group membership, and no merge
// is ever inferred from a matching title, weakness or route. A group the record does not
// establish falls back to its separate findings with the reason recorded.
//
// Locations are deduplicated: three detections citing one line are one affected
// location with a citation count of three, never three locations.

// reIssueLocation splits a recorded "path:start[-end]" citation. Nothing here shifts,
// clamps or invents a citation; an unparsable value becomes an unavailable location.
var reIssueLocation = regexp.MustCompile(`^\s*([^\s:]+):(\d+)(?:\s*[-–‑—]\s*(\d+))?`)

// supportedFinding is one eligible member with the fields the projection needs.
type supportedFinding struct {
	id, stableID  string
	title         string
	severity      string
	cwe           string
	normalizedCWE string
	canonicalName string
	family        string
	location      string
	entryPoint    string
	evidence      []Evidence
	raw           map[string]any
}

// BuildPrimaryIssues projects the supported findings and the recorded groups onto the
// reader-facing reporting unit. It returns the issues in display order, most serious
// first with a stable tie order, and the per-severity counts over issues.
//
// Accounting, identity, severity and locations are established before any guidance is
// resolved, so a missing or changed guidance entry cannot alter which issues exist, how
// many there are, or how they are rated.
func BuildPrimaryIssues(in Input) ([]PrimaryIssue, map[string]int) {
	issues, counts, _ := buildPrimaryIssues(in)
	return issues, counts
}

// buildPrimaryIssues also returns the grouping notes: the recorded groups that were NOT
// used as a reporting unit, each with the reason. They are surfaced in Scan details so a
// reader who knows a group exists can see what became of it (FR-008, T062).
func buildPrimaryIssues(in Input) ([]PrimaryIssue, map[string]int, []string) {
	members := eligibleSupported(in)
	byID := make(map[string]*supportedFinding, len(members))
	for i := range members {
		byID[members[i].id] = &members[i]
	}

	// Established groups are reused as recorded. A group is usable only when it is
	// established and at least one of its members is an eligible supported finding.
	claimed := map[string]bool{}
	var issues []PrimaryIssue
	notes := []string{}
	for _, g := range in.Groups {
		if !groupIsEstablished(g) {
			notes = append(notes, fmt.Sprintf(
				"recorded group %s (status %q) was not used as one issue; its supported findings are reported separately",
				g.ID, orText(g.Status, "not recorded")))
			continue
		}
		var mem []*supportedFinding
		var roles []string
		for _, m := range g.Members {
			f, ok := byID[m.ID]
			if !ok || claimed[m.ID] {
				// A member that is not an eligible supported finding contributes nothing:
				// group membership never confers support (FR-008).
				continue
			}
			claimed[m.ID] = true
			mem = append(mem, f)
			roles = append(roles, m.Role)
		}
		if len(mem) == 0 {
			notes = append(notes, fmt.Sprintf(
				"recorded group %s produced no issue: every member is already reported under another group, or is not a supported detection",
				g.ID))
			continue
		}
		issues = append(issues, newPrimaryIssue(g.ID, g.Family, g.CanonicalName, mem, roles, in, ""))
	}

	// Anything still unclaimed is its own primary issue, visible exactly once. This is
	// both the no-group case and the fallback for a group the record did not establish.
	for i := range members {
		f := &members[i]
		if claimed[f.id] {
			continue
		}
		claimed[f.id] = true
		note := ""
		if gid := groupOfFinding(in, f.id); gid != "" {
			note = "recorded group " + gid + " was not established, so this finding is reported on its own"
		}
		issues = append(issues, newPrimaryIssue("", f.family, f.canonicalName, []*supportedFinding{f}, []string{"primary"}, in, note))
	}

	sortPrimaryIssues(issues)
	counts := EmptySeverityCounts()
	for i := range issues {
		issues[i].Ref = fmt.Sprintf("ISSUE-%03d", i+1)
		counts[issues[i].Severity]++
	}
	sort.Strings(notes)
	return issues, counts, notes
}

// eligibleSupported returns the supported, non-duplicate findings in recorded order.
func eligibleSupported(in Input) []supportedFinding {
	var out []supportedFinding
	for _, f := range in.Doc.Findings {
		if !isSupported(f) {
			continue
		}
		if dup, ok := f["duplicate_of"].(string); ok && strings.TrimSpace(dup) != "" {
			continue
		}
		sf := supportedFinding{
			id: str(f["id"]), stableID: str(f["stable_identity"]), title: str(f["title"]),
			severity: str(f["severity"]), cwe: str(f["cwe"]), normalizedCWE: str(f["normalized_cwe"]),
			canonicalName: str(f["canonical_name"]), family: str(f["cwe_family"]),
			location: str(f["location"]), entryPoint: str(f["entry_point"]), raw: f,
		}
		if sf.family == "" {
			sf.family = strings.ToLower(orText(sf.normalizedCWE, sf.cwe))
		}
		for _, e := range evidenceOf(f) {
			sf.evidence = append(sf.evidence, e)
		}
		out = append(out, sf)
	}
	return out
}

// groupIsEstablished reports whether a recorded group may be used as the reporting unit.
// A suggested or otherwise unestablished group never merges findings (FR-008, C-P12).
func groupIsEstablished(g Group) bool {
	return strings.EqualFold(strings.TrimSpace(g.Status), "established") && len(g.Members) > 0
}

// groupOfFinding returns the recorded group id naming this finding, if any.
func groupOfFinding(in Input, id string) string {
	for _, g := range in.Groups {
		for _, m := range g.Members {
			if m.ID == id {
				return g.ID
			}
		}
	}
	return ""
}

// newPrimaryIssue assembles one issue from its eligible members.
func newPrimaryIssue(groupID, family, canonical string, mem []*supportedFinding, roles []string, in Input, note string) PrimaryIssue {
	issue := PrimaryIssue{
		GroupID: groupID, Family: family, CanonicalName: canonical,
		DetectionCount: len(mem), GroupingNote: note,
		Members: []IssueMember{}, Locations: []AffectedLocation{},
		HowToCheckTheFix: []string{}, Evidence: []Evidence{},
	}
	recorded := make([]string, 0, len(mem))
	for i, f := range mem {
		role := "occurrence"
		if i < len(roles) && roles[i] != "" {
			role = roles[i]
		}
		if i == 0 {
			role = "primary"
		}
		issue.Members = append(issue.Members, IssueMember{
			FindingID: f.id, StableID: f.stableID, Role: role, EntryPoint: f.entryPoint, Severity: f.severity,
		})
		recorded = append(recorded, f.severity)
		issue.Evidence = append(issue.Evidence, f.evidence...)
	}
	issue.Severity, issue.OriginalSeverities = GroupSeverity(recorded)
	// Only show the originals when they differ from what is displayed; repeating "High"
	// under a High heading tells the reader nothing.
	if len(issue.OriginalSeverities) == 1 && issue.OriginalSeverities[0] == issue.Severity {
		issue.OriginalSeverities = nil
	}

	primary := mem[0]
	issue.Title = primary.title
	issue.CWE = orText(primary.normalizedCWE, primary.cwe)
	if issue.CanonicalName == "" {
		issue.CanonicalName = primary.canonicalName
	}
	issue.Locations = dedupeLocations(mem, in.GitCommit)
	issue.EntryPoints = distinctEntryPoints(mem)
	fillReaderSections(&issue, primary)
	return issue
}

// fillReaderSections builds the reader-facing sections of one issue from recorded fields
// and the reviewed guidance table (FR-011, FR-012, FR-014; T051, T052).
//
// Each section answers a different question, and no paragraph is placed under two headings
// (C-P17): what was found comes from the review's own reasoning, why it matters from the
// recorded impact, and how to fix it from guidance resolution. Where a recorded field is
// absent the gap is disclosed; nothing is invented to fill a heading.
func fillReaderSections(issue *PrimaryIssue, primary *supportedFinding) {
	f := primary.raw
	rec := guidanceFor(*issue, f)
	issue.HowToFixIt = RemediationRecommendation{
		Provenance: rec.Provenance, Steps: rec.Steps, Checks: rec.Checks,
		MissingDecision: rec.MissingDecision, Label: rec.Label,
		Mechanism: rec.Mechanism, RecordedNote: rec.RecordedNote,
	}
	issue.HowToCheckTheFix = append([]string{}, rec.Checks...)

	// What we found: the review's reasoning about this code, then its data flow. Both are
	// recorded text; neither is paraphrased here.
	issue.WhatWeFound = firstNonEmptyText(
		recField(f, "rationale"),
		str(f["data_flow"]),
		recField(f, "source_to_sink"),
	)
	if issue.WhatWeFound == "" {
		issue.WhatWeFound = whatWeFoundFallback(*issue, rec.Mechanism)
	}

	// Why it matters: the recorded security impact. Where the record has none, the reviewed
	// mechanism is stated and the gap is disclosed rather than filled with a guess.
	issue.WhyItMatters = recField(f, "security_impact")
	if sameParagraph(issue.WhyItMatters, issue.WhatWeFound) {
		issue.WhyItMatters = ""
	}
	if issue.WhyItMatters == "" {
		if rec.Mechanism != "" {
			issue.WhyItMatters = "The impact was not recorded for this issue. The weakness mechanism is that " +
				rec.Mechanism + "; assess the consequence against this application before scheduling the fix."
		} else {
			issue.WhyItMatters = "The impact was not recorded for this issue, and the weakness class is not one the guidance tables cover. Assess the consequence from the cited code."
		}
	}

	// Context that belongs beside the claim rather than in a technical appendix (C-P18).
	issue.AccessRequired = recField(f, "preconditions")
	issue.AttackerControl = recField(f, "attacker_control")
	issue.SafeguardsReviewed = recField(f, "defenses_reviewed")
	// Keep each of them out of the two prose sections to avoid a repeated paragraph.
	for _, p := range []*string{&issue.AccessRequired, &issue.AttackerControl, &issue.SafeguardsReviewed} {
		if sameParagraph(*p, issue.WhatWeFound) || sameParagraph(*p, issue.WhyItMatters) {
			*p = ""
		}
	}
}

// guidanceFor resolves the remediation for one issue from its recorded weakness and fix.
func guidanceFor(issue PrimaryIssue, f map[string]any) guidance.Recommendation {
	return guidance.Resolve(guidance.Request{
		Family:        issue.Family,
		CWE:           orText(issue.CWE, str(f["cwe"])),
		CanonicalName: issue.CanonicalName,
		RecordedFix:   str(f["fix"]),
	})
}

// whatWeFoundFallback states the recorded identity of the defect when the review recorded
// no reasoning text. It asserts nothing the record does not carry.
func whatWeFoundFallback(issue PrimaryIssue, mechanism string) string {
	what := orText(issue.CanonicalName, orText(issue.CWE, "a weakness"))
	where := "the affected code"
	for _, l := range issue.Locations {
		if l.Available {
			where = l.File
			if l.Lines != "" {
				where += ":" + l.Lines
			}
			break
		}
	}
	out := "The review recorded " + what + " at " + where + " without a written rationale."
	if mechanism != "" {
		out += " For this weakness class the defect is that " + mechanism + "."
	}
	return out
}

// recField reads a field from the verification record first, then the finding itself, the
// same precedence findingDetail uses, so an issue and its detections cite the same text.
func recField(f map[string]any, key string) string {
	if v := rec(f, key); strings.TrimSpace(v) != "" {
		return strings.TrimSpace(v)
	}
	return strings.TrimSpace(str(f[key]))
}

func firstNonEmptyText(vals ...string) string {
	for _, v := range vals {
		if s := strings.TrimSpace(v); s != "" {
			return s
		}
	}
	return ""
}

// sameParagraph reports whether two recorded texts say the same thing, so one of them can
// be dropped instead of appearing under two headings (C-P17).
func sameParagraph(a, b string) bool {
	na, nb := normalizeText(a), normalizeText(b)
	return na != "" && na == nb
}

func normalizeText(s string) string {
	return strings.Join(strings.Fields(strings.ToLower(strings.TrimSpace(s))), " ")
}

// dedupeLocations collapses repeated citations of one location into a single affected
// location carrying how many detections cited it (FR-013, C-P15).
func dedupeLocations(mem []*supportedFinding, revision string) []AffectedLocation {
	order := []string{}
	byKey := map[string]*AffectedLocation{}
	for _, f := range mem {
		file, lines, ok := splitIssueLocation(f.location)
		key := file + ":" + lines
		if !ok {
			// No usable citation: disclose the absence rather than inventing one.
			key = "\x00unavailable"
		}
		loc, seen := byKey[key]
		if !seen {
			loc = &AffectedLocation{File: file, Lines: lines, Available: ok, Revision: revision}
			if !ok {
				loc.File, loc.Lines = strings.TrimSpace(f.location), ""
			}
			byKey[key] = loc
			order = append(order, key)
		}
		loc.CitationCount++
		if loc.EntryPoint == "" {
			loc.EntryPoint = strings.TrimSpace(f.entryPoint)
		}
	}
	out := make([]AffectedLocation, 0, len(order))
	for _, k := range order {
		out = append(out, *byKey[k])
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Available != out[j].Available {
			return out[i].Available // usable citations first
		}
		if out[i].File != out[j].File {
			return out[i].File < out[j].File
		}
		return out[i].Lines < out[j].Lines
	})
	return out
}

// splitIssueLocation parses a recorded citation into its file and line range.
func splitIssueLocation(loc string) (file, lines string, ok bool) {
	m := reIssueLocation.FindStringSubmatch(loc)
	if m == nil {
		return "", "", false
	}
	lines = m[2]
	if m[3] != "" {
		lines = m[2] + "-" + m[3]
	}
	return m[1], lines, true
}

// distinctEntryPoints lists the recorded entry points once each, in recorded order.
func distinctEntryPoints(mem []*supportedFinding) []string {
	seen := map[string]bool{}
	var out []string
	for _, f := range mem {
		ep := strings.TrimSpace(f.entryPoint)
		if ep == "" || seen[ep] {
			continue
		}
		seen[ep] = true
		out = append(out, ep)
	}
	return out
}

// sortPrimaryIssues orders by displayed severity, then by detection count descending so
// a repeated defect outranks a one-off of the same severity, then by title and the first
// member id for a stable, reproducible order.
func sortPrimaryIssues(issues []PrimaryIssue) {
	sort.SliceStable(issues, func(i, j int) bool {
		ri, rj := SeverityRankOf(issues[i].Severity), SeverityRankOf(issues[j].Severity)
		if ri != rj {
			return ri < rj
		}
		if issues[i].DetectionCount != issues[j].DetectionCount {
			return issues[i].DetectionCount > issues[j].DetectionCount
		}
		if issues[i].Title != issues[j].Title {
			return issues[i].Title < issues[j].Title
		}
		return firstMemberID(issues[i]) < firstMemberID(issues[j])
	})
}

func firstMemberID(p PrimaryIssue) string {
	if len(p.Members) == 0 {
		return ""
	}
	return p.Members[0].FindingID
}

// BuildPriorityActions returns at most five rows, each a DIFFERENT primary issue, in
// the issues' own display order (FR-010, C-P21).
func BuildPriorityActions(issues []PrimaryIssue, limit int) []PriorityAction {
	out := []PriorityAction{}
	for _, p := range issues {
		if len(out) >= limit {
			break
		}
		out = append(out, PriorityAction{
			Ref: p.Ref, Issue: p.Title, Severity: p.Severity,
			AffectedArea: affectedArea(p), Action: primaryAction(p),
		})
	}
	return out
}

// affectedArea names where the issue lives, preferring the recorded entry point and
// falling back to the file. It never fabricates a component name.
func affectedArea(p PrimaryIssue) string {
	if len(p.EntryPoints) > 0 {
		return p.EntryPoints[0]
	}
	for _, l := range p.Locations {
		if l.Available {
			return l.File
		}
	}
	return "location not recorded"
}

// primaryAction is the concrete next action for a priority row. It is never the string
// "fix not provided" (FR-015, C-P24): with no resolved step it names the investigation.
func primaryAction(p PrimaryIssue) string {
	if len(p.HowToFixIt.Steps) > 0 {
		return p.HowToFixIt.Steps[0]
	}
	if p.HowToFixIt.MissingDecision != "" {
		return "Decide and then enforce: " + p.HowToFixIt.MissingDecision
	}
	return "Inspect the affected code and establish the required change"
}

// evidenceOf extracts the captured evidence from a finding's verification record,
// exactly as findingDetail does, so a primary issue and its detections cite the same
// ranges. Nothing is synthesised when the record holds none.
func evidenceOf(f map[string]any) []Evidence {
	vr, ok := f["verification_record"].(map[string]any)
	if !ok {
		return nil
	}
	var out []Evidence
	for _, e := range asSlice(vr["evidence"]) {
		em, _ := e.(map[string]any)
		if em == nil {
			continue
		}
		out = append(out, Evidence{
			Path: str(em["path"]), Start: toInt(em["start_line"]),
			End: toInt(em["end_line"]), Quote: str(em["quote"]),
		})
	}
	return out
}
