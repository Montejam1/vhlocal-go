package report

import (
	"fmt"
	"strings"
)

// Feature 016 (US1): the reader-facing Markdown document.
//
// Section order is fixed by FR-001: report identity, executive summary with severity
// totals and a compact scope note, up to five prioritized actions, the vulnerability
// index, issue details, Needs review, Scan details, and then the secondary sections —
// dismissed candidates and the technical diagnostics an operator needs.
//
// Everything here reads the persisted presentation projection, so this document, the
// standalone HTML, the three served pages and the React app cannot disagree. No model is
// consulted and no number is recomputed from prose.

// Markdown headings. Tests and the HTML renderer share these so the two surfaces cannot
// drift apart in naming.
const (
	secSummary     = "Summary"
	secPriority    = "Priority actions"
	secIssues      = "Issues to fix"
	secIssueDetail = "Issue details"
	secNeedsReview = "Needs review"
	secScanDetails = "Scan details"
	secDismissed   = "Dismissed candidates"
)

func renderMarkdownPresentation(in Input, m ReportModel) string {
	p := m.Presentation
	var b strings.Builder

	fmt.Fprintf(&b, "# Security Scan Report — %s\n\n", p.Identity.Application)
	b.WriteString(identityMarkdown(p.Identity))
	b.WriteString(incompleteNoteMarkdown(p.Scope))

	// 1. Executive summary: the bounded prose, then the totals as a table so the figures
	// do not compete with the sentences for the reader's attention (FR-002, FR-007).
	fmt.Fprintf(&b, "## %s\n\n", secSummary)
	b.WriteString(p.Opening.RiskSummary + "\n\n")
	if p.Opening.ScopeSentence != "" {
		b.WriteString(p.Opening.ScopeSentence + "\n\n")
	}
	b.WriteString(countsTableMarkdown(p.Counts))

	// 2. Priority actions: at most five different primary issues, each with a next step.
	fmt.Fprintf(&b, "## %s\n\n", secPriority)
	if len(p.Priority) == 0 {
		b.WriteString("_No established issue requires a fix. Needs review and Scan details record what remains open._\n\n")
	} else {
		b.WriteString("| # | Issue | Severity | Affected area | Next action |\n|---|---|---|---|---|\n")
		for i, a := range p.Priority {
			fmt.Fprintf(&b, "| %d | [%s](#%s) | %s | %s | %s |\n",
				i+1, mdCell(a.Issue), strings.ToLower(a.Ref), a.Severity, mdCell(a.AffectedArea), mdCell(a.Action))
		}
		b.WriteString("\n")
	}

	// 3. The vulnerability index: one row per primary issue, no internal identifier in
	// the title column (FR-010, C-P22).
	fmt.Fprintf(&b, "## %s\n\n", secIssues)
	if len(p.Issues) == 0 {
		b.WriteString("_None established in the reviewed code._\n\n")
	} else {
		b.WriteString("| # | Severity | Issue | Affected | Recommended action |\n|---|---|---|---|---|\n")
		for i, is := range p.Issues {
			fmt.Fprintf(&b, "| %d | %s | [%s](#%s) | %s | %s |\n",
				i+1, is.Severity, mdCell(is.Title), strings.ToLower(is.Ref), mdCell(affectedSummary(is)), mdCell(primaryAction(is)))
		}
		b.WriteString("\n")
	}

	// 4. Issue details: one section per primary issue, never one per detection.
	fmt.Fprintf(&b, "## %s\n\n", secIssueDetail)
	for _, is := range p.Issues {
		b.WriteString(issueDetailMarkdown(is))
	}

	// 5. Needs review: labelled separately and never counted as a vulnerability.
	b.WriteString(needsReviewMarkdown(m))

	// 6. Scan details: the operator-facing facts, including every count and diagnostic
	// moved out of the opening (FR-003).
	b.WriteString(scanDetailsMarkdown(in, m))

	// 7. Secondary: dismissed candidates, kept available with their recorded reason.
	b.WriteString(dismissedMarkdown(m))
	return b.String()
}

// identityMarkdown names what the report is about: the application, the scan date with
// its timezone, and the revision when the record carries one (FR-002, C-P2).
func identityMarkdown(id ReportIdentity) string {
	parts := []string{"**Application**: " + id.Application}
	if id.ScanDate != "" {
		when := id.ScanDate
		if id.Timezone != "" {
			when += " (" + id.Timezone + ")"
		}
		parts = append(parts, "**Scanned**: "+when)
	} else {
		parts = append(parts, "**Scanned**: date not recorded")
	}
	if id.Revision != "" {
		parts = append(parts, "**Revision**: "+shortRev(id.Revision))
	}
	return strings.Join(parts, " · ") + "\n\n"
}

// incompleteNoteMarkdown is the one-line honesty note for a run that did not complete.
// It replaces the feature-015 banner, which presented a candidate total as findings and
// led with phase troubleshooting (FR-003, SC-002, T030).
func incompleteNoteMarkdown(sc ScopeNote) string {
	if !scopeIsIncomplete(sc) {
		return ""
	}
	return "> ⚠ **This assessment is not exhaustive.** The results below cover the code that was reviewed; Scan details records what was not.\n\n"
}

// scopeIsIncomplete reports whether the recorded scope leaves the reader with something
// unassessed: execution short of complete, or coverage short of its own denominator.
func scopeIsIncomplete(sc ScopeNote) bool {
	if sc.Execution != "Complete" {
		return true
	}
	return sc.CoverageKnown && sc.CoverageComplete < sc.CoverageTotal
}

// countsTableMarkdown renders the reader-facing totals from ReportCounts only. Needs
// review and dismissed candidates are labelled and never added into the headline (FR-007,
// C-P6, C-P7).
func countsTableMarkdown(c ReportCounts) string {
	var b strings.Builder
	b.WriteString("| Measure | Count |\n|---|---:|\n")
	fmt.Fprintf(&b, "| **Issues to fix** | %d |\n", c.IssuesToFix)
	for _, s := range DisplaySeverities {
		fmt.Fprintf(&b, "| &nbsp;&nbsp;%s | %d |\n", s, c.Severity[s])
	}
	fmt.Fprintf(&b, "| Needs review (not counted as issues) | %d |\n", c.NeedsReview)
	fmt.Fprintf(&b, "| Dismissed candidates | %d |\n\n", c.Dismissed)
	return b.String()
}

// affectedSummary describes where an issue lives without multiplying one defect into
// several rows. Repeated citations of one location stay one location (FR-013, C-P15).
func affectedSummary(is PrimaryIssue) string {
	switch len(is.Locations) {
	case 0:
		return "location not recorded"
	case 1:
		l := is.Locations[0]
		s := locationText(l)
		if l.CitationCount > 1 {
			s += fmt.Sprintf(" (%d detections)", l.CitationCount)
		}
		return s
	default:
		return fmt.Sprintf("%d locations", len(is.Locations))
	}
}

func locationText(l AffectedLocation) string {
	if !l.Available {
		if strings.TrimSpace(l.File) == "" {
			return "location not recorded"
		}
		return l.File + " (citation not resolvable)"
	}
	if l.Lines == "" {
		return l.File
	}
	return l.File + ":" + l.Lines
}

// issueDetailMarkdown renders one primary issue. The anchors preserve every existing deep
// link: the issue reference, the recorded group id, and each backing detection id
// (FR-010, C-P22).
func issueDetailMarkdown(is PrimaryIssue) string {
	var b strings.Builder
	fmt.Fprintf(&b, "<a id=\"%s\"></a>\n", strings.ToLower(is.Ref))
	if is.GroupID != "" {
		fmt.Fprintf(&b, "<a id=\"group-%s\"></a>\n", is.GroupID)
	}
	for _, mem := range is.Members {
		fmt.Fprintf(&b, "<a id=\"finding-%s\"></a>\n", mem.FindingID)
	}
	// Header: severity, title and the stable reference a reader can cite (FR-011, C-P16).
	fmt.Fprintf(&b, "\n### %s — %s · %s\n\n", is.Severity, is.Title, is.Ref)

	// 1. What we found, with the context that belongs beside the claim (FR-012, C-P18).
	fmt.Fprintf(&b, "**What we found**\n\n%s\n\n", is.WhatWeFound)
	if is.CWE != "" || is.CanonicalName != "" {
		fmt.Fprintf(&b, "- **Weakness**: %s\n", weaknessText(is))
	}
	if is.AccessRequired != "" {
		fmt.Fprintf(&b, "- **Access required**: %s\n", is.AccessRequired)
	}
	if is.AttackerControl != "" {
		fmt.Fprintf(&b, "- **What an attacker controls**: %s\n", is.AttackerControl)
	}
	if is.SafeguardsReviewed != "" {
		fmt.Fprintf(&b, "- **Safeguards reviewed**: %s\n", is.SafeguardsReviewed)
	}
	if len(is.OriginalSeverities) > 0 {
		fmt.Fprintf(&b, "- **Recorded rating**: %s (shown as %s)\n", strings.Join(is.OriginalSeverities, ", "), is.Severity)
	}
	b.WriteString("\n")

	// 2. Why it matters.
	fmt.Fprintf(&b, "**Why it matters**\n\n%s\n\n", is.WhyItMatters)

	// 3. Where it is: one entry per deduplicated location (FR-013, C-P15).
	b.WriteString("**Where it is**\n\n")
	if len(is.Locations) == 0 {
		b.WriteString("- the affected location was not recorded\n")
	}
	for _, l := range is.Locations {
		line := "- `" + locationText(l) + "`"
		if l.CitationCount > 1 {
			line += fmt.Sprintf(" — cited by %d detections", l.CitationCount)
		}
		if l.EntryPoint != "" {
			line += " · reached through " + l.EntryPoint
		}
		b.WriteString(line + "\n")
	}
	if len(is.EntryPoints) > 0 {
		fmt.Fprintf(&b, "- **Entry points**: %s\n", strings.Join(is.EntryPoints, ", "))
	}
	b.WriteString("\n")

	// 4. How to fix it, with its provenance disclosed (FR-014, C-R2, C-R3).
	b.WriteString("**How to fix it**\n\n")
	if is.HowToFixIt.Label != "" {
		fmt.Fprintf(&b, "_%s_\n\n", is.HowToFixIt.Label)
	}
	for i, step := range is.HowToFixIt.Steps {
		fmt.Fprintf(&b, "%d. %s\n", i+1, step)
	}
	if is.HowToFixIt.MissingDecision != "" {
		fmt.Fprintf(&b, "\n- **Decision this needs from you**: %s\n", is.HowToFixIt.MissingDecision)
	}
	if is.HowToFixIt.RecordedNote != "" {
		fmt.Fprintf(&b, "\n- **Recorded recommendation, kept for reference**: %s\n", is.HowToFixIt.RecordedNote)
	}
	b.WriteString("\n")

	// 5. How to check the fix. These are suggestions; none has been run.
	b.WriteString("**How to check the fix**\n\n")
	if len(is.HowToCheckTheFix) == 0 {
		b.WriteString("- no check is suggested for this weakness class; decide one from the change you make\n")
	}
	for _, chk := range is.HowToCheckTheFix {
		fmt.Fprintf(&b, "- %s\n", chk)
	}
	b.WriteString("\n")

	// Optional detail: provenance and the captured evidence.
	b.WriteString("**Technical evidence**\n\n")
	fmt.Fprintf(&b, "- **Established by**: %s\n", detectionList(is))
	if is.GroupingNote != "" {
		fmt.Fprintf(&b, "- **Grouping**: %s\n", is.GroupingNote)
	}
	if len(is.Evidence) == 0 {
		b.WriteString("- **Captured evidence**: none recorded\n")
	} else {
		fmt.Fprintf(&b, "- **Captured evidence**: %d excerpt(s)\n\n", len(is.Evidence))
		for _, e := range is.Evidence {
			fmt.Fprintf(&b, "  `%s:%d-%d`\n\n", e.Path, e.Start, e.End)
			b.WriteString("  ```\n")
			for _, ln := range strings.Split(strings.TrimRight(e.Quote, "\n"), "\n") {
				b.WriteString("  " + strings.ReplaceAll(ln, "```", "` ` `") + "\n")
			}
			b.WriteString("  ```\n\n")
		}
	}
	b.WriteString("\n")
	return b.String()
}

// weaknessText names the weakness in reader-facing words, with the recorded CWE beside it.
func weaknessText(is PrimaryIssue) string {
	name := strings.TrimSpace(is.CanonicalName)
	if name == "" {
		name = "weakness class not named in the records"
	}
	if c := bracket(is.CWE); c != "" {
		return name + " " + c
	}
	return name
}

// detectionList names the backing detections so every original identity stays traceable,
// without letting those identifiers dominate the reader-facing columns.
func detectionList(is PrimaryIssue) string {
	parts := make([]string, 0, len(is.Members))
	for _, mem := range is.Members {
		s := mem.FindingID
		if mem.Severity != "" && mem.Severity != is.Severity {
			s += " (recorded " + mem.Severity + ")"
		}
		parts = append(parts, s)
	}
	out := strings.Join(parts, ", ")
	if is.GroupID != "" {
		out += " · recorded group " + is.GroupID
	}
	return out
}

func bracket(s string) string {
	if strings.TrimSpace(s) == "" {
		return ""
	}
	return "(" + s + ")"
}

// needsReviewMarkdown lists the allegations whose assessment is inconclusive or
// unfinished. They are labelled separately, never counted as vulnerabilities, any proposed
// severity is marked provisional, and the long failure explanations stay in Scan details
// (FR-017, C-C1, C-C2).
func needsReviewMarkdown(m ReportModel) string {
	p := m.Presentation
	var b strings.Builder
	fmt.Fprintf(&b, "## %s\n\n", secNeedsReview)
	if len(p.ReviewItems) == 0 {
		b.WriteString("_Nothing is awaiting review for this scan._\n\n")
		return b.String()
	}
	fmt.Fprintf(&b, "_%s could not be settled either way: neither confirmed nor dismissed. None is counted among the issues to fix, and none carries an assessed severity._\n\n",
		plural(len(p.ReviewItems), "item", "items"))

	writeGroup := func(kind, heading, note string) {
		var rows []ReviewItem
		for _, it := range p.ReviewItems {
			if it.Kind == kind {
				rows = append(rows, it)
			}
		}
		if len(rows) == 0 {
			return
		}
		fmt.Fprintf(&b, "**%s** — %s\n\n", heading, note)
		for _, it := range rows {
			fmt.Fprintf(&b, "- **%s** — %s", it.Title, it.WhatIsUnresolved)
			if it.Location != "" {
				fmt.Fprintf(&b, " · location: `%s`", it.Location)
			}
			if it.ProvisionalSeverity != "" {
				fmt.Fprintf(&b, " · severity proposed, not established: %s", it.ProvisionalSeverity)
			}
			fmt.Fprintf(&b, " · next step: %s", it.NextStep)
			if it.DiagnosticsRef != "" {
				fmt.Fprintf(&b, " · diagnostics: %s", it.DiagnosticsRef)
			}
			b.WriteString("\n")
		}
		b.WriteString("\n")
	}
	writeGroup(ReviewInconclusive, "Inconclusive", "examined, with no decision either way")
	writeGroup(ReviewIncomplete, "Assessment not completed", "the review stopped before reaching a decision")
	return b.String()
}

// dismissedMarkdown keeps every dismissed candidate available with the reason and the
// decision recorded at the time. Presentation never alters a recorded decision
// (FR-018, C-C3).
func dismissedMarkdown(m ReportModel) string {
	p := m.Presentation
	var b strings.Builder
	fmt.Fprintf(&b, "## %s\n\n", secDismissed)
	b.WriteString("_Examined and refuted. Kept here with the reason recorded at the time; a dismissal is never re-decided by the report._\n\n")
	if len(p.Dismissed) == 0 {
		b.WriteString("_None._\n\n")
		return b.String()
	}
	for _, d := range p.Dismissed {
		fmt.Fprintf(&b, "- **%s**", d.Title)
		if d.Location != "" {
			fmt.Fprintf(&b, " (`%s`)", d.Location)
		}
		fmt.Fprintf(&b, " — %s · recorded decision: %s\n", d.Reason, d.Decision)
	}
	b.WriteString("\n")
	return b.String()
}

// scanDetailsMarkdown is the operator section. Every count, phase fact, token figure,
// turn figure and verification failure category lives here rather than in the opening
// (FR-003, T027).
func scanDetailsMarkdown(in Input, m ReportModel) string {
	p := m.Presentation
	rs := in.Doc.RunStatus
	var b strings.Builder
	fmt.Fprintf(&b, "## %s\n\n", secScanDetails)
	b.WriteString("_Scanner troubleshooting and provenance. Nothing here changes the issue counts above._\n\n")

	b.WriteString("### Scan summary\n\n")
	fmt.Fprintf(&b, "- **Target**: %s\n- **Model**: %s\n- **Inference endpoint**: %s\n", in.Target, orNR(in.Model), orNR(redactEndpoint(in.Host)))
	if m.Target.Revision != "" {
		fmt.Fprintf(&b, "- **Revision**: %s", m.Target.Revision)
		if m.Target.Branch != "" {
			fmt.Fprintf(&b, " (%s)", m.Target.Branch)
		}
		b.WriteString("\n")
	}
	fmt.Fprintf(&b, "- **Started**: %s\n- **Finished**: %s\n- **Duration**: %s\n", orNR(in.StartedAt), orNR(in.FinishedAt), orNR(in.Duration))
	if pl := partitionLine(in.Doc.Meta); pl != "" {
		b.WriteString("- " + pl + "\n")
	}
	b.WriteString("\n")

	b.WriteString("### Run status (three independent axes)\n\n")
	fmt.Fprintf(&b, "- **Execution**: %s\n", p.Scope.Execution)
	fmt.Fprintf(&b, "- **Coverage**: %s\n", orNR(rs.CoverageStatus))
	if len(rs.CoverageDegradedReasons) > 0 {
		for _, r := range rs.CoverageDegradedReasons {
			fmt.Fprintf(&b, "  - %s\n", r)
		}
	}
	fmt.Fprintf(&b, "- **Assessment method**: %s\n", p.Scope.Method)
	b.WriteString("\n_The raw recorded values are under Technical diagnostics._\n\n")

	b.WriteString("### Accounting\n\n")
	c := p.Counts
	fmt.Fprintf(&b, "- **Candidates examined**: %d — allegations the scan looked at; not a count of established defects\n", c.CandidatesExamined)
	fmt.Fprintf(&b, "- **Supported detections**: %d — individual detections that survived review; one defect cited in several places is still one issue\n", c.Detections)
	fmt.Fprintf(&b, "- **Issues to fix**: %d — the established defects reported above\n", c.IssuesToFix)
	fmt.Fprintf(&b, "- **Needs review**: %d — %d inconclusive, %d where review did not finish\n", c.NeedsReview, c.NeedsInconclusive, c.NeedsIncomplete)
	fmt.Fprintf(&b, "- **Dismissed**: %d\n", c.Dismissed)
	if m.Counts.Duplicates > 0 {
		fmt.Fprintf(&b, "- **Duplicate detections folded**: %d\n", m.Counts.Duplicates)
	}
	b.WriteString("\n")

	// Grouping: what became of a recorded group that is not a reporting unit (FR-008).
	if len(p.GroupingNotes) > 0 {
		b.WriteString("### Grouping\n\n_Recorded remediation groups that are not one of the issues above, and why._\n\n")
		for _, n := range p.GroupingNotes {
			fmt.Fprintf(&b, "- %s\n", n)
		}
		b.WriteString("\n")
	}

	b.WriteString(sourceReviewMarkdown(m))
	b.WriteString(reviewCoverageMarkdown(in))

	b.WriteString("### Scope and limitations\n\n")
	if !in.CodeExecuted {
		b.WriteString("- The target's code was **never executed**; issues are established by reading the source, not by running an exploit.\n")
	}
	if !in.VerifyModelUsed {
		b.WriteString("- Falsification ran on the **same model** that produced the candidates (no `--verify-model`).\n")
	}
	b.WriteString("- No network egress occurred beyond the configured inference endpoint.\n\n")

	// Technical diagnostics (FR-019, C-C4, C-C5): everything an operator needs to
	// troubleshoot the scanner, and nothing a reader needs to fix the application. It is
	// collapsed in the interactive view and left out of the default print body.
	b.WriteString("### Technical diagnostics\n\n")
	b.WriteString("_Scanner troubleshooting only. Nothing below changes a count, a severity or a decision above._\n\n")
	b.WriteString(recordedStatusMarkdown(in, m))
	b.WriteString(providerMarkdown(in, m))
	b.WriteString(configurationMarkdown(in))
	b.WriteString(failuresMarkdown(in))
	if m.DiagramSummary != "" {
		fmt.Fprintf(&b, "#### Threat model diagram\n\n- **Validation** ([threat_model_diagram.json](threat_model_diagram.json)): %s\n\n", m.DiagramSummary)
	}
	b.WriteString(completionMarkdown(in))

	// Unfinished verification sessions: the failure class, operation and message, once.
	if len(m.Appendix.UnresolvedFailed) > 0 {
		b.WriteString("#### Unfinished verification sessions\n\n")
		b.WriteString("_Each row is an assessment that did not reach a decision. The matching reader-facing entries are under Needs review._\n\n")
		for _, r := range m.Appendix.UnresolvedFailed {
			fmt.Fprintf(&b, "- **%s** — %s (`%s`) · [%s] operation: %s; code: %s · %s\n",
				r.ID, r.Title, r.Location, orText(r.Class, "unknown"), orText(r.Operation, "unknown"), orText(r.Code, "not recorded"), r.Message)
		}
		b.WriteString("\n")
	}

	b.WriteString(executionMarkdown(in, m))
	if len(in.Nav) > 0 {
		b.WriteString("### Related documents\n\n")
		for _, n := range in.Nav {
			fmt.Fprintf(&b, "- [%s](%s)\n", n.Label, n.Path)
		}
		b.WriteString("\n")
	}
	fmt.Fprintf(&b, "Artifact records: `%s`. Evidence records: `%s`, `%s`, `%s`.\n",
		m.Appendix.ArtifactsRef, m.Refs["review_units"], m.Refs["hunt_execution"], m.Refs["sessions"])
	return b.String()
}

// recordedStatusMarkdown prints the raw recorded axis values, which are internal
// vocabulary and therefore belong to the technical details (FR-019, C-P19).
func recordedStatusMarkdown(in Input, m ReportModel) string {
	rs := in.Doc.RunStatus
	var b strings.Builder
	b.WriteString("#### Recorded statuses\n\n")
	fmt.Fprintf(&b, "- **execution_status**: recorded as `%s`\n", orNR(rs.ExecutionStatus))
	fmt.Fprintf(&b, "- **coverage_status**: recorded as `%s`\n", orNR(rs.CoverageStatus))
	fmt.Fprintf(&b, "- **validation_mode**: recorded as `%s`\n", orNR(rs.ValidationMode))
	fmt.Fprintf(&b, "- **coverage semantics**: %s\n", orNR(m.CoverageSemanticsLabel))
	if len(rs.CoverageDegradedReasons) > 0 {
		fmt.Fprintf(&b, "- **coverage_degraded_reasons**: %s\n", strings.Join(rs.CoverageDegradedReasons, "; "))
	}
	b.WriteString("\n")
	return b.String()
}

// providerMarkdown records which provider, model and endpoint produced the scan. The
// endpoint is redacted: a credential embedded in the URL is never written to a report
// (FR-019, C-C5, and the constitution's rule that credentials are never persisted).
func providerMarkdown(in Input, m ReportModel) string {
	var b strings.Builder
	b.WriteString("#### Provider and model\n\n")
	fmt.Fprintf(&b, "- **Model**: %s\n", orNR(in.Model))
	fmt.Fprintf(&b, "- **Inference endpoint**: %s\n", orNR(redactEndpoint(in.Host)))
	fmt.Fprintf(&b, "- **Credentials**: never recorded in a report; any credential in the endpoint URL is redacted here\n")
	fmt.Fprintf(&b, "- **Falsification model**: %s\n", verifyModelText(in))
	b.WriteString("\n")
	return b.String()
}

// configurationMarkdown records the run configuration that changes what a scan can find.
func configurationMarkdown(in Input) string {
	var b strings.Builder
	b.WriteString("#### Configuration\n\n")
	fmt.Fprintf(&b, "- **Code execution**: %s\n", codeExecutionText(in.CodeExecuted))
	fmt.Fprintf(&b, "- **Separate falsification model**: %s\n", yesNo(in.VerifyModelUsed))
	if pl := partitionLine(in.Doc.Meta); pl != "" {
		b.WriteString("- " + pl + "\n")
	}
	if phases := metaList(in.Doc.Meta, "phases_requested"); len(phases) > 0 {
		fmt.Fprintf(&b, "- **Phases requested**: %s\n", strings.Join(phases, ", "))
	}
	if phases := metaList(in.Doc.Meta, "phases_completed"); len(phases) > 0 {
		fmt.Fprintf(&b, "- **Phases completed**: %s\n", strings.Join(phases, ", "))
	}
	b.WriteString("\n")
	return b.String()
}

// redactEndpoint removes any userinfo from a recorded endpoint URL, keeping the host so an
// operator can still see where the scan ran.
func redactEndpoint(host string) string {
	h := strings.TrimSpace(host)
	if h == "" {
		return ""
	}
	scheme := ""
	rest := h
	if i := strings.Index(h, "://"); i >= 0 {
		scheme, rest = h[:i+3], h[i+3:]
	}
	if at := strings.LastIndex(rest, "@"); at >= 0 {
		rest = rest[at+1:]
		return scheme + "[credential redacted]@" + rest
	}
	return scheme + rest
}

func verifyModelText(in Input) string {
	if in.VerifyModelUsed {
		return "a separate model was used for falsification"
	}
	return "none; falsification ran on the model that produced the candidates"
}

func codeExecutionText(enabled bool) string {
	if enabled {
		return "enabled for the scanner's own tooling; the target application was still never executed"
	}
	return "disabled"
}

// metaList reads a recorded list of strings from scan metadata.
func metaList(meta map[string]any, key string) []string {
	var out []string
	for _, v := range asSlice(meta[key]) {
		if s, ok := v.(string); ok && s != "" {
			out = append(out, s)
		}
	}
	return out
}

// executionMarkdown renders the per-phase and per-agent tables, including the token and
// turn figures that no longer appear in the opening.
func executionMarkdown(in Input, m ReportModel) string {
	var b strings.Builder
	if len(m.Appendix.Phases) == 0 && len(phaseOutcomes(in)) == 0 {
		return ""
	}
	b.WriteString("#### Execution\n\n")
	if len(m.Appendix.Phases) > 0 {
		b.WriteString("| Phase | Agents | Turns | Stop reasons | Produced | Prompt tok | Completion tok |\n|---|---|---|---|---|---|---|\n")
		for _, p := range m.Appendix.Phases {
			fmt.Fprintf(&b, "| %s | %d | %d | %s | %s | %d | %d |\n", p.Phase, p.Agents, p.Turns, stopsText(p.Stops), yesNo(p.Produced), p.PromptTokens, p.CompletionTokens)
		}
		b.WriteString("\n")
	}
	if outcomes := phaseOutcomes(in); len(outcomes) > 0 {
		fmt.Fprintf(&b, "#### Per-phase outcome (per agent; also in `%s`)\n\n", m.Appendix.AgentsRef)
		b.WriteString("| Phase | Agent | Turns | Stop reason | Produced | Prompt tok | Completion tok |\n|---|---|---|---|---|---|---|\n")
		for _, o := range outcomes {
			fmt.Fprintf(&b, "| %s | %s | %d | %s | %s | %d | %d |\n", o.Phase, o.Label, o.Turns, o.Stop, yesNo(o.Produced), o.PT, o.CT)
		}
		b.WriteString("\n")
	}
	return b.String()
}

func yesNo(v bool) string {
	if v {
		return "yes"
	}
	return "no"
}
