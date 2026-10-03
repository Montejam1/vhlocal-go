package report

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// RenderMarkdown produces SCAN_REPORT.md from the report model (feature 015,
// C-A6 order): executive summary → outcome metrics → findings index → findings →
// coverage and limitations → candidate appendix → execution appendix.
func RenderMarkdown(in Input) string {
	m := BuildModel(in)
	return renderMarkdownModel(in, m)
}

// renderMarkdownModel renders the reader-facing document from the presentation
// projection (feature 016). A model saved before that feature carries no projection and
// renders through the unchanged legacy path, so an old report still reads as it did
// (FR-026, C-C7).
func renderMarkdownModel(in Input, m ReportModel) string {
	if m.Presentation != nil {
		return renderMarkdownPresentation(in, m)
	}
	return renderMarkdownLegacy(in, m)
}

func renderMarkdownLegacy(in Input, m ReportModel) string {
	var b strings.Builder
	rs := in.Doc.RunStatus
	fmt.Fprintf(&b, "# Security Scan Report — %s\n\n", in.Target)

	// One-line run-status warning (FR-012/FR-004): reasons live once, under
	// Coverage and limitations.
	if !isCleanRun(in) {
		fmt.Fprintf(&b, "> ⚠ **Incomplete run.** %s (%d coverage reason(s) — see Coverage and limitations.)\n\n",
			brokenBanner(in), len(rs.CoverageDegradedReasons))
	}

	// 1. Executive summary.
	b.WriteString("## Executive summary\n\n")
	b.WriteString(m.Summary.Narrative + "\n\n")
	if len(m.Summary.Leading) > 0 {
		b.WriteString("**Leading issues**\n\n")
		for i, l := range m.Summary.Leading {
			fmt.Fprintf(&b, "%d. [%s](#%s) — %s · %s · %s\n", i+1, l.Title, l.Ref, l.Severity, l.Surface, l.Action)
		}
		fmt.Fprintf(&b, "\n_Complete list: [Findings index](#findings-index) (%d supported)._\n\n", m.Counts.Supported)
	}
	if len(m.Summary.Limitations) > 0 {
		b.WriteString("**Material limitations**\n\n")
		for _, l := range m.Summary.Limitations {
			fmt.Fprintf(&b, "- %s\n", l)
		}
		b.WriteString("\n")
	}

	// 2. Outcome metrics — every count labelled, from the model only.
	b.WriteString("## Outcome metrics\n\n")
	c := m.Counts
	fmt.Fprintf(&b, "- **Supported findings (raw)**: %d\n", c.Supported)
	fmt.Fprintf(&b, "- **Remediation groups (grouped)**: %d — one actionable fix per group; occurrences keep their own evidence\n", c.RemediationGroups)
	fmt.Fprintf(&b, "- **Rejected candidates**: %d\n", c.Rejected)
	fmt.Fprintf(&b, "- **Unresolved candidates**: %d — %d explicit verifier decisions, %d failed verification sessions\n", c.UnresolvedExplicit+c.UnresolvedFailed, c.UnresolvedExplicit, c.UnresolvedFailed)
	fmt.Fprintf(&b, "- **Total candidates**: %d — a candidate total is not a confirmed-vulnerability count.\n", c.TotalCandidates)
	if c.Duplicates > 0 {
		fmt.Fprintf(&b, "- **Duplicate detections folded**: %d\n", c.Duplicates)
	}
	fmt.Fprintf(&b, "- **Execution**: %s\n- **Coverage**: %s\n", orText(m.Status.Execution, "unknown"), orText(m.Status.Coverage, "unknown"))
	if c.SourceReview.Total > 0 {
		fmt.Fprintf(&b, "- **Source review**: %d of %d entry points completed (%s)\n", c.SourceReview.Completed, c.SourceReview.Total, orText(m.CoverageSemanticsLabel, "coverage semantics unknown"))
	} else {
		b.WriteString("- **Source review**: no entry-point inventory for this run\n")
	}
	fmt.Fprintf(&b, "- **Validation mode**: %s\n", orText(m.Status.ValidationMode, "unknown"))
	if pl := partitionLine(in.Doc.Meta); pl != "" {
		b.WriteString("- " + pl + "\n")
	}
	b.WriteString("\n**Supported findings by severity**\n\n")
	writeSeverityList(&b, m.SeveritySupported, true)
	b.WriteString("\n**Candidates by severity (all statuses — not vulnerabilities)**\n\n")
	writeSeverityList(&b, m.SeverityCandidates, false)
	if len(in.Nav) > 0 {
		b.WriteString("\n### Navigation\n\n")
		for _, n := range in.Nav {
			fmt.Fprintf(&b, "- [%s](%s)\n", n.Label, n.Path)
		}
	}
	b.WriteString("\n")

	// 3. Findings index.
	b.WriteString("## Findings index\n\n")
	if len(m.Index) == 0 {
		b.WriteString("_No supported findings._\n\n")
	} else {
		if len(m.Groups) > 0 {
			fmt.Fprintf(&b, "_%d supported finding(s) (raw) in %d remediation group(s). Groups are listed primary first; ↳ marks an occurrence of the same defect with its own evidence._\n\n", m.Counts.Supported, m.Counts.RemediationGroups)
		}
		b.WriteString("| # | Finding | Severity | Surface | Evidence | Action |\n|---|---|---|---|---|---|\n")
		for i, row := range m.Index {
			grp, mark := "", ""
			if row.GroupID != "" {
				grp = " · " + row.GroupID
				switch row.Role {
				case "primary":
					if row.GroupSize > 1 {
						grp += fmt.Sprintf(" (%d occurrences)", row.GroupSize)
					}
					mark = fmt.Sprintf("<a id=\"group-%s\"></a>", row.GroupID)
				case "occurrence":
					mark = "↳ "
				}
			}
			fmt.Fprintf(&b, "| %d | %s[%s](#%s) — %s%s | %s | %s | %s | %s |\n", i+1, mark, row.ID, row.Anchor, mdCell(row.Title), grp, row.Severity, mdCell(row.Surface), row.EvidenceStatus, mdCell(orText(row.Action, "fix not provided")))
		}
		b.WriteString("\n")
	}

	// 4. Findings — one ### per supported finding.
	b.WriteString("## Findings\n\n")
	if len(m.Findings) == 0 {
		b.WriteString("_No findings were verified as supported._ Rejected and unresolved candidates are listed in Appendix A.\n\n")
	} else {
		fmt.Fprintf(&b, "_%d supported finding(s), each verified by source-grounded review. Rejected and unresolved candidates are listed in Appendix A._\n\n", len(m.Findings))
	}
	for _, f := range m.Findings {
		fmt.Fprintf(&b, "<a id=\"finding-%s\"></a>\n\n### %s — %s (%s)\n\n", f.ID, f.ID, f.Title, f.Severity)
		if f.GroupID != "" {
			fmt.Fprintf(&b, "- **Remediation group**: %s\n", f.GroupID)
		}
		fmt.Fprintf(&b, "- **CWE**: %s", orNR(f.CWE))
		if f.NormalizedCWE != "" && f.NormalizedCWE != f.CWE {
			fmt.Fprintf(&b, " (normalized %s — %s)", f.NormalizedCWE, f.CanonicalName)
		}
		b.WriteString("\n")
		fmt.Fprintf(&b, "- **Location**: %s\n- **Entry point**: %s\n", f.Location, orNR(f.EntryPoint))
		fmt.Fprintf(&b, "- **Impact**: %s\n- **Attacker prerequisites**: %s\n- **Attacker control**: %s\n", orNR(f.Impact), orNR(f.Prerequisites), orNR(f.AttackerControl))
		fmt.Fprintf(&b, "- **Source-to-sink reasoning**: %s\n- **Reviewed defenses**: %s\n- **Rationale**: %s\n", orNR(f.SourceToSink), orNR(f.Defenses), orNR(f.Rationale))
		if len(f.Evidence) == 0 {
			b.WriteString("- **Captured evidence**: none (not verified)\n")
		} else {
			fmt.Fprintf(&b, "- **Captured evidence**: %d excerpt(s)\n\n", len(f.Evidence))
			for _, e := range f.Evidence {
				fmt.Fprintf(&b, "  `%s:%d-%d`\n\n", e.Path, e.Start, e.End)
				b.WriteString("  ```\n")
				for _, ln := range strings.Split(strings.TrimRight(e.Quote, "\n"), "\n") {
					b.WriteString("  " + strings.ReplaceAll(ln, "```", "` ` `") + "\n")
				}
				b.WriteString("  ```\n\n")
			}
		}
		if strings.TrimSpace(f.Fix) == "" {
			b.WriteString("- **Recommended fix**: not provided\n")
		} else {
			fmt.Fprintf(&b, "- **Recommended fix**: %s\n", f.Fix)
		}
		fmt.Fprintf(&b, "- **Reproduction**: %s\n", in.reproLine(f.ID))
		fmt.Fprintf(&b, "- **Classification**: %s\n\n", orNR(f.Classification))
	}

	// 5. Coverage and limitations (scan facts, axes, 014 completion block, review coverage, scope).
	b.WriteString("## Coverage and limitations\n\n")
	b.WriteString("### Scan summary\n\n")
	fmt.Fprintf(&b, "- **Target**: %s\n- **Model**: %s\n- **Host**: %s\n", in.Target, in.Model, redactEndpoint(in.Host))
	if m.Target.Revision != "" {
		fmt.Fprintf(&b, "- **Revision**: %s", m.Target.Revision)
		if m.Target.Branch != "" {
			fmt.Fprintf(&b, " (%s)", m.Target.Branch)
		}
		b.WriteString("\n")
	}
	fmt.Fprintf(&b, "- **Started**: %s\n- **Finished**: %s\n- **Duration**: %s\n\n", in.StartedAt, in.FinishedAt, in.Duration)
	b.WriteString("### Run status (three axes)\n\n")
	fmt.Fprintf(&b, "- **Execution**: %s\n- **Coverage**: %s\n", rs.ExecutionStatus, rs.CoverageStatus)
	if len(rs.CoverageDegradedReasons) > 0 {
		fmt.Fprintf(&b, "  - degraded: %s\n", strings.Join(rs.CoverageDegradedReasons, "; "))
	}
	fmt.Fprintf(&b, "- **Validation mode**: %s\n\n", rs.ValidationMode)
	b.WriteString(sourceReviewMarkdown(m))
	b.WriteString(failuresMarkdown(in))
	if m.DiagramSummary != "" {
		fmt.Fprintf(&b, "### Threat model diagram\n\n- **Validation** ([threat_model_diagram.json](threat_model_diagram.json)): %s\n\n", m.DiagramSummary)
	}
	b.WriteString(completionMarkdown(in))
	b.WriteString(reviewCoverageMarkdown(in))
	b.WriteString("### Scope and limitations\n\n")
	if !in.CodeExecuted {
		b.WriteString("- The target's code was **never executed**; findings are confirmed by reasoning, not by execution. Exploit tests, if written, were not run.\n")
	}
	if !in.VerifyModelUsed {
		b.WriteString("- Falsification (Phase 2b) ran on the **same model** that produced the candidates (no `--verify-model`).\n")
	}
	b.WriteString("- No network egress occurred beyond the configured inference endpoint.\n\n")

	// 6. Appendix A — candidates that are not findings, each with reason and action.
	b.WriteString("## Appendix A — Candidates\n\n")
	b.WriteString("### Rejected candidates\n\n_Reviewed and refuted — not vulnerabilities._\n\n")
	if len(m.Appendix.Rejected) == 0 {
		b.WriteString("_None._\n\n")
	}
	for _, r := range m.Appendix.Rejected {
		fmt.Fprintf(&b, "- **%s** — %s (%s) · %s · action: %s\n", r.ID, r.Title, r.Location, r.Reason, r.Action)
	}
	if len(m.Appendix.Rejected) > 0 {
		b.WriteString("\n")
	}
	b.WriteString("### Unresolved (explicit decision)\n\n_The verifier examined these and submitted `unresolved`: evidence of uncertainty, not confirmation._\n\n")
	if len(m.Appendix.UnresolvedExplicit) == 0 {
		b.WriteString("_None._\n\n")
	}
	for _, r := range m.Appendix.UnresolvedExplicit {
		fmt.Fprintf(&b, "- **%s** — %s (%s) · %s · action: %s\n", r.ID, r.Title, r.Location, r.Reason, r.Action)
	}
	if len(m.Appendix.UnresolvedExplicit) > 0 {
		b.WriteString("\n")
	}
	b.WriteString("### Unresolved (session failed)\n\n_No decision was recorded: the verification session failed. Investigate the failure class before treating these as noise._\n\n")
	if len(m.Appendix.UnresolvedFailed) == 0 {
		b.WriteString("_None._\n\n")
	}
	for _, r := range m.Appendix.UnresolvedFailed {
		cls := r.Class
		if cls == "" {
			cls = "unknown"
		}
		fmt.Fprintf(&b, "- **%s** — %s (%s) · [%s] operation: %s; code: %s · %s\n", r.ID, r.Title, r.Location, cls, orText(r.Operation, "unknown"), orText(r.Code, "not recorded"), r.Message)
	}
	if len(m.Appendix.UnresolvedFailed) > 0 {
		b.WriteString("\n")
	}

	// 7. Appendix B — execution: per-phase summary, per-agent rows (on demand in
	// HTML; here at the very end).
	b.WriteString("## Appendix B — Execution\n\n")
	if len(m.Appendix.Phases) > 0 {
		b.WriteString("### Phases\n\n| Phase | Agents | Turns | Stop reasons | Produced | Prompt tok | Completion tok |\n|---|---|---|---|---|---|---|\n")
		for _, p := range m.Appendix.Phases {
			prod := "no"
			if p.Produced {
				prod = "yes"
			}
			fmt.Fprintf(&b, "| %s | %d | %d | %s | %s | %d | %d |\n", p.Phase, p.Agents, p.Turns, stopsText(p.Stops), prod, p.PromptTokens, p.CompletionTokens)
		}
		b.WriteString("\n")
	}
	if outcomes := phaseOutcomes(in); len(outcomes) > 0 {
		fmt.Fprintf(&b, "### Per-phase outcome (per agent; also in `%s`)\n\n", m.Appendix.AgentsRef)
		b.WriteString("| Phase | Agent | Turns | Stop reason | Produced | Prompt tok | Completion tok |\n|---|---|---|---|---|---|---|\n")
		for _, o := range outcomes {
			prod := "no"
			if o.Produced {
				prod = "yes"
			}
			fmt.Fprintf(&b, "| %s | %s | %d | %s | %s | %d | %d |\n", o.Phase, o.Label, o.Turns, o.Stop, prod, o.PT, o.CT)
		}
		b.WriteString("\n")
	}
	fmt.Fprintf(&b, "Artifact records: `%s`. Evidence records: `%s`, `%s`, `%s`.\n", m.Appendix.ArtifactsRef, m.Refs["review_units"], m.Refs["hunt_execution"], m.Refs["sessions"])
	return b.String()
}

// writeSeverityList prints severities in display order; withUnrated forces an
// explicit Unrated line so supported totals always account for every finding.
func writeSeverityList(b *strings.Builder, counts map[string]int, withUnrated bool) {
	printed := 0
	for _, sd := range sevDisplay {
		n := counts[sd.label]
		if n > 0 || (withUnrated && sd.label == "Unrated") {
			fmt.Fprintf(b, "- %s **%s**: %d\n", sd.glyph, sd.label, n)
			printed++
		}
	}
	// Any severity label outside the display order is still shown (never hidden).
	for _, k := range sortedKeys(counts) {
		known := false
		for _, sd := range sevDisplay {
			if sd.label == k {
				known = true
			}
		}
		if !known && counts[k] > 0 {
			fmt.Fprintf(b, "- ? **%s**: %d\n", k, counts[k])
			printed++
		}
	}
	if printed == 0 {
		b.WriteString("- none\n")
	}
}

func stopsText(stops map[string]int) string {
	var parts []string
	for _, k := range sortedKeys(stops) {
		parts = append(parts, fmt.Sprintf("%s ×%d", k, stops[k]))
	}
	if len(parts) == 0 {
		return "—"
	}
	return strings.Join(parts, ", ")
}

// mdCell makes a value safe inside a Markdown table cell.
func mdCell(s string) string {
	s = strings.ReplaceAll(s, "|", "\\|")
	s = strings.ReplaceAll(s, "\n", " ")
	return s
}

// Write emits report_model.json, SCAN_REPORT.md and SCAN_REPORT.html into
// resultsDir — all three from the same model.
func Write(in Input, resultsDir string) (mdPath, htmlPath string, err error) {
	m := BuildModel(in)
	if _, err = WriteModel(m, resultsDir); err != nil {
		return
	}
	mdPath = filepath.Join(resultsDir, MDFile)
	if err = os.WriteFile(mdPath, []byte(renderMarkdownModel(in, m)), 0o644); err != nil {
		return
	}
	htmlPath = filepath.Join(resultsDir, HTMLFile)
	err = os.WriteFile(htmlPath, []byte(renderHTMLModel(in, m)), 0o644)
	return
}
