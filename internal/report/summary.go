package report

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// Executive-summary bounds (feature 015, FR-001): the opening is at most
// MaxSummaryWords narrative words with at most MaxLeading leading issues/actions.
const (
	MaxSummaryWords = 300
	MaxLeading      = 5
)

// MaxOpeningWords is the feature-016 reader-facing bound on the opening prose (FR-002,
// C-P3). It counts the risk summary plus the scope sentence and nothing else: no title,
// no metric labels or values, no priority rows.
//
// It replaces MaxSummaryWords as the reader-facing bound. MaxSummaryWords counts a
// different quantity — the feature-015 narrative plus the leading list plus every
// limitation line — which is why a 557-word opening passed its own check. MaxSummaryWords
// is retained only for the legacy renderer, which still produces that Summary.
const MaxOpeningWords = 180

// buildOpening assembles the bounded opening from recorded facts. No model is consulted
// and nothing is rated or concluded here: the sentences restate counts, the scope note
// and a pointer to the details (FR-002, C-P3).
func buildOpening(counts ReportCounts, scope ScopeNote, app string) OpeningProse {
	sentences := riskSentences(counts, scope, app)
	o := OpeningProse{ScopeSentence: scopeSentence(scope)}

	// Bounded trimming: drop the least load-bearing sentence first. A status axis, the
	// material scope gap and the pointer to the details are protected, so the bound can
	// never be met by deleting a fact the reader needs (C-P3).
	for {
		o.RiskSummary = joinSentences(sentences)
		o.Words = len(strings.Fields(o.RiskSummary)) + len(strings.Fields(o.ScopeSentence))
		if o.Words <= MaxOpeningWords {
			break
		}
		i := lastDroppable(sentences)
		if i < 0 {
			break // everything left is load-bearing; report the honest count
		}
		sentences = append(sentences[:i], sentences[i+1:]...)
		o.Trimmed = true
	}
	return o
}

// openingSentence is one sentence of the risk summary. Protected sentences are never
// dropped to satisfy the word bound.
type openingSentence struct {
	text      string
	protected bool
}

func riskSentences(counts ReportCounts, scope ScopeNote, app string) []openingSentence {
	reviewIncomplete := scope.Execution != "Complete" || (scope.CoverageKnown && scope.CoverageComplete < scope.CoverageTotal)
	if counts.IssuesToFix == 0 {
		out := []openingSentence{
			{text: fmt.Sprintf("This scan established no issues to fix in the code of %s that was reviewed.", app), protected: true},
		}
		if reviewIncomplete {
			out = append(out, openingSentence{
				text:      "Review did not finish, so this does not establish that the application has none.",
				protected: true,
			})
		}
		out = append(out, openingSentence{
			text:      "Scan details below record what was reviewed and what was not.",
			protected: true,
		})
		return out
	}
	out := []openingSentence{
		{text: fmt.Sprintf("This scan established %s to fix in %s.", plural(counts.IssuesToFix, "issue", "issues"), app), protected: true},
	}
	if spread := severitySpread(counts.Severity); spread != "" {
		// Droppable: the severity table alongside carries the same figures.
		out = append(out, openingSentence{text: "By severity: " + spread + "."})
	}
	if counts.NeedsReview > 0 {
		// Droppable: the Needs review section states this with its own split.
		out = append(out, openingSentence{
			text: fmt.Sprintf("A further %s could not be settled either way and are listed separately under Needs review.",
				plural(counts.NeedsReview, "allegation", "allegations")),
		})
	}
	out = append(out, openingSentence{
		text:      "Each issue below names the affected code, why it matters, and the change to make.",
		protected: true,
	})
	return out
}

// scopeSentence states the three independent status facts once, in plain language, and
// carries the material scope gap with them (FR-004, C-P8, C-P9).
func scopeSentence(sc ScopeNote) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Review scope: execution %s; ", sc.Execution)
	if sc.CoverageKnown {
		fmt.Fprintf(&b, "%d of %d entry points completed — %s; ", sc.CoverageComplete, sc.CoverageTotal, sc.EntryPointGloss)
	} else {
		fmt.Fprintf(&b, "entry-point coverage was not recorded for this run, so how much was reviewed is unknown — entry points are %s; ", sc.EntryPointGloss)
	}
	fmt.Fprintf(&b, "method %s, so the application itself was never executed.", sc.Method)
	if sc.GapSentence != "" {
		b.WriteString(" " + sc.GapSentence)
	}
	return b.String()
}

// severitySpread renders the non-zero displayed severities in display order. A category
// with no issues is left out of the sentence; the table still shows its zero.
func severitySpread(counts map[string]int) string {
	var parts []string
	for _, s := range DisplaySeverities {
		if n := counts[s]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, s))
		}
	}
	return strings.Join(parts, ", ")
}

func joinSentences(s []openingSentence) string {
	parts := make([]string, 0, len(s))
	for _, x := range s {
		parts = append(parts, x.text)
	}
	return strings.Join(parts, " ")
}

func lastDroppable(s []openingSentence) int {
	for i := len(s) - 1; i >= 0; i-- {
		if !s[i].protected {
			return i
		}
	}
	return -1
}

// plural renders a count with the right noun, so no reader meets "1 issue(s)".
func plural(n int, one, many string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, one)
	}
	return fmt.Sprintf("%d %s", n, many)
}

// buildSummary assembles the deterministic executive summary from model facts.
// No model is consulted; every sentence names a recorded fact, and the limitation
// leads whenever the run has no supported findings and incomplete work (FR-003).
func buildSummary(m *ReportModel, in Input) Summary {
	s := Summary{Leading: []Leading{}, Limitations: []string{}}

	// Leading issues: the highest-severity supported findings (index order is
	// already severity rank then id), at most MaxLeading, one action each.
	for _, row := range m.Index {
		if len(s.Leading) == MaxLeading {
			break
		}
		if row.Role == "occurrence" { // one action per remediation group (FR-020)
			continue
		}
		s.Leading = append(s.Leading, Leading{Ref: row.Anchor, Title: row.Title, Severity: row.Severity, Surface: row.Surface, Action: row.Action})
	}

	// Limitations: degraded reasons, disabled phases and recovery steps from the
	// outcome block, each once, in a fixed order.
	s.Limitations = limitations(m, in)

	surfaces := map[string]bool{}
	for _, row := range m.Index {
		surfaces[row.Surface] = true
	}
	var b strings.Builder
	incomplete := m.Status.Execution != "" && m.Status.Execution != "complete"
	target := m.Target.Name
	if m.Target.Revision != "" {
		target += " at revision " + shortRev(m.Target.Revision)
	}
	switch {
	case m.Counts.Supported == 0 && incomplete:
		fmt.Fprintf(&b, "Limitation first: this scan of %s did not complete (execution %s, coverage %s) and produced no supported findings — that does not establish the absence of vulnerabilities. ",
			target, m.Status.Execution, m.Status.Coverage)
	case m.Counts.Supported == 0:
		fmt.Fprintf(&b, "Scan of %s completed (execution %s, coverage %s) with no supported findings within the reviewed scope; unreviewed scope, if any, is listed under limitations. ",
			target, m.Status.Execution, m.Status.Coverage)
	default:
		fmt.Fprintf(&b, "Scan of %s (execution %s, coverage %s). ", target, m.Status.Execution, m.Status.Coverage)
	}
	fmt.Fprintf(&b, "%d supported finding(s) across %d affected surface(s); %d candidate(s) rejected by source review; %d unresolved (%d explicit verifier decisions, %d failed verification sessions); %d candidates examined in total. ",
		m.Counts.Supported, len(surfaces), m.Counts.Rejected, m.Counts.UnresolvedExplicit+m.Counts.UnresolvedFailed, m.Counts.UnresolvedExplicit, m.Counts.UnresolvedFailed, m.Counts.TotalCandidates)
	if m.Counts.RemediationGroups > 0 && m.Counts.RemediationGroups < m.Counts.Supported {
		fmt.Fprintf(&b, "The supported findings reduce to %d remediation group(s). ", m.Counts.RemediationGroups)
	}
	if len(s.Leading) > 0 {
		b.WriteString("Principal risks: ")
		for i, l := range s.Leading {
			if i > 0 {
				b.WriteString("; ")
			}
			fmt.Fprintf(&b, "%s (%s) at %s", l.Title, l.Severity, l.Surface)
		}
		b.WriteString(". ")
	}
	if m.Status.ValidationMode != "" {
		fmt.Fprintf(&b, "Validation mode: %s — findings are supported by static reasoning, not by executed exploits. ", m.Status.ValidationMode)
	}
	if !incomplete && m.Status.Execution != "" {
		b.WriteString("Job termination is reported separately from these axes. ")
	}
	s.Narrative = strings.TrimSpace(b.String())

	// Enforce the word bound over the whole opening (narrative + leading lines +
	// limitations): trim limitations first, then the narrative, with an explicit
	// pointer to the full lists.
	s.Words = summaryWords(s)
	for s.Words > MaxSummaryWords && len(s.Limitations) > 1 {
		s.Limitations = s.Limitations[:len(s.Limitations)-1]
		s.Limitations[len(s.Limitations)-1] = "… more limitations are listed under Coverage and limitations"
		s.Words = summaryWords(s)
		if len(s.Limitations) == 1 {
			break
		}
	}
	if s.Words > MaxSummaryWords {
		s.Narrative = clampWords(s.Narrative, MaxSummaryWords-summaryWordsExcept(s)) + " (see Outcome metrics)"
		s.Words = summaryWords(s)
	}
	return s
}

func limitations(m *ReportModel, in Input) []string {
	seen := map[string]bool{}
	var out []string
	add := func(s string) {
		s = strings.TrimSpace(s)
		if s == "" || seen[s] {
			return
		}
		seen[s] = true
		out = append(out, s)
	}
	if m.Status.Execution != "" && m.Status.Execution != "complete" {
		add("execution " + m.Status.Execution + ": not every requested phase completed")
	}
	for _, r := range m.Status.DegradedReasons {
		add(r)
	}
	oc := outcomeFields(in.Doc.RunStatus.Outcome)
	for _, p := range oc.DisabledOptionalPhases {
		add("optional phase disabled: " + p)
	}
	for _, s := range oc.RecoverySteps {
		add("recovery: " + s)
	}
	if m.Counts.SourceReview.Total > 0 {
		add(fmt.Sprintf("source review: %d of %d entry points completed (%s)", m.Counts.SourceReview.Completed, m.Counts.SourceReview.Total, orText(m.CoverageSemanticsLabel, "coverage semantics unknown")))
	}
	if !in.CodeExecuted {
		add("the target's code was never executed; exploit tests, if authored, were not run")
	}
	if !in.VerifyModelUsed {
		add("verification ran on the same model that produced the candidates")
	}
	if out == nil {
		out = []string{}
	}
	return out
}

type outcomeSlice struct {
	DisabledOptionalPhases []string `json:"disabled_optional_phases"`
	RecoverySteps          []string `json:"recovery_steps"`
}

func outcomeFields(outcome any) outcomeSlice {
	var oc outcomeSlice
	if outcome == nil {
		return oc
	}
	if b, err := jsonMarshal(outcome); err == nil {
		_ = jsonUnmarshal(b, &oc)
	}
	return oc
}

// summaryWords counts every word of the opening (narrative, leading items,
// limitations) — the metrics block and index are not part of the opening.
func summaryWords(s Summary) int {
	n := len(strings.Fields(s.Narrative))
	n += summaryWordsExcept(s)
	return n
}

func summaryWordsExcept(s Summary) int {
	n := 0
	for _, l := range s.Leading {
		n += len(strings.Fields(l.Title + " " + l.Severity + " " + l.Surface + " " + l.Action))
	}
	for _, l := range s.Limitations {
		n += len(strings.Fields(l))
	}
	return n
}

func shortRev(r string) string {
	if len(r) > 12 {
		return r[:12]
	}
	return r
}

// sortedKeys is a small helper for deterministic map rendering.
func sortedKeys(m map[string]int) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

func jsonMarshal(v any) ([]byte, error)   { return json.Marshal(v) }
func jsonUnmarshal(b []byte, v any) error { return json.Unmarshal(b, v) }
