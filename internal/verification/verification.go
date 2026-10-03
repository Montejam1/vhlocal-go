// Package verification is the adversarial, candidate-bound verification layer
// (feature 005, US3). It builds a candidate manifest BEFORE Phase 2b, reconciles
// per-candidate decisions fail-closed (every candidate gets supported / rejected /
// unresolved), and renders the disposition output + supported-only handoff. The
// model-driven session that produces decisions lives in the engine; this package
// is pure, deterministic logic (no model call) so it is fully offline-testable.
//
// Fidelity notes (documented approximations, plan Complexity #2): candidate
// identity uses lexical Python owners, cited-line text, statement occurrence,
// CWE and path, not a Python-AST statement digest. "Containing function context" (FR-009)
// is computed by an indentation/`def` scan rather than a Python AST — a supported
// verdict requires the evidence to cover the complete enclosing function span
// (decorators + body). The authz route-guard entry-point match (FR-010) resolves
// the handler by nearest route line rather than an exact AST span (Go inventory
// carries no end-line).
package verification

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"vhlocal/internal/citation"
	"vhlocal/internal/consolidate"
	"vhlocal/internal/source"
)

const (
	CandidateManifestFile = "candidate_manifest.json"
	ArtifactManifestFile  = "artifact_manifest.json"
	DecisionsFile         = "verification_decisions.json"
	MetricsFile           = "verification_metrics.json"
	ReconciliationFile    = "verification_reconciliation.json"
)

// Candidate is one hunt finding promoted to a verification target.
type Candidate struct {
	ID       string              `json:"id"`
	Identity string              `json:"stable_identity"`
	Finding  consolidate.Finding `json:"finding"`
	// LikelyGroup (feature 015, R5): the established-rule remediation group this
	// candidate would share. Reporting only — no candidate is skipped or merged.
	LikelyGroup string `json:"likely_group,omitempty"`
	// Citation (feature 015, FR-025): the validated citation record (schema 2).
	Citation *CitationRecord `json:"citation,omitempty"`
	// Supersedes / Superseded (feature 015, FR-026): amendment identity links.
	Supersedes string `json:"supersedes,omitempty"`
	Superseded string `json:"superseded,omitempty"` // the id that replaced this candidate
}

// Manifest is candidate_manifest.json — the falsification input, built before 2b.
type Manifest struct {
	SchemaVersion int         `json:"schema_version"`
	Revision      string      `json:"revision"`
	Repo          string      `json:"repo"`
	RawCount      int         `json:"raw_count"`
	Candidates    []Candidate `json:"candidates"`
	// Feature 015 (FR-026): accepted/rejected amendments and identity supersessions.
	Amendments []Amendment      `json:"amendments,omitempty"`
	Superseded []SupersededPair `json:"superseded,omitempty"`
	Counts     map[string]int   `json:"citation_counts,omitempty"`
}

// Amendment is one amend_candidate outcome (data-model "amendments[]").
type Amendment struct {
	CandidateID    string `json:"candidate_id"`
	SessionAttempt int    `json:"session_attempt"`
	Original       string `json:"original"`
	Amended        string `json:"amended"`
	Reason         string `json:"reason"`
	Revision       string `json:"revision"`
	Agent          string `json:"agent"`
	Outcome        string `json:"outcome"`  // accepted | rejected
	Identity       string `json:"identity"` // kept | superseded_by:<id>
	Error          string `json:"error,omitempty"`
}

// SupersededPair links an amended-away candidate to its replacement.
type SupersededPair struct {
	OldID string `json:"old_id"`
	NewID string `json:"new_id"`
}

// Evidence is an immutable, candidate-bound source citation captured from live source.
type Evidence struct {
	ID        string `json:"evidence_id"`
	Path      string `json:"path"`
	StartLine int    `json:"start_line"`
	EndLine   int    `json:"end_line"`
	Quote     string `json:"quote"`
}

// Decision is one submitted verification decision for a candidate.
type Decision struct {
	CandidateID         string     `json:"candidate_id"`
	Verdict             string     `json:"verdict"`
	Rationale           string     `json:"rationale"`
	EntryPoint          string     `json:"entry_point"`
	AttackerControl     string     `json:"attacker_control"`
	Preconditions       string     `json:"preconditions"`
	DefensesReviewed    string     `json:"defenses_reviewed"`
	SecurityImpact      string     `json:"security_impact"`
	UnresolvedQuestions []string   `json:"unresolved_questions"`
	Evidence            []Evidence `json:"evidence"`
	Reviewer            string     `json:"reviewer"`
	Revision            string     `json:"revision"`
}

// DecisionResult is a candidate's reconciled disposition.
type DecisionResult struct {
	CandidateID string    `json:"candidate_id"`
	Status      string    `json:"status"` // supported | rejected | unresolved
	Reason      string    `json:"reason"`
	Record      *Decision `json:"record"`
}

// Reconciliation is verification_reconciliation.json.
type Reconciliation struct {
	SchemaVersion int              `json:"schema_version"`
	Complete      bool             `json:"complete"`
	Errors        []string         `json:"errors"`
	Counts        map[string]int   `json:"counts"`
	Results       []DecisionResult `json:"results"`
}

func candidateIdentity(f consolidate.Finding, repo string) string {
	cwe := f.CWE
	if cwe == "" {
		cwe = f.NormalizedCWE
	}
	// Preserve source text case: literals that differ in case are distinct sites.
	file, line := fileAndLine(f.Location)
	anchor := f.Location + "|" + f.Source + "|" + f.SourceID
	if b, err := source.ReadFile(repo, file); err == nil {
		lines := strings.Split(string(b), "\n")
		if line > 0 && line <= len(lines) {
			stmt := strings.TrimSpace(lines[line-1])
			// Lexical Python owners plus occurrence avoid merging identical sinks in
			// separate functions/classes, or repeated sinks within one function. For
			// other languages retain exact location rather than guessing scope.
			if strings.HasSuffix(file, ".py") && stmt != "" {
				owners, start := sourceOwners(lines, line)
				occurrence := 0
				for i := start; i < line-1; i++ {
					if strings.TrimSpace(lines[i]) == stmt {
						occurrence++
					}
				}
				anchor = filepath.ToSlash(filepath.Clean(file)) + "|" + strings.Join(owners, "/") + "|" + stmt + fmt.Sprintf("|%d", occurrence)
			}
		}
	}
	sum := sha256.Sum256([]byte(strings.ToUpper(cwe) + "|" + anchor))
	return fmt.Sprintf("%x", sum)
}

var reOwner = regexp.MustCompile(`^(\s*)(?:(?:async\s+)?def|class)\s+([A-Za-z_][A-Za-z_0-9]*)`)

func sourceOwners(lines []string, line int) ([]string, int) {
	type owner struct {
		name          string
		indent, start int
	}
	var stack []owner
	counts := map[string]int{}
	for i := 0; i < line; i++ {
		text := lines[i]
		if strings.TrimSpace(text) == "" || strings.HasPrefix(strings.TrimSpace(text), "#") {
			continue
		}
		indent := leadingWS(text)
		for len(stack) > 0 && indent <= stack[len(stack)-1].indent {
			stack = stack[:len(stack)-1]
		}
		if m := reOwner.FindStringSubmatch(text); m != nil {
			prefix := ""
			for _, o := range stack {
				prefix += o.name + "/"
			}
			key := prefix + m[2]
			occurrence := counts[key]
			counts[key]++
			stack = append(stack, owner{fmt.Sprintf("%s#%d", m[2], occurrence), indent, i})
		}
	}
	var names []string
	start := 0
	for _, o := range stack {
		names = append(names, o.name)
		start = o.start
	}
	return names, start
}

func normPath(loc string) string {
	if i := strings.IndexByte(loc, ':'); i >= 0 {
		return loc[:i]
	}
	return loc
}

func fileAndLine(loc string) (string, int) {
	i := strings.IndexByte(loc, ':')
	if i < 0 {
		return loc, 0
	}
	n := 0
	for _, c := range loc[i+1:] {
		if c < '0' || c > '9' {
			break
		}
		n = n*10 + int(c-'0')
	}
	return loc[:i], n
}

func citedLineText(loc, repo string) string {
	f, ln := fileAndLine(loc)
	if repo == "" || f == "" || ln < 1 || filepath.IsAbs(f) || strings.Contains(f, "..") {
		return ""
	}
	b, err := source.ReadFile(repo, f)
	if err != nil {
		return ""
	}
	lines := strings.Split(string(b), "\n")
	if ln > len(lines) {
		return ""
	}
	return lines[ln-1]
}

// BuildManifest constructs the candidate manifest from hunt findings and writes it
// (before 2b). Duplicates are skipped; identity is line-shift/prose-insensitive.
func BuildManifest(resultsDir, repo, revision string, findings []consolidate.Finding) (*Manifest, error) {
	if revision == "" {
		revision = "tree-sha256:unknown"
	}
	m := &Manifest{SchemaVersion: ManifestSchema, Revision: revision, Repo: repo, Candidates: []Candidate{}, Counts: map[string]int{CitationValid: 0, CitationInvalid: 0}}
	seen := map[string]bool{}
	likely := consolidate.GroupKeys(findings, repo)
	binder := citation.NewBinder(repo)
	for _, f := range findings {
		// Source identity, not prose-based consolidation, owns candidate dedup.
		f.DuplicateOf = nil
		// Feature 015 (FR-025): validate the citation first; a valid one is recorded in
		// canonical form (original retained), an invalid one stays visible as such.
		cr, canonical := ValidateCitation(f, repo, revision, binder)
		if canonical != "" {
			f.Location = canonical
		}
		id := candidateIdentity(f, repo)
		cid := "CAND-" + id[:24]
		if seen[cid] { // dedup by stable candidate identity → one session per candidate
			continue
		}
		seen[cid] = true
		m.Counts[cr.Status]++
		crCopy := cr
		m.Candidates = append(m.Candidates, Candidate{ID: cid, Identity: id, Finding: f, LikelyGroup: likely[f.ID], Citation: &crCopy})
	}
	m.RawCount = len(findings)
	return m, writeJSON(filepath.Join(resultsDir, CandidateManifestFile), m)
}

// Reconcile assigns every candidate a fail-closed disposition (FR-020): missing,
// duplicate, or invalid decisions stay unresolved with a reason; a "supported"
// verdict requires cited evidence covering the location AND source corroboration;
// a "rejected" verdict requires a rationale + cited evidence; "unresolved" is an
// accepted explicit outcome. Never confers support without evidence (FR-C2).
func Reconcile(m *Manifest, decisions []Decision, repo string) *Reconciliation {
	invalid := func(why string) *Reconciliation {
		return &Reconciliation{SchemaVersion: 1, Errors: []string{why}, Counts: map[string]int{"supported": 0, "rejected": 0, "unresolved": 0}}
	}
	if m == nil || m.SchemaVersion < 1 || m.SchemaVersion > ManifestSchema || strings.TrimSpace(m.Revision) == "" || m.Repo == "" || m.Candidates == nil {
		return invalid("invalid candidate manifest schema, repository, or revision")
	}
	manifestRepo, e1 := filepath.EvalSymlinks(m.Repo)
	liveRepo, e2 := filepath.EvalSymlinks(repo)
	if e1 != nil || e2 != nil {
		return invalid("candidate manifest repository unavailable")
	}
	manifestRepo, _ = filepath.Abs(manifestRepo)
	liveRepo, _ = filepath.Abs(liveRepo)
	if manifestRepo != liveRepo {
		return invalid("candidate manifest belongs to a different repository")
	}
	seen := map[string]bool{}
	for _, c := range m.Candidates {
		if c.ID == "" || seen[c.ID] {
			return invalid("candidate manifest has empty or duplicate IDs")
		}
		seen[c.ID] = true
	}
	byCand := map[string][]Decision{}
	valid := map[string]bool{}
	for _, c := range m.Candidates {
		valid[c.ID] = true
	}
	var errs []string
	for _, d := range decisions {
		if d.CandidateID == "" || !valid[d.CandidateID] {
			errs = append(errs, "decision has no valid candidate_id: "+d.CandidateID)
			continue
		}
		byCand[d.CandidateID] = append(byCand[d.CandidateID], d)
	}
	rec := &Reconciliation{SchemaVersion: 1, Counts: map[string]int{"supported": 0, "rejected": 0, "unresolved": 0, "invalid_citation": 0, "superseded": 0}}
	for _, c := range m.Candidates {
		rows := byCand[c.ID]
		status, reason := "unresolved", "No verification decision supplied"
		var record *Decision
		switch {
		case !c.HasValidCitation():
			// C-C8: an invalid, unamended citation cannot be bypassed by any verdict.
			reason = InvalidCitationReason(c.Citation)
			if len(rows) > 0 {
				errs = append(errs, c.ID+": decision submitted for an invalid_citation candidate (rejected)")
			}
		case c.Superseded != "":
			reason = "superseded by " + c.Superseded + " (citation amended)"
			status = "superseded"
			if len(rows) > 0 {
				errs = append(errs, c.ID+": decision submitted for a superseded candidate (rejected)")
			}
		case len(rows) == 0:
			errs = append(errs, c.ID+": missing decision")
		case len(rows) > 1:
			errs = append(errs, c.ID+": duplicate decisions")
		default:
			d := rows[0]
			if !isVerdict(d.Verdict) || strings.TrimSpace(d.Rationale) == "" {
				reason = "Unknown verdict or missing rationale"
				errs = append(errs, c.ID+": "+reason)
			} else if d.Verdict == "unresolved" {
				status, reason, record = "unresolved", d.Rationale, &rows[0]
			} else if strings.TrimSpace(m.Revision) == "" || d.Revision != m.Revision {
				reason = "review does not identify this target revision"
				errs = append(errs, c.ID+": "+reason)
			} else if why := validateEvidenceBacked(c, d, repo); why != "" {
				reason = why
				errs = append(errs, c.ID+": "+why)
			} else {
				status, reason, record = d.Verdict, d.Rationale, &rows[0]
			}
		}
		rec.Results = append(rec.Results, DecisionResult{CandidateID: c.ID, Status: status, Reason: reason, Record: record})
		rec.Counts[status]++
		if !c.HasValidCitation() {
			rec.Counts["invalid_citation"]++
		}
	}
	rec.Complete = len(errs) == 0
	rec.Errors = errs
	return rec
}

func isVerdict(v string) bool {
	return v == "supported" || v == "rejected" || v == "unresolved"
}

// validateEvidenceBacked validates a supported/rejected decision. Returns "" when
// valid, else the reason it cannot be accepted.
func validateEvidenceBacked(c Candidate, d Decision, repo string) string {
	for _, field := range []struct{ name, value string }{
		{"reviewer", d.Reviewer}, {"entry_point", d.EntryPoint}, {"attacker_control", d.AttackerControl},
		{"preconditions", d.Preconditions}, {"defenses_reviewed", d.DefensesReviewed}, {"security_impact", d.SecurityImpact},
	} {
		if strings.TrimSpace(field.value) == "" {
			return "review is missing " + field.name
		}
	}
	if !exactLocation.MatchString(c.Finding.Location) {
		return "candidate needs an exact source location"
	}
	if len(d.Evidence) == 0 {
		return "a supported or rejected verdict requires cited source evidence"
	}
	// Every evidence quote must byte-match the live source it cites (immutable,
	// current-revision) — never a paraphrase.
	for _, e := range d.Evidence {
		if !evidenceMatchesSource(e, repo) {
			return "evidence quote does not match the live source at " + e.Path
		}
	}
	// supported: unresolved questions are contradictory; require function/location
	// coverage + source corroboration.
	if d.Verdict == "supported" && len(d.UnresolvedQuestions) > 0 {
		return "a supported decision cannot carry unresolved questions"
	}
	if !evidenceCoversLocation(c.Finding.Location, d.Evidence, repo) {
		return "evidence must cover the cited primary location (the containing handler/defenses)"
	}
	if d.Verdict == "rejected" {
		return ""
	}
	// FR-009: the evidence must cover the COMPLETE containing function (decorators +
	// defenses), so a context check cannot bleed into a neighbouring handler.
	if why := requireFunctionEvidence(c.Finding.Location, d.Evidence, repo); why != "" {
		return why
	}
	// FR-010: when the location resolves to a route handler, the review's entry_point
	// must equal the resolved route guard (METHOD PATH).
	if method, path, ok := routeGuardFor(repo, c.Finding.Location); ok {
		if strings.TrimSpace(d.EntryPoint) != method+" "+path {
			return "review entry point does not match the cited source handler"
		}
	}
	if consolidate.ClassEvidenceRefuted(&c.Finding, repo) {
		return "class-specific evidence refutes exploitability for this weakness class"
	}
	// Block only when the source DEFINITELY refutes the class (present, no matching
	// sink) — never merely because corroboration is NA. An authorization/logic class
	// has no syntactic sink to corroborate, so a complete evidence-backed review of it
	// is accepted (FR-024); a sink-class finding whose source lacks the sink is still
	// refused, and a primary-evidence class (CORS) still stands on its class evidence.
	if consolidate.SourceRefuted(&c.Finding, repo) && !consolidate.ClassPrimaryEvidence(&c.Finding, repo) {
		return "the cited source refutes the weakness class (no matching sink at the cited location)"
	}
	return ""
}

func evidenceMatchesSource(e Evidence, repo string) bool {
	if repo == "" || e.Path == "" || filepath.IsAbs(e.Path) || strings.Contains(e.Path, "..") {
		return false
	}
	b, err := source.ReadFile(repo, e.Path)
	if err != nil {
		return false
	}
	lines := strings.Split(string(b), "\n")
	if e.StartLine < 1 || e.EndLine > len(lines) || e.StartLine > e.EndLine {
		return false
	}
	want := strings.Join(lines[e.StartLine-1:e.EndLine], "\n")
	return strings.TrimRight(want, "\n") == strings.TrimRight(e.Quote, "\n")
}

var exactLocation = regexp.MustCompile(`^(.+?):([1-9][0-9]*)(?:[-–‑]([1-9][0-9]*))?$`)

func evidenceCoversLocation(location string, ev []Evidence, repo string) bool {
	m := exactLocation.FindStringSubmatch(location)
	if m == nil {
		return false
	}
	primary, err := source.Resolve(repo, m[1])
	if err != nil {
		return false
	}
	start, _ := strconv.Atoi(m[2])
	end := start
	if m[3] != "" {
		end, _ = strconv.Atoi(m[3])
	}
	if end < start {
		return false
	}
	for _, e := range ev {
		path, err := source.Resolve(repo, e.Path)
		if err == nil && path == primary && e.StartLine <= start && e.EndLine >= end {
			return true
		}
	}
	return false
}

var reDef = regexp.MustCompile(`^(\s*)(?:async\s+)?def\s`)

type funcSpan struct{ start, end int } // 1-based, inclusive; start includes decorators

// functionSpans scans Python source (by indentation) for every def/async def and
// its span, extending start upward across contiguous decorator lines and end
// downward while the body stays more-indented than the def (blank lines don't end
// a function). An approximation of the Python AST span (Go has no AST).
func functionSpans(lines []string) []funcSpan {
	var spans []funcSpan
	for i, l := range lines {
		m := reDef.FindStringSubmatch(l)
		if m == nil {
			continue
		}
		indent := len(m[1])
		start := i
		for j := i - 1; j >= 0; j-- {
			if strings.HasPrefix(strings.TrimSpace(lines[j]), "@") && leadingWS(lines[j]) == indent {
				start = j
			} else {
				break
			}
		}
		end := i
		for j := i + 1; j < len(lines); j++ {
			if strings.TrimSpace(lines[j]) == "" {
				continue
			}
			if leadingWS(lines[j]) > indent {
				end = j
			} else {
				break
			}
		}
		spans = append(spans, funcSpan{start: start + 1, end: end + 1})
	}
	return spans
}

func leadingWS(s string) int {
	n := 0
	for _, c := range s {
		if c != ' ' && c != '\t' {
			break
		}
		n++
	}
	return n
}

// requireFunctionEvidence returns "" when the cited evidence covers the complete
// enclosing function (or the location is not inside a resolvable Python function),
// else the reason support is refused (FR-009; parity with the reference
// verification.require_function_evidence).
func requireFunctionEvidence(location string, ev []Evidence, repo string) string {
	file, cited := fileAndLine(location)
	if file == "" || cited == 0 || !strings.HasSuffix(file, ".py") {
		return ""
	}
	if repo == "" || filepath.IsAbs(file) || strings.Contains(file, "..") {
		return ""
	}
	b, err := source.ReadFile(repo, file)
	if err != nil {
		return "cannot validate containing function context"
	}
	lines := strings.Split(string(b), "\n")
	var best *funcSpan
	for _, s := range functionSpans(lines) {
		if s.start <= cited && cited <= s.end {
			if best == nil || (s.end-s.start) < (best.end-best.start) {
				sp := s
				best = &sp
			}
		}
	}
	if best == nil {
		return "" // not inside a function → nothing extra to require
	}
	covered := map[int]bool{}
	for _, e := range ev {
		if e.Path == file || strings.HasSuffix(e.Path, "/"+file) || strings.HasSuffix(file, "/"+e.Path) {
			for l := e.StartLine; l <= e.EndLine; l++ {
				covered[l] = true
			}
		}
	}
	for l := best.start; l <= best.end; l++ {
		if !covered[l] {
			return "evidence must cover the complete containing function, including decorators and defenses"
		}
	}
	return ""
}

// WriteDecisions persists the reconciled decisions (verification_decisions.json).
func WriteDecisions(resultsDir string, decisions []Decision) error {
	if decisions == nil {
		decisions = []Decision{}
	}
	return writeJSON(filepath.Join(resultsDir, DecisionsFile), decisions)
}

// WriteArtifactManifestPlaceholder writes an empty artifact_manifest.json (only
// when none exists — the engine guards against clobbering a real one, FR-C3).
func WriteArtifactManifestPlaceholder(resultsDir string) error {
	return writeJSON(filepath.Join(resultsDir, ArtifactManifestFile), []any{})
}

// FinalFindings maps the reconciled manifest to findings, stamping each with its
// verification disposition; FromConfirmed is true ONLY for supported (FR-C1/C2).
func FinalFindings(m *Manifest, rec *Reconciliation) []consolidate.Finding {
	byID := map[string]DecisionResult{}
	for _, r := range rec.Results {
		byID[r.CandidateID] = r
	}
	out := make([]consolidate.Finding, 0, len(m.Candidates))
	for _, c := range m.Candidates {
		f := c.Finding
		f.ID = c.ID
		f.StableIdentity = c.Identity
		f.DuplicateOf = nil
		f.VerificationRecord = nil
		r := byID[c.ID]
		if r.Status == "" {
			r.Status = "unresolved"
			r.Reason = "invalid verification manifest: " + strings.Join(rec.Errors, "; ")
		}
		f.VerificationStatus = r.Status
		f.VerificationReason = r.Reason
		f.FromConfirmed = r.Status == "supported"
		if c.Superseded != "" { // feature 015 (C-C7): the amended-away identity folds into its replacement
			sup := c.Superseded
			f.DuplicateOf = &sup
		}
		if r.Record != nil {
			data, _ := json.Marshal(r.Record)
			_ = json.Unmarshal(data, &f.VerificationRecord)
		}
		out = append(out, f)
	}
	return out
}

// Render writes the disposition table (phase2b_output.md), the supported-only
// handoff (phase2b_handoff.md), the reconciliation, and metrics (FR-023). The
// output explicitly notes acceptance of unresolved does NOT imply confirmation.
func Render(resultsDir string, m *Manifest, rec *Reconciliation) error {
	byID := map[string]DecisionResult{}
	for _, r := range rec.Results {
		byID[r.CandidateID] = r
	}
	var b strings.Builder
	b.WriteString("# Candidate verification\n\n| Candidate | Decision | Explanation |\n|---|---|---|\n")
	for _, c := range m.Candidates {
		r := byID[c.ID]
		b.WriteString(fmt.Sprintf("| %s | %s | %s |\n", c.ID, r.Status, sanitizeCell(r.Reason)))
	}
	b.WriteString("\n_Acceptance includes explicit unresolved decisions; it does not imply vulnerability confirmation._\n")
	if err := os.WriteFile(filepath.Join(resultsDir, "phase2b_output.md"), []byte(b.String()), 0o644); err != nil {
		return err
	}

	var h strings.Builder
	h.WriteString("# Verified candidate handoff\n\n_These are source-grounded model reviews, not runtime reproductions. Preserve candidate IDs exactly._\n\n")
	h.WriteString("| Candidate | Location | CWE |\n|---|---|---|\n")
	supported := 0
	for _, c := range m.Candidates {
		if byID[c.ID].Status == "supported" {
			supported++
			h.WriteString(fmt.Sprintf("| %s | %s | %s |\n", c.ID, sanitizeCell(c.Finding.Location), sanitizeCell(c.Finding.CWE)))
		}
	}
	if supported == 0 {
		h.WriteString("\nNo candidates were verified as supported. Total confirmed findings: 0\n")
	}
	if err := os.WriteFile(filepath.Join(resultsDir, "phase2b_handoff.md"), []byte(h.String()), 0o644); err != nil {
		return err
	}

	metrics := map[string]any{
		"candidates":         len(m.Candidates),
		"supported":          rec.Counts["supported"],
		"rejected":           rec.Counts["rejected"],
		"unresolved":         rec.Counts["unresolved"],
		"invalid_citation":   rec.Counts["invalid_citation"],
		"superseded":         rec.Counts["superseded"],
		"accepted_decisions": countAccepted(rec),
		"incomplete":         !rec.Complete,
	}
	// Feature 015 (C-C10): occurrences vs sessions vs stop reasons, from the persisted
	// session outcomes (identical at finalize and regeneration).
	var sessions []SessionOutcome
	for _, s := range LoadSessions(resultsDir) {
		sessions = append(sessions, s)
	}
	sort.Slice(sessions, func(i, j int) bool { return sessions[i].CandidateID < sessions[j].CandidateID })
	metrics["session_aggregates"] = Aggregates(sessions)
	if len(m.Amendments) > 0 {
		metrics["amendments"] = len(m.Amendments)
	}
	_ = writeJSON(filepath.Join(resultsDir, MetricsFile), metrics)
	return writeJSON(filepath.Join(resultsDir, ReconciliationFile), rec)
}

func countAccepted(rec *Reconciliation) int {
	n := 0
	for _, r := range rec.Results {
		if r.Record != nil {
			n++
		}
	}
	return n
}

func sanitizeCell(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "|", "/"), "\n", " ")
}

func writeJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
