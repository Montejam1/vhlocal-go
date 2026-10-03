// Package benchmark scores a finished results directory against a ground-truth
// corpus (feature 015, FR-021..023, research R6, contracts C-C16..C-C18). It is
// offline and deterministic: it reads records only (findings.json, the candidate
// manifest, verification metrics/sessions, review units, scan_meta) and the target
// source for function scoping. Only a `supported ∧ non-duplicate` finding can
// detect a truth entry; every truth id counts once; unmatched supported findings are
// false positives; hits on safe controls are false positives flagged by language
// and family; denominators are explicit; cost is "unknown" for unpriced backends.
package benchmark

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"vhlocal/internal/consolidate"
	"vhlocal/internal/pricing"
	"vhlocal/internal/recognize"
	"vhlocal/internal/source"
)

// Truth is testdata/benchmark/truth/ground_truth.json (version 2).
type Truth struct {
	Version int     `json:"version"`
	Target  string  `json:"target"`
	Notes   any     `json:"notes,omitempty"`
	Entries []Entry `json:"entries"`
}

// Entry is one seeded issue or safe control.
type Entry struct {
	ID                string  `json:"id"`
	Language          string  `json:"language"`
	CWE               string  `json:"cwe"`
	Family            string  `json:"family"`
	Expected          string  `json:"expected"` // vulnerable | safe_control
	Anchor            Anchor  `json:"anchor"`
	RootCause         string  `json:"root_cause,omitempty"`
	AcceptableMatches []Match `json:"acceptable_matches"`
	Notes             string  `json:"notes,omitempty"`
}

// Anchor is the seeded location.
type Anchor struct {
	File     string `json:"file"`
	Function string `json:"function"`
	Lines    [2]int `json:"lines"`
}

// Match is one acceptable way to hit an entry: a file+function or a route.
type Match struct {
	File     string `json:"file,omitempty"`
	Function string `json:"function,omitempty"`
	Route    string `json:"route,omitempty"`
}

// LoadTruth reads and validates a truth file.
func LoadTruth(path string) (Truth, error) {
	var t Truth
	b, err := os.ReadFile(path)
	if err != nil {
		return t, err
	}
	if err := json.Unmarshal(b, &t); err != nil {
		return t, fmt.Errorf("ground truth: %w", err)
	}
	if t.Version != 2 {
		return t, fmt.Errorf("ground truth version %d unsupported (want 2)", t.Version)
	}
	seen := map[string]bool{}
	for _, e := range t.Entries {
		if e.ID == "" || seen[e.ID] || (e.Expected != "vulnerable" && e.Expected != "safe_control") || e.Anchor.File == "" {
			return t, fmt.Errorf("ground truth entry invalid: %+v", e)
		}
		seen[e.ID] = true
	}
	return t, nil
}

// Bucket is a precision/recall cell with explicit denominators.
type Bucket struct {
	TP          int     `json:"tp"`
	FP          int     `json:"fp"`
	FN          int     `json:"fn"`
	Precision   float64 `json:"precision"`
	Recall      float64 `json:"recall"`
	Denominator int     `json:"denominator"` // vulnerable truth entries in this cell
}

func (b *Bucket) finish() {
	if b.TP+b.FP > 0 {
		b.Precision = round(float64(b.TP) / float64(b.TP+b.FP))
	}
	if b.Denominator > 0 {
		b.Recall = round(float64(b.TP) / float64(b.Denominator))
	}
}

// SafeControlHit is a supported finding on a safe control (a flagged FP).
type SafeControlHit struct {
	TruthID   string `json:"truth_id"`
	Language  string `json:"language"`
	Family    string `json:"family"`
	FindingID string `json:"finding_id"`
	Location  string `json:"location"`
}

// Supported is the headline cell plus the matched/unmatched identities.
type Supported struct {
	Bucket
	Matched    map[string]string   `json:"matched"`               // truth id → first finding id
	RepeatHits map[string][]string `json:"repeat_hits,omitempty"` // truth id → later finding ids (not FP, not extra TP)
	Unmatched  []string            `json:"unmatched"`             // FP finding ids
	Missed     []string            `json:"missed"`                // FN truth ids
}

// Ratio is a matched/total pair.
type Ratio struct {
	Matched int      `json:"matched"`
	Total   int      `json:"total"`
	IDs     []string `json:"ids,omitempty"`
}

// VerificationStats summarizes the verification phase.
type VerificationStats struct {
	Candidates      int            `json:"candidates"`
	Accepted        int            `json:"accepted"`
	Recovered       int            `json:"recovered"` // sessions with ≥1 failure that still completed
	TerminalByClass map[string]int `json:"terminal_by_class"`
	Supported       int            `json:"supported"`
	Rejected        int            `json:"rejected"`
	Unresolved      int            `json:"unresolved"`
	InvalidCitation int            `json:"invalid_citation"`
	Sessions        int            `json:"sessions"`
}

// CoverageStats is the source-review axis.
type CoverageStats struct {
	CompletedReview  int `json:"completed_review"`
	SourceExposed    int `json:"source_exposed"`
	Total            int `json:"total"`
	SemanticsVersion int `json:"semantics_version"`
}

// ArtifactStats is the artifact completeness axis.
type ArtifactStats struct {
	Complete bool     `json:"complete"`
	Missing  []string `json:"missing"`
}

// Cost is the run cost; USD is a number or the string "unknown".
type Cost struct {
	PromptTokens     int     `json:"prompt_tokens"`
	CompletionTokens int     `json:"completion_tokens"`
	Seconds          float64 `json:"seconds"`
	USD              any     `json:"usd"`
}

// Denominators names every count a rate divides by.
type Denominators struct {
	VulnerableEntries int `json:"vulnerable_entries"`
	SafeControls      int `json:"safe_controls"`
	SupportedFindings int `json:"supported_findings"`
	Candidates        int `json:"candidates"`
}

// RunConfig is the configuration identity of a run (for baselines and diffs).
type RunConfig struct {
	TargetRevision  string            `json:"target_revision"`
	Build           map[string]string `json:"build"`
	Models          map[string]string `json:"models"`
	Backend         string            `json:"backend"`
	PromptsHash     map[string]string `json:"prompts_hash"`
	ToolSchemaHash  map[string]string `json:"tool_schema_hash"`
	Sampling        map[string]any    `json:"sampling"`
	Seeds           map[string]any    `json:"seeds"`
	Budgets         map[string]any    `json:"budgets"`
	EffectiveConfig any               `json:"effective_config,omitempty"`
}

// Results is the scored outcome of one results directory.
type Results struct {
	TruthVersion    int               `json:"truth_version"`
	ResultsDir      string            `json:"results_dir"`
	Provider        string            `json:"provider"` // backend as recorded (e.g. ollama, fake, transcript)
	Live            bool              `json:"live"`     // false for fixture/transcript providers
	Seeded          bool              `json:"seeded"`   // route/prior seeding applied
	PerLanguage     map[string]Bucket `json:"per_language"`
	PerFamily       map[string]Bucket `json:"per_family"`
	Supported       Supported         `json:"supported"`
	CandidateRecall Ratio             `json:"candidate_recall"`
	SafeControlFP   []SafeControlHit  `json:"safe_control_fp"`
	Verification    VerificationStats `json:"verification"`
	Coverage        CoverageStats     `json:"coverage"`
	Artifacts       ArtifactStats     `json:"artifacts"`
	Cost            Cost              `json:"cost"`
	Denominators    Denominators      `json:"denominators"`
	Config          RunConfig         `json:"config"`
	Notes           []string          `json:"notes"`
}

// scanMeta is the subset of scan_meta.json the scorer reads.
type scanMeta struct {
	Repo             string            `json:"repo"`
	Model            string            `json:"model"`
	VerifyModel      *string           `json:"verify_model"`
	ReconModel       string            `json:"recon_model"`
	ReproduceModel   string            `json:"reproduce_model"`
	Backend          string            `json:"backend"`
	StartedAt        float64           `json:"started_at"`
	FinishedAt       float64           `json:"finished_at"`
	Usage            map[string]any    `json:"usage"`
	ArtifactErrors   []string          `json:"artifact_errors"`
	GitCommit        string            `json:"git_commit"`
	EngineVersion    string            `json:"engine_version"`
	PromptHashes     map[string]string `json:"prompt_hashes"`
	ToolSchemaHashes map[string]string `json:"tool_schema_hashes"`
	HuntSamples      int               `json:"hunt_samples"`
	NumCtx           int               `json:"num_ctx"`
	MaxBudgetUSD     float64           `json:"max_budget_usd"`
	SeedRoutes       bool              `json:"seed_routes_applied"`
	SeedPrior        bool              `json:"seed_prior_applied"`
	EffectiveConfig  any               `json:"effective_config"`
	Agents           []struct {
		Model string `json:"model"`
	} `json:"agents"`
}

// Score scores resultsDir against truth. It never launches a scan.
func Score(resultsDir string, truth Truth) (Results, error) {
	res := Results{TruthVersion: truth.Version, ResultsDir: resultsDir, PerLanguage: map[string]Bucket{}, PerFamily: map[string]Bucket{},
		Supported: Supported{Matched: map[string]string{}, Unmatched: []string{}, Missed: []string{}}, SafeControlFP: []SafeControlHit{}, Notes: []string{}}
	var meta scanMeta
	if b, err := os.ReadFile(filepath.Join(resultsDir, "scan_meta.json")); err == nil {
		if err := json.Unmarshal(b, &meta); err != nil {
			return res, fmt.Errorf("scan_meta.json: %w", err)
		}
	} else {
		return res, fmt.Errorf("scan_meta.json: %w", err)
	}
	repo := meta.Repo
	if !filepath.IsAbs(repo) {
		repo = filepath.Join(filepath.Dir(resultsDir), repo)
	}
	fb, err := os.ReadFile(filepath.Join(resultsDir, "findings.json"))
	if err != nil {
		return res, fmt.Errorf("findings.json: %w", err)
	}
	var doc struct {
		Findings []map[string]any `json:"findings"`
	}
	if err := json.Unmarshal(fb, &doc); err != nil {
		return res, fmt.Errorf("findings.json: %w", err)
	}

	// Denominators and per-cell buckets from the truth.
	for _, e := range truth.Entries {
		if e.Expected == "vulnerable" {
			res.Denominators.VulnerableEntries++
			pl, pf := res.PerLanguage[e.Language], res.PerFamily[e.Family]
			pl.Denominator++
			pf.Denominator++
			res.PerLanguage[e.Language], res.PerFamily[e.Family] = pl, pf
		} else {
			res.Denominators.SafeControls++
		}
	}
	res.Supported.Denominator = res.Denominators.VulnerableEntries

	matcher := newMatcher(repo, truth)
	claimed := map[string]bool{}
	for _, f := range doc.Findings {
		if consolidate.Classify(f) != consolidate.ClassSupported {
			continue // rejected / unresolved / duplicates never count (C-C16)
		}
		res.Denominators.SupportedFindings++
		id := str(f["id"])
		loc := str(f["location"])
		e := matcher.match(loc, str(f["entry_point"]), familyOf(f), orDefault(str(f["normalized_cwe"]), str(f["cwe"])))
		lang := matcher.languageOf(loc)
		switch {
		case e == nil:
			res.Supported.FP++
			res.Supported.Unmatched = append(res.Supported.Unmatched, id)
			bump(res.PerLanguage, lang, func(b *Bucket) { b.FP++ })
			bump(res.PerFamily, familyOf(f), func(b *Bucket) { b.FP++ })
		case e.Expected == "safe_control":
			res.Supported.FP++
			res.SafeControlFP = append(res.SafeControlFP, SafeControlHit{TruthID: e.ID, Language: e.Language, Family: e.Family, FindingID: id, Location: loc})
			bump(res.PerLanguage, e.Language, func(b *Bucket) { b.FP++ })
			bump(res.PerFamily, e.Family, func(b *Bucket) { b.FP++ })
		case claimed[e.ID]:
			if res.Supported.RepeatHits == nil {
				res.Supported.RepeatHits = map[string][]string{}
			}
			res.Supported.RepeatHits[e.ID] = append(res.Supported.RepeatHits[e.ID], id)
		default:
			claimed[e.ID] = true
			res.Supported.TP++
			res.Supported.Matched[e.ID] = id
			bump(res.PerLanguage, e.Language, func(b *Bucket) { b.TP++ })
			bump(res.PerFamily, e.Family, func(b *Bucket) { b.TP++ })
		}
	}
	for _, e := range truth.Entries {
		if e.Expected == "vulnerable" && !claimed[e.ID] {
			res.Supported.FN++
			res.Supported.Missed = append(res.Supported.Missed, e.ID)
			bump(res.PerLanguage, e.Language, func(b *Bucket) { b.FN++ })
			bump(res.PerFamily, e.Family, func(b *Bucket) { b.FN++ })
		}
	}
	res.Supported.Bucket.finish()
	for k, b := range res.PerLanguage {
		b.finish()
		res.PerLanguage[k] = b
	}
	for k, b := range res.PerFamily {
		b.finish()
		res.PerFamily[k] = b
	}
	sort.Strings(res.Supported.Unmatched)
	sort.Strings(res.Supported.Missed)

	// Candidate recall: any manifest candidate (whatever its verdict) on a vulnerable entry.
	res.CandidateRecall = Ratio{Total: res.Denominators.VulnerableEntries}
	if mb, err := os.ReadFile(filepath.Join(resultsDir, "candidate_manifest.json")); err == nil {
		var man struct {
			Candidates []struct {
				ID      string `json:"id"`
				Finding struct {
					Location   string `json:"location"`
					EntryPoint string `json:"entry_point"`
					CWE        string `json:"cwe"`
					Family     string `json:"cwe_family"`
				} `json:"finding"`
			} `json:"candidates"`
		}
		if json.Unmarshal(mb, &man) == nil {
			res.Denominators.Candidates = len(man.Candidates)
			res.Verification.Candidates = len(man.Candidates)
			hit := map[string]bool{}
			for _, c := range man.Candidates {
				if e := matcher.match(c.Finding.Location, c.Finding.EntryPoint, c.Finding.Family, c.Finding.CWE); e != nil && e.Expected == "vulnerable" {
					hit[e.ID] = true
				}
			}
			for id := range hit {
				res.CandidateRecall.IDs = append(res.CandidateRecall.IDs, id)
			}
			sort.Strings(res.CandidateRecall.IDs)
			res.CandidateRecall.Matched = len(hit)
		}
	}

	// Verification stats from metrics + sessions (records only).
	res.Verification.TerminalByClass = map[string]int{}
	if vb, err := os.ReadFile(filepath.Join(resultsDir, "verification_metrics.json")); err == nil {
		var m struct {
			Supported, Rejected, Unresolved, InvalidCitation, AcceptedDecisions int
		}
		var raw map[string]any
		_ = json.Unmarshal(vb, &raw)
		m.Supported, m.Rejected, m.Unresolved = numOf(raw["supported"]), numOf(raw["rejected"]), numOf(raw["unresolved"])
		m.InvalidCitation, m.AcceptedDecisions = numOf(raw["invalid_citation"]), numOf(raw["accepted_decisions"])
		res.Verification.Supported, res.Verification.Rejected, res.Verification.Unresolved = m.Supported, m.Rejected, m.Unresolved
		res.Verification.InvalidCitation, res.Verification.Accepted = m.InvalidCitation, m.AcceptedDecisions
	}
	if sb, err := os.ReadFile(filepath.Join(resultsDir, "verification_sessions.json")); err == nil {
		var sessions []struct {
			StopReason      string         `json:"stop_reason"`
			Failures        int            `json:"failures"`
			FailuresByClass map[string]int `json:"failures_by_class"`
		}
		if json.Unmarshal(sb, &sessions) == nil {
			res.Verification.Sessions = len(sessions)
			for _, s := range sessions {
				if s.StopReason == "complete" && s.Failures > 0 {
					res.Verification.Recovered++
					continue
				}
				if s.StopReason != "complete" {
					best, bestN := "", 0
					for k, n := range s.FailuresByClass {
						if n > bestN || (n == bestN && k < best) {
							best, bestN = k, n
						}
					}
					if best == "" {
						best = s.StopReason
					}
					res.Verification.TerminalByClass[best]++
				}
			}
		}
	}

	// Coverage from review_units.json (v2 axes; v1 counts otherwise).
	if rb, err := os.ReadFile(filepath.Join(resultsDir, "review_units.json")); err == nil {
		var ru struct {
			SemanticsVersion int `json:"semantics_version"`
			Counts           struct {
				Total, ReviewedWithFindings, ReviewedNoIssue, SourceExposed int
			} `json:"counts"`
			Axes *struct {
				SourceExposed   int `json:"source_exposed"`
				CompletedReview int `json:"completed_review"`
			} `json:"axes"`
		}
		var raw struct {
			SemanticsVersion int            `json:"semantics_version"`
			Counts           map[string]int `json:"counts"`
			Axes             map[string]int `json:"axes"`
		}
		if json.Unmarshal(rb, &raw) == nil {
			_ = ru
			res.Coverage.SemanticsVersion = raw.SemanticsVersion
			if res.Coverage.SemanticsVersion == 0 {
				res.Coverage.SemanticsVersion = 1
			}
			res.Coverage.Total = raw.Counts["total"]
			res.Coverage.CompletedReview = raw.Counts["reviewed_with_findings"] + raw.Counts["reviewed_no_issue"]
			if raw.Axes != nil {
				res.Coverage.CompletedReview = raw.Axes["completed_review"]
				res.Coverage.SourceExposed = raw.Axes["source_exposed"]
			} else {
				res.Coverage.SourceExposed = res.Coverage.CompletedReview
			}
		}
	}

	// Artifacts and cost from scan_meta.
	res.Artifacts = ArtifactStats{Complete: len(meta.ArtifactErrors) == 0, Missing: append([]string{}, meta.ArtifactErrors...)}
	res.Cost = Cost{PromptTokens: numOf(meta.Usage["prompt_tokens"]), CompletionTokens: numOf(meta.Usage["completion_tokens"]), USD: "unknown"}
	if meta.FinishedAt > 0 && meta.StartedAt > 0 {
		res.Cost.Seconds = round(meta.FinishedAt - meta.StartedAt)
	}
	if p, ok := pricing.Lookup(meta.Backend, meta.Model); ok {
		res.Cost.USD = round(p.Cost(res.Cost.PromptTokens, res.Cost.CompletionTokens))
	} else {
		res.Notes = append(res.Notes, fmt.Sprintf("cost unknown: backend %q model %q is not in the reviewed price table", meta.Backend, meta.Model))
	}

	// Labels and config identity.
	res.Provider = meta.Backend
	res.Live = meta.Backend != "fake" && meta.Backend != "transcript"
	if !res.Live {
		res.Provider = "transcript"
		res.Notes = append(res.Notes, "offline run: a scripted transcript provider served every call — this proves the pipeline and scorer, not model efficacy")
	}
	res.Seeded = meta.SeedRoutes || meta.SeedPrior
	verify := meta.Model
	if meta.VerifyModel != nil && *meta.VerifyModel != "" {
		verify = *meta.VerifyModel
	}
	res.Config = RunConfig{
		TargetRevision: meta.GitCommit, Backend: meta.Backend,
		Build:       map[string]string{"engine_version": meta.EngineVersion},
		Models:      map[string]string{"hunt": meta.Model, "verify": verify, "recon": orDefault(meta.ReconModel, meta.Model), "reproduce": orDefault(meta.ReproduceModel, meta.Model)},
		PromptsHash: orMap(meta.PromptHashes), ToolSchemaHash: orMap(meta.ToolSchemaHashes),
		Sampling:        map[string]any{"hunt_samples": max(meta.HuntSamples, 1)},
		Seeds:           map[string]any{"seed_routes": meta.SeedRoutes, "seed_prior": meta.SeedPrior},
		Budgets:         map[string]any{"max_budget_usd": meta.MaxBudgetUSD, "num_ctx": meta.NumCtx},
		EffectiveConfig: meta.EffectiveConfig,
	}
	if res.Config.TargetRevision == "" {
		res.Config.TargetRevision = "unknown (no git provenance recorded)"
	}
	return res, nil
}

// ---- matching -------------------------------------------------------------

var reLoc = regexp.MustCompile(`^([^\s:]+):(\d+)`)

type matcher struct {
	repo    string
	entries []Entry
	byFile  map[string][]int
	cache   map[string][]string
}

func newMatcher(repo string, t Truth) *matcher {
	m := &matcher{repo: repo, entries: t.Entries, byFile: map[string][]int{}, cache: map[string][]string{}}
	for i, e := range t.Entries {
		files := map[string]bool{e.Anchor.File: true}
		for _, am := range e.AcceptableMatches {
			if am.File != "" {
				files[am.File] = true
			}
		}
		for f := range files {
			m.byFile[f] = append(m.byFile[f], i)
		}
	}
	return m
}

func (m *matcher) languageOf(loc string) string {
	file := loc
	if i := strings.IndexByte(loc, ':'); i >= 0 {
		file = loc[:i]
	}
	if lang, ok := recognize.LanguageFor(file); ok {
		return string(lang)
	}
	return "unknown"
}

// match returns the truth entry a location/entry point hits: same file and (line
// within the anchor range, or the enclosing function equals the anchor/acceptable
// function), or the entry point equals an acceptable route.
func (m *matcher) match(loc, entryPoint, family, cwe string) *Entry {
	mm := reLoc.FindStringSubmatch(strings.TrimSpace(loc))
	route := normRoute(entryPoint)
	var file string
	line := 0
	if mm != nil {
		file = filepath.ToSlash(filepath.Clean(mm[1]))
		line, _ = strconv.Atoi(mm[2])
	}
	fn := ""
	if file != "" && line > 0 {
		fn = m.enclosing(file, line)
	}
	for i := range m.entries {
		e := &m.entries[i]
		if !strings.EqualFold(family, e.Family) && !strings.EqualFold(cwe, e.CWE) {
			continue // a different weakness at the same location is not a detection
		}
		if file != "" && (e.Anchor.File == file) {
			if line >= e.Anchor.Lines[0] && line <= e.Anchor.Lines[1] {
				return e
			}
			if fn != "" && fn == e.Anchor.Function {
				return e
			}
		}
		for _, am := range e.AcceptableMatches {
			if am.File != "" && am.File == file && fn != "" && fn == am.Function {
				return e
			}
			if am.Route != "" && route != "" && normRoute(am.Route) == route {
				return e
			}
		}
	}
	return nil
}

// enclosing resolves the function containing a line via recognize (Python/Go named
// scopes; brace languages have no owner and fall back to the line range rule).
func (m *matcher) enclosing(file string, line int) string {
	src, err := source.ReadFile(m.repo, file)
	if err != nil {
		return ""
	}
	lang, ok := recognize.LanguageFor(file)
	if !ok {
		return ""
	}
	sc := recognize.EnclosingScope(lang, src, line)
	if !sc.Found || len(sc.Owner) == 0 {
		return ""
	}
	return sc.Owner[len(sc.Owner)-1]
}

// normRoute keeps "METHOD /path" (drops query strings and trailing prose).
func normRoute(s string) string {
	f := strings.Fields(strings.TrimSpace(s))
	if len(f) < 2 {
		return ""
	}
	path := f[1]
	if i := strings.IndexByte(path, '?'); i >= 0 {
		path = path[:i]
	}
	return strings.ToUpper(f[0]) + " " + path
}

// ---- baseline / policy / comparison ---------------------------------------

// Tolerance is the declared per-metric slack (absolute deltas).
type Tolerance struct {
	Precision     float64 `json:"precision"`
	Recall        float64 `json:"recall"`
	SafeControlFP int     `json:"safe_control_fp"`
}

// Policy is the parsed POLICY.md contract.
type Policy struct {
	Version   string    `json:"version"`
	Tolerance Tolerance `json:"tolerance"`
}

var reFence = regexp.MustCompile("(?s)```json\\s*(\\{.*?\\})\\s*```")

// LoadPolicy requires an explicit version and tolerances; no silent policy changes.
func LoadPolicy(path string) (Policy, error) {
	var p Policy
	b, err := os.ReadFile(path)
	if err != nil {
		return p, err
	}
	if m := reFence.FindSubmatch(b); m != nil {
		if err := json.Unmarshal(m[1], &p); err != nil {
			return p, fmt.Errorf("policy block: %w", err)
		}
	} else {
		return p, fmt.Errorf("policy requires a fenced JSON block")
	}
	if p.Version != "1" || !validTolerance(p.Tolerance) {
		return p, fmt.Errorf("unsupported policy or invalid tolerance")
	}
	return p, nil
}

func validTolerance(t Tolerance) bool {
	return t.Precision >= 0 && t.Precision <= 1 && t.Recall >= 0 && t.Recall <= 1 && t.SafeControlFP >= 0
}

// Baseline is a frozen scored run (testdata/benchmark/baseline/<date>.json).
type Baseline struct {
	FrozenAt      string    `json:"frozen_at"`
	Provider      string    `json:"provider"`
	Live          bool      `json:"live"`
	Seeded        bool      `json:"seeded"`
	Config        RunConfig `json:"config"`
	Results       Results   `json:"results"`
	Runs          []Run     `json:"runs"`
	Variation     Variation `json:"variation"`
	PolicyVersion string    `json:"policy_version"`
	Tolerance     Tolerance `json:"tolerance"`
}

// Run is one scored run inside a baseline.
type Run struct {
	ResultsDir string  `json:"results_dir"`
	Results    Results `json:"results"`
}

// Variation is the run-to-run spread of the headline rates.
type Variation struct {
	PrecisionRange [2]float64 `json:"precision_range"`
	RecallRange    [2]float64 `json:"recall_range"`
	Runs           int        `json:"runs"`
}

// LoadBaseline reads a baseline file.
func LoadBaseline(path string) (Baseline, error) {
	var b Baseline
	data, err := os.ReadFile(path)
	if err != nil {
		return b, err
	}
	if err := json.Unmarshal(data, &b); err != nil {
		return b, fmt.Errorf("baseline: %w", err)
	}
	if b.PolicyVersion != "1" || b.Results.TruthVersion != 2 || !validTolerance(b.Tolerance) {
		return b, fmt.Errorf("baseline lacks a supported policy/truth version or has invalid tolerances")
	}
	return b, nil
}

// NewBaseline freezes one or more scored runs (the first is the headline).
func NewBaseline(frozenAt string, policy Policy, runs ...Run) Baseline {
	b := Baseline{FrozenAt: frozenAt, PolicyVersion: policy.Version, Tolerance: policy.Tolerance, Runs: runs}
	if len(runs) == 0 {
		return b
	}
	b.Results, b.Config, b.Provider, b.Live, b.Seeded = runs[0].Results, runs[0].Results.Config, runs[0].Results.Provider, runs[0].Results.Live, runs[0].Results.Seeded
	b.Variation = Variation{Runs: len(runs), PrecisionRange: [2]float64{runs[0].Results.Supported.Precision, runs[0].Results.Supported.Precision},
		RecallRange: [2]float64{runs[0].Results.Supported.Recall, runs[0].Results.Supported.Recall}}
	for _, r := range runs[1:] {
		p, rc := r.Results.Supported.Precision, r.Results.Supported.Recall
		b.Variation.PrecisionRange = [2]float64{minF(b.Variation.PrecisionRange[0], p), maxF(b.Variation.PrecisionRange[1], p)}
		b.Variation.RecallRange = [2]float64{minF(b.Variation.RecallRange[0], rc), maxF(b.Variation.RecallRange[1], rc)}
	}
	return b
}

// Regression is one policy breach relative to the baseline.
type Regression struct {
	Scope     string  `json:"scope"` // "supported", "language:python", "family:xss", "safe_control_fp"
	Metric    string  `json:"metric"`
	Baseline  float64 `json:"baseline"`
	Current   float64 `json:"current"`
	Tolerance float64 `json:"tolerance"`
}

// Compare applies the policy: a per-language/per-family (and headline) drop in
// precision or recall, or a rise in safe-control false positives, beyond the
// tolerance is a regression. No absolute threshold is asserted.
func Compare(cur Results, base Baseline, policy Policy) []Regression {
	tol := policy.Tolerance
	if base.Tolerance != (Tolerance{}) {
		tol = base.Tolerance
	}
	var out []Regression
	cell := func(scope string, b, c Bucket) {
		if b.Denominator == 0 && c.Denominator == 0 && b.TP+b.FP == 0 {
			return
		}
		if c.Precision < b.Precision-tol.Precision {
			out = append(out, Regression{Scope: scope, Metric: "precision", Baseline: b.Precision, Current: c.Precision, Tolerance: tol.Precision})
		}
		if c.Recall < b.Recall-tol.Recall {
			out = append(out, Regression{Scope: scope, Metric: "recall", Baseline: b.Recall, Current: c.Recall, Tolerance: tol.Recall})
		}
	}
	cell("supported", base.Results.Supported.Bucket, cur.Supported.Bucket)
	for _, k := range sortedKeys(base.Results.PerLanguage) {
		cell("language:"+k, base.Results.PerLanguage[k], cur.PerLanguage[k])
	}
	for _, k := range sortedKeys(base.Results.PerFamily) {
		cell("family:"+k, base.Results.PerFamily[k], cur.PerFamily[k])
	}
	if len(cur.SafeControlFP) > len(base.Results.SafeControlFP)+tol.SafeControlFP {
		out = append(out, Regression{Scope: "safe_control_fp", Metric: "count", Baseline: float64(len(base.Results.SafeControlFP)), Current: float64(len(cur.SafeControlFP)), Tolerance: float64(tol.SafeControlFP)})
	}
	// A reduction in one language must not conceal a new safe-control failure
	// elsewhere. Apply the declared tolerance to each language/family as well.
	byScope := func(hits []SafeControlHit) map[string]int {
		m := map[string]int{}
		for _, h := range hits {
			m["language:"+h.Language]++
			m["family:"+h.Family]++
		}
		return m
	}
	bc, cc := byScope(base.Results.SafeControlFP), byScope(cur.SafeControlFP)
	for _, scope := range sortedKeys(cc) {
		if cc[scope] > bc[scope]+tol.SafeControlFP {
			out = append(out, Regression{Scope: scope, Metric: "safe_control_fp", Baseline: float64(bc[scope]), Current: float64(cc[scope]), Tolerance: float64(tol.SafeControlFP)})
		}
	}
	return out
}

// ConfigDiff lists every configuration/build difference between a run and the
// baseline — printed FIRST by every comparison (C-C18).
func ConfigDiff(cur RunConfig, base RunConfig) []string {
	var out []string
	add := func(k, a, b string) {
		if a != b {
			out = append(out, fmt.Sprintf("%s: baseline %q → current %q", k, b, a))
		}
	}
	add("target_revision", cur.TargetRevision, base.TargetRevision)
	curEffective, _ := json.Marshal(cur.EffectiveConfig)
	baseEffective, _ := json.Marshal(base.EffectiveConfig)
	add("effective_config", string(curEffective), string(baseEffective))
	add("backend", cur.Backend, base.Backend)
	for _, k := range mergedKeys(cur.Build, base.Build) {
		add("build."+k, cur.Build[k], base.Build[k])
	}
	for _, k := range mergedKeys(cur.Models, base.Models) {
		add("models."+k, cur.Models[k], base.Models[k])
	}
	for _, k := range mergedKeys(cur.PromptsHash, base.PromptsHash) {
		add("prompts_hash."+k, cur.PromptsHash[k], base.PromptsHash[k])
	}
	for _, k := range mergedKeys(cur.ToolSchemaHash, base.ToolSchemaHash) {
		add("tool_schema_hash."+k, cur.ToolSchemaHash[k], base.ToolSchemaHash[k])
	}
	for _, name := range []string{"sampling", "seeds", "budgets"} {
		var a, b map[string]any
		switch name {
		case "sampling":
			a, b = cur.Sampling, base.Sampling
		case "seeds":
			a, b = cur.Seeds, base.Seeds
		default:
			a, b = cur.Budgets, base.Budgets
		}
		keys := map[string]bool{}
		for k := range a {
			keys[k] = true
		}
		for k := range b {
			keys[k] = true
		}
		for _, k := range sortedKeys(keys) {
			add(name+"."+k, fmt.Sprint(a[k]), fmt.Sprint(b[k]))
		}
	}
	if out == nil {
		out = []string{}
	}
	return out
}

// ---- helpers --------------------------------------------------------------

func bump(m map[string]Bucket, key string, f func(*Bucket)) {
	if key == "" {
		key = "unknown"
	}
	b := m[key]
	f(&b)
	m[key] = b
}

func familyOf(f map[string]any) string {
	for _, k := range []string{"cwe_family", "normalized_cwe", "cwe"} {
		if s := str(f[k]); s != "" {
			return strings.ToLower(s)
		}
	}
	return "unknown"
}

func str(v any) string {
	s, _ := v.(string)
	return s
}

func numOf(v any) int {
	switch n := v.(type) {
	case float64:
		return int(n)
	case int:
		return n
	}
	return 0
}

func round(f float64) float64 { return float64(int(f*10000+0.5)) / 10000 }

func orDefault(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func orMap(m map[string]string) map[string]string {
	if m == nil {
		return map[string]string{}
	}
	return m
}

func minF(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}

func maxF(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func mergedKeys(a, b map[string]string) []string {
	keys := map[string]bool{}
	for k := range a {
		keys[k] = true
	}
	for k := range b {
		keys[k] = true
	}
	return sortedKeys(keys)
}
