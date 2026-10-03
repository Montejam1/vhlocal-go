package engine

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
	"vhlocal/internal/benchmark"
	"vhlocal/internal/client"
	"vhlocal/internal/pricing"
	"vhlocal/internal/tools"
	"vhlocal/internal/verification"
)

type CompareVariant struct {
	Name, Model, Prompt, Backend, Endpoint string
	Provider                               client.Provider // nil records a planned, not-run variant
}
type ComparisonSpec struct {
	Manifest, Repo, Revision, OutputDir, SkillDir, Truth string
	NumCtx, MaxOutputTokens                              int
	Variants                                             []CompareVariant
}
type CompareGate struct {
	EfficacyImproved bool   `json:"efficacy_improved"`
	Reason           string `json:"reason"`
}
type CompareDecisions struct {
	Supported          int `json:"supported"`
	Rejected           int `json:"rejected"`
	UnresolvedExplicit int `json:"unresolved_explicit"`
	Missing            int `json:"missing"`
}
type VariantResult struct {
	Name              string              `json:"name"`
	Model             string              `json:"model"`
	Backend           string              `json:"backend"`
	Endpoint          string              `json:"endpoint"`
	PromptHash        string              `json:"prompt_hash"`
	ResultsDir        string              `json:"results_dir,omitempty"`
	NotRun            bool                `json:"not_run"`
	Decisions         CompareDecisions    `json:"decisions"`
	RepairRate        float64             `json:"repair_rate"`
	EvidenceValidRate float64             `json:"evidence_valid_rate"`
	Seconds           float64             `json:"seconds"`
	Cost              any                 `json:"cost_usd"`
	Provenance        []client.Provenance `json:"provenance"`
	TruthAccuracy     *benchmark.Results  `json:"truth_accuracy,omitempty"`
	Gate              CompareGate         `json:"gate"`
}
type ComparisonResult struct {
	ConfigDiff        []string        `json:"config_diff"`
	ManifestRef       string          `json:"manifest_ref"`
	Revision          string          `json:"revision"`
	SourceFingerprint string          `json:"source_fingerprint"`
	Variants          []VariantResult `json:"variants"`
	NotRun            bool            `json:"not_run"`
}

func comparisonEndpoint(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return "[invalid endpoint]"
	}
	u.User, u.RawQuery, u.Fragment = nil, "", ""
	return u.String()
}

// SourceFingerprint hashes file content and symlink destinations, without executing
// target code or following symlinks. Git administration files are excluded.
func SourceFingerprint(repo string) (string, error) {
	h := sha256.New()
	err := filepath.WalkDir(repo, func(p string, d fs.DirEntry, e error) error {
		if e != nil {
			return e
		}
		if d.IsDir() {
			if d.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		rel, e := filepath.Rel(repo, p)
		if e != nil {
			return e
		}
		fmt.Fprintf(h, "%s\x00", filepath.ToSlash(rel))
		if d.Type()&os.ModeSymlink != 0 {
			dest, e := os.Readlink(p)
			fmt.Fprintf(h, "symlink:%s\x00", dest)
			return e
		}
		if !d.Type().IsRegular() {
			return fmt.Errorf("unsupported source file %s", rel)
		}
		f, e := os.Open(p)
		if e != nil {
			return e
		}
		_, e = io.Copy(h, f)
		f.Close()
		h.Write([]byte{0})
		return e
	})
	return fmt.Sprintf("tree-sha256:%x", h.Sum(nil)), err
}

type comparisonProvider struct {
	client.Provider
	Calls []client.Provenance
}

func (p *comparisonProvider) Chat(ctx context.Context, r client.ChatRequest) (*client.ChatResponse, error) {
	out, e := p.Provider.Chat(ctx, r)
	pr := client.Provenance{Backend: p.Backend(), Endpoint: p.Endpoint(), RequestedModel: r.Model}
	if out != nil {
		pr = out.Provenance
		if pr.Backend == "" {
			pr.Backend = p.Backend()
		}
		if pr.Endpoint == "" {
			pr.Endpoint = p.Endpoint()
		}
		if pr.RequestedModel == "" {
			pr.RequestedModel = r.Model
		}
	}
	if out != nil {
		out.Provenance = pr
	}
	p.Calls = append(p.Calls, pr)
	return out, e
}

// CompareVerification runs only verification into NEW directories. It never
// regenerates or amends the frozen input and has no default remote provider.
func CompareVerification(ctx context.Context, s ComparisonSpec) (ComparisonResult, error) {
	result := ComparisonResult{ManifestRef: s.Manifest, Revision: s.Revision, ConfigDiff: []string{}, Variants: []VariantResult{}}
	b, err := os.ReadFile(s.Manifest)
	if err != nil {
		return result, err
	}
	var frozen verification.Manifest
	if err = json.Unmarshal(b, &frozen); err != nil {
		return result, err
	}
	if s.Revision == "" || frozen.Revision != s.Revision {
		return result, fmt.Errorf("manifest revision does not match requested revision")
	}
	repo, err := filepath.EvalSymlinks(s.Repo)
	if err != nil {
		return result, err
	}
	repo, _ = filepath.Abs(repo)
	s.Repo = repo
	originalRepo, _ := filepath.EvalSymlinks(frozen.Repo)
	originalRepo, _ = filepath.Abs(originalRepo)
	if originalRepo != repo {
		return result, fmt.Errorf("manifest repository does not match target")
	}
	fingerprint, err := SourceFingerprint(repo)
	if err != nil {
		return result, err
	}
	result.SourceFingerprint = fingerprint
	git := client.Git(repo)
	if s.Revision != fingerprint && (git.Commit != s.Revision || git.Dirty) {
		return result, fmt.Errorf("target is not the frozen revision (use an unchanged checkout or matching tree fingerprint)")
	}
	out, err := filepath.Abs(s.OutputDir)
	if err != nil || s.OutputDir == "" {
		return result, fmt.Errorf("new output directory required")
	}
	// Resolve the parent so a symlink cannot place output inside the target.
	parent, err := filepath.EvalSymlinks(filepath.Dir(out))
	if err != nil {
		return result, err
	}
	out = filepath.Join(parent, filepath.Base(out))
	rel, _ := filepath.Rel(repo, out)
	if rel == "." || (!strings.HasPrefix(rel, ".."+string(filepath.Separator)) && rel != "..") {
		return result, fmt.Errorf("comparison output must be outside target")
	}
	if len(s.Variants) == 0 {
		return result, fmt.Errorf("at least one variant required")
	}
	if err = os.Mkdir(out, 0700); err != nil {
		return result, fmt.Errorf("comparison requires a new output directory: %w", err)
	}
	var truth *benchmark.Truth
	if s.Truth != "" {
		t, e := benchmark.LoadTruth(s.Truth)
		if e != nil {
			return result, e
		}
		truth = &t
	}
	for i, v := range s.Variants {
		if ctx.Err() != nil {
			return result, ctx.Err()
		}
		current, e := SourceFingerprint(repo)
		if e != nil || current != fingerprint {
			return result, fmt.Errorf("source changed during comparison")
		}
		vr := VariantResult{Name: v.Name, Model: v.Model, Backend: v.Backend, Endpoint: comparisonEndpoint(v.Endpoint), PromptHash: sha256Hex([]byte(verifySystem(baseSystem, v.Prompt))), Cost: "unknown", Gate: CompareGate{Reason: "not_run"}}
		if i > 0 {
			prior := s.Variants[0]
			if prior.Backend != v.Backend || prior.Endpoint != v.Endpoint {
				result.ConfigDiff = append(result.ConfigDiff, v.Name+" requested provider/endpoint differs")
			}
			if prior.Model != v.Model {
				result.ConfigDiff = append(result.ConfigDiff, fmt.Sprintf("%s model: %s -> %s", v.Name, prior.Model, v.Model))
			}
			if prior.Prompt != v.Prompt {
				result.ConfigDiff = append(result.ConfigDiff, v.Name+" prompt differs")
			}
		}
		if v.Provider == nil {
			vr.NotRun = true
			result.NotRun = true
			result.Variants = append(result.Variants, vr)
			continue
		}
		vr.Backend, vr.Endpoint = string(v.Provider.Backend()), v.Provider.Endpoint()
		if i > 0 && s.Variants[0].Provider != nil && (vr.Backend != string(s.Variants[0].Provider.Backend()) || vr.Endpoint != s.Variants[0].Provider.Endpoint()) {
			result.ConfigDiff = append(result.ConfigDiff, v.Name+" provider/endpoint differs")
		}
		vr.ResultsDir = filepath.Join(out, fmt.Sprintf("variant-%02d", i+1))
		if err = os.Mkdir(vr.ResultsDir, 0700); err != nil {
			return result, err
		}
		spec := ScanSpec{Repo: repo, ResultsDir: vr.ResultsDir, SkillDir: s.SkillDir, Model: v.Model, VerifyModel: v.Model, Backend: vr.Backend, Host: vr.Endpoint, NumCtx: s.NumCtx, MaxOutputTokens: s.MaxOutputTokens, Phases: []string{"2b"}}
		rec := &RunRecord{PromptHashes: map[string]string{"2b": vr.PromptHash}, ToolSchemaHashes: map[string]string{}, Repo: repo, ResultsDir: vr.ResultsDir, GitCommit: s.Revision, Model: v.Model, Backend: vr.Backend, Host: vr.Endpoint, StartedAt: nowUnix(), Usage: map[string]any{}, PhasesRequested: []string{"2b"}}
		schema, _ := json.Marshal(verifyToolEnvelope())
		rec.ToolSchemaHashes["2b"] = sha256Hex(schema)
		sb, e := tools.NewSandbox(repo, s.SkillDir, vr.ResultsDir)
		if e != nil {
			return result, e
		}
		provider := &comparisonProvider{Provider: v.Provider}
		start := time.Now()
		if runVerificationWith(ctx, rec, provider, sb, spec, baseSystem, verifyOptions{sessionPrompt: v.Prompt, frozenManifest: &frozen}, nil) {
			rec.PhasesCompleted = []string{"2b"}
		}
		current, e = SourceFingerprint(repo)
		if e != nil || current != fingerprint {
			return result, fmt.Errorf("source changed during comparison")
		}
		vr.Seconds = time.Since(start).Seconds()
		vr.Provenance = provider.Calls
		rec.FinishedAt = nowUnix()
		if _, e = rec.Write(vr.ResultsDir); e != nil {
			return result, e
		}
		var decisions []verification.Decision
		db, e := os.ReadFile(filepath.Join(vr.ResultsDir, verification.DecisionsFile))
		if e != nil {
			return result, e
		}
		if e = json.Unmarshal(db, &decisions); e != nil {
			return result, e
		}
		finalBytes, e := os.ReadFile(filepath.Join(vr.ResultsDir, verification.CandidateManifestFile))
		if e != nil {
			return result, e
		}
		var finalMan verification.Manifest
		if e = json.Unmarshal(finalBytes, &finalMan); e != nil {
			return result, e
		}
		rc := verification.Reconcile(&finalMan, decisions, repo)
		for _, r := range rc.Results {
			switch {
			case r.Record == nil:
				vr.Decisions.Missing++
			case r.Status == "supported":
				vr.Decisions.Supported++
			case r.Status == "rejected":
				vr.Decisions.Rejected++
			default:
				vr.Decisions.UnresolvedExplicit++
			}
		}
		accepted := vr.Decisions.Supported + vr.Decisions.Rejected + vr.Decisions.UnresolvedExplicit
		if len(rc.Results) > 0 {
			vr.EvidenceValidRate = float64(vr.Decisions.Supported+vr.Decisions.Rejected) / float64(len(rc.Results))
		}
		sessions := verification.LoadSessions(vr.ResultsDir)
		repaired := 0
		for _, ss := range sessions {
			if len(ss.FailuresByClass) > 0 && ss.StopReason == "complete" {
				repaired++
			}
		}
		if len(sessions) > 0 {
			vr.RepairRate = float64(repaired) / float64(len(sessions))
		}
		if p, ok := pricing.Lookup(vr.Backend, v.Model); ok {
			pt, ct := usageTiles(rec)
			vr.Cost = p.Cost(pt, ct)
		}
		vr.Gate.Reason = "accuracy_not_measured"
		if accepted > 0 && float64(vr.Decisions.UnresolvedExplicit)/float64(accepted) >= .95 {
			vr.Gate.Reason = "all_unresolved"
		}
		if truth != nil {
			fs := verification.FinalFindings(&finalMan, rc)
			if _, e = writeJSON(filepath.Join(vr.ResultsDir, "findings.json"), map[string]any{"findings": fs}); e != nil {
				return result, e
			}
			scored, e := benchmark.Score(vr.ResultsDir, *truth)
			if e != nil {
				return result, e
			}
			vr.TruthAccuracy = &scored
			if vr.Gate.Reason != "all_unresolved" && len(result.Variants) > 0 && result.Variants[0].TruthAccuracy != nil {
				baseline := result.Variants[0].TruthAccuracy
				regressions := benchmark.Compare(scored, benchmark.NewBaseline("comparison", benchmark.Policy{Version: "1"}, benchmark.Run{Results: *baseline}), benchmark.Policy{Version: "1"})
				vr.Gate.EfficacyImproved = len(regressions) == 0 && (scored.Supported.Precision > baseline.Supported.Precision || scored.Supported.Recall > baseline.Supported.Recall)
				vr.Gate.Reason = "ground_truth_comparison"
			}
		}
		result.Variants = append(result.Variants, vr)
		if _, e = writeJSON(filepath.Join(out, "comparison.json"), result); e != nil {
			return result, e
		}
	}
	_, err = writeJSON(filepath.Join(out, "comparison.json"), result)
	return result, err
}
