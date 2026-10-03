package parity

import (
	"crypto/sha1"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Projection is the canonical semantic reduction of a results directory — the
// dimensions parity is judged on (feature 006, US2; data-model §Semantic
// projection). Everything is sorted/keyed so two runs of the same behavior project
// identically regardless of incidental ordering, timestamps, or raw candidate IDs.
type Projection struct {
	Dispatch     []DispatchUnit    `json:"dispatch"`
	Passes       []string          `json:"passes"`
	Candidates   []ProjCandidate   `json:"candidates"`
	Dispositions map[string]string `json:"dispositions"`
	Tiers        map[string]string `json:"tiers"`
	Coverage     map[string]string `json:"coverage"`
	Handoffs     []string          `json:"handoffs"`
	Artifacts    []string          `json:"artifacts"`
	RunStatus    RunStatusProj     `json:"run_status"`
}

// DispatchUnit is one (partition, class) hunt unit.
type DispatchUnit struct {
	Partition string `json:"partition"`
	Class     string `json:"class"`
}

// ProjCandidate is a candidate keyed by its normalized identity (stable across the
// Go-heuristic vs Python-AST raw-id difference).
type ProjCandidate struct {
	NormID   string `json:"norm_id"`
	CWE      string `json:"cwe"`
	Location string `json:"location"`
}

// RunStatusProj is the three-axis run status (degraded reasons compared set-wise).
type RunStatusProj struct {
	Execution       string   `json:"execution"`
	Coverage        string   `json:"coverage"`
	ValidationMode  string   `json:"validation_mode"`
	CoverageReasons []string `json:"coverage_reasons"`
}

var reCWE = regexp.MustCompile(`(?i)CWE-?(\d+)`)
var reLine = regexp.MustCompile(`:(\d+)`)

// NormID computes the stable candidate identity: sha1(normPath:line:CWE).
// Exact fixture locations prevent nearby, distinct sinks from collapsing.
// The CWE is normalized to its bare number.
func NormID(location, cwe string) string {
	path := location
	if i := strings.IndexByte(location, ':'); i >= 0 {
		path = location[:i]
	}
	bucket := 0
	if m := reLine.FindStringSubmatch(location); m != nil {
		n, _ := strconv.Atoi(m[1])
		bucket = n
	}
	num := ""
	if m := reCWE.FindStringSubmatch(cwe); m != nil {
		num = m[1]
	}
	sum := sha1.Sum([]byte(fmt.Sprintf("%s:%d:%s", filepath.ToSlash(path), bucket, num)))
	return fmt.Sprintf("%x", sum)[:16]
}

// Project reduces a results directory to its canonical Projection.
func Project(dir string) (Projection, error) {
	p := Projection{
		Dispositions: map[string]string{}, Tiers: map[string]string{},
		Coverage: map[string]string{},
	}
	// Dispatch + passes from the per-unit hunt files under results/.
	entries, _ := os.ReadDir(filepath.Join(dir, "results"))
	seen := map[DispatchUnit]bool{}
	passes := map[string]bool{}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".md") {
			continue
		}
		if regexp.MustCompile(`\.s\d+\.md$`).MatchString(name) { // per-sample file
			continue
		}
		base := strings.TrimSuffix(name, ".md")
		switch {
		case base == "sink_driven":
			passes["sink"] = true
		case strings.HasPrefix(base, "iac"):
			passes["iac"] = true
		default:
			if i := strings.LastIndexByte(base, '_'); i > 0 {
				u := DispatchUnit{Partition: base[:i], Class: base[i+1:]}
				// Feature 014 (FR-015): coverage follow-up units (`<partition>_followup.md`)
				// are a deliberate, documented divergence from the Python reference's
				// fan-out — bounded recovery for unreviewed entry points, recorded in
				// review_units.json — so they are not part of the reference dispatch contract.
				if u.Class == "followup" {
					continue
				}
				if !seen[u] {
					seen[u] = true
					p.Dispatch = append(p.Dispatch, u)
				}
			}
		}
	}
	sort.Slice(p.Dispatch, func(i, j int) bool {
		if p.Dispatch[i].Partition != p.Dispatch[j].Partition {
			return p.Dispatch[i].Partition < p.Dispatch[j].Partition
		}
		return p.Dispatch[i].Class < p.Dispatch[j].Class
	})
	for k := range passes {
		p.Passes = append(p.Passes, k)
	}
	sort.Strings(p.Passes)

	// Candidates / dispositions / tiers / run_status from findings.json.
	if b, err := os.ReadFile(filepath.Join(dir, "findings.json")); err == nil {
		var doc map[string]any
		if json.Unmarshal(b, &doc) == nil {
			if fs, ok := doc["findings"].([]any); ok {
				for _, fi := range fs {
					f, _ := fi.(map[string]any)
					if f == nil || f["duplicate_of"] != nil {
						continue
					}
					loc, _ := f["location"].(string)
					cwe, _ := f["cwe"].(string)
					id := NormID(loc, cwe)
					p.Candidates = append(p.Candidates, ProjCandidate{NormID: id, CWE: normCWE(cwe), Location: loc})
					if vs, _ := f["verification_status"].(string); vs != "" {
						p.Dispositions[id] = vs
					}
					if cl, _ := f["classification"].(string); cl != "" {
						p.Tiers[id] = cl
					}
				}
			}
			sort.Slice(p.Candidates, func(i, j int) bool { return p.Candidates[i].NormID < p.Candidates[j].NormID })
			if rs, ok := doc["run_status"].(map[string]any); ok {
				p.RunStatus.Execution, _ = rs["execution_status"].(string)
				p.RunStatus.Coverage, _ = rs["coverage_status"].(string)
				p.RunStatus.ValidationMode, _ = rs["validation_mode"].(string)
				if reasons, ok := rs["coverage_degraded_reasons"].([]any); ok {
					for _, r := range reasons {
						if s, _ := r.(string); s != "" {
							p.RunStatus.CoverageReasons = append(p.RunStatus.CoverageReasons, s)
						}
					}
					sort.Strings(p.RunStatus.CoverageReasons)
				}
			}
		}
	}

	// Coverage entry -> disposition from the coverage ledger.
	if b, err := os.ReadFile(filepath.Join(dir, "coverage_ledger.json")); err == nil {
		var lg struct {
			Entries []struct {
				Method, Path, Disposition string
			} `json:"entries"`
		}
		if json.Unmarshal(b, &lg) == nil {
			for _, e := range lg.Entries {
				p.Coverage[e.Method+" "+e.Path] = e.Disposition
			}
		}
	}

	// Handoffs present (by filename).
	for _, name := range []string{"phase2b_handoff.md", "phase3_output.md", "phase3d_output.md"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err == nil {
			p.Handoffs = append(p.Handoffs, name)
		}
	}
	sort.Strings(p.Handoffs)

	// Artifact-manifest entry kinds (sorted, de-duplicated).
	if b, err := os.ReadFile(filepath.Join(dir, "artifact_manifest.json")); err == nil {
		var arr []map[string]any
		if json.Unmarshal(b, &arr) == nil {
			kinds := map[string]bool{}
			for _, e := range arr {
				if k, _ := e["kind"].(string); k != "" {
					kinds[k] = true
				}
			}
			for k := range kinds {
				p.Artifacts = append(p.Artifacts, k)
			}
			sort.Strings(p.Artifacts)
		}
	}
	return p, nil
}

func normCWE(cwe string) string {
	if m := reCWE.FindStringSubmatch(cwe); m != nil {
		return "CWE-" + m[1]
	}
	return cwe
}
