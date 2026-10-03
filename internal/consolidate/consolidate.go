package consolidate

import (
	"encoding/json"
	"os"
	"path/filepath"
)

const (
	FindingsJSONFile = "findings.json"
	ScanReportMDFile = "SCAN_REPORT.md"
)

// CoverageInfo is the coverage block embedded in findings.json (nil when no
// ledger was built).
type CoverageInfo struct {
	TotalEntryPoints int  `json:"total_entry_points"`
	Reviewed         int  `json:"reviewed"`
	NotReviewed      int  `json:"not_reviewed"`
	Complete         bool `json:"complete"`
}

// Options carry the non-finding inputs needed to assemble findings.json.
type Options struct {
	Meta                map[string]any // the scan_meta dict, embedded under "meta"
	EngineVersion       string
	HuntModel           string
	VerifyModel         string
	Status              RunStatus
	Coverage            *CoverageInfo
	SBOM                any // sbom.Summary or nil
	Lifecycle           any // lifecycle block or nil
	VulnerabilityLedger any // membank coverage summary or nil
	Remediation         any // remediation summary or nil
}

// Doc is the top-level findings.json structure (field order mirrors Python).
type Doc struct {
	Meta        map[string]any `json:"meta"`
	Attribution Attribution    `json:"attribution"`
	RunStatus   RunStatus      `json:"run_status"`
	Coverage    *CoverageInfo  `json:"coverage"`
	Counts      map[string]int `json:"counts"`
	// Feature 015 (FR-002): severity totals over SUPPORTED findings only (Unrated
	// explicit) and over all non-duplicate candidates, plus the per-class counts
	// from the single Classify rule. Counts above is retained unchanged.
	SeveritySupported       map[string]int   `json:"severity_supported"`
	SeverityCandidates      map[string]int   `json:"severity_candidates"`
	ClassCounts             map[Class]int    `json:"class_counts"`
	Assessment              Assessment       `json:"assessment"`
	Verification            any              `json:"verification"`
	VulnerabilityCounts     map[string]int   `json:"vulnerability_counts"`
	HypothesisCounts        map[string]int   `json:"hypothesis_counts"`
	Lifecycle               any              `json:"lifecycle"`
	VulnerabilityLedger     any              `json:"vulnerability_ledger"`
	Chains                  []any            `json:"chains"`
	Remediation             any              `json:"remediation"`
	ApplicationIntelligence AppIntel         `json:"application_intelligence"`
	Findings                []map[string]any `json:"findings"`
}

// Attribution records which model produced/falsified findings.
type Attribution struct {
	HuntModel          string `json:"hunt_model"`
	FalsificationModel string `json:"falsification_model"`
	Orchestrator       string `json:"orchestrator"`
}

// Assessment totals over the finding set.
type Assessment struct {
	Candidates          int `json:"candidates"`
	Supported           int `json:"supported"`
	Unresolved          int `json:"unresolved"`
	StaticallySupported int `json:"statically_supported"`
	Reviewed            int `json:"reviewed"`
	Hypotheses          int `json:"hypotheses"`
	Reproduced          int `json:"reproduced"`
}

// AppIntel is the application_intelligence block.
type AppIntel struct {
	SBOM any `json:"sbom"`
}

func isSubstantiated(f Finding) bool {
	return f.Classification == ClassStaticallySupported || f.Classification == ClassReviewed
}

func counts(findings []Finding, pred func(Finding) bool) map[string]int {
	m := map[string]int{}
	for _, f := range findings {
		if f.DuplicateOf != nil {
			continue
		}
		if pred == nil || pred(f) {
			m[f.Severity]++
		}
	}
	return m
}

// Build assembles the findings.json Doc from a normalized/deduped finding set.
func Build(findings []Finding, opt Options) Doc {
	falsification := opt.VerifyModel
	if falsification == "" {
		falsification = opt.HuntModel
	}
	doc := Doc{
		Meta: opt.Meta,
		Attribution: Attribution{
			HuntModel: opt.HuntModel, FalsificationModel: falsification,
			Orchestrator: "vhlocal " + opt.EngineVersion,
		},
		RunStatus:               opt.Status,
		Coverage:                opt.Coverage,
		Counts:                  counts(findings, nil),
		SeveritySupported:       map[string]int{},
		SeverityCandidates:      map[string]int{},
		ClassCounts:             map[Class]int{},
		VulnerabilityCounts:     counts(findings, isSubstantiated),
		HypothesisCounts:        counts(findings, func(f Finding) bool { return f.Classification == ClassHypothesis }),
		Chains:                  []any{},
		Lifecycle:               opt.Lifecycle,
		VulnerabilityLedger:     opt.VulnerabilityLedger,
		Remediation:             opt.Remediation,
		ApplicationIntelligence: AppIntel{SBOM: opt.SBOM},
		Findings:                []map[string]any{},
	}
	var a Assessment
	for _, f := range findings {
		cls := ClassifyFinding(f)
		doc.ClassCounts[cls]++
		if cls == ClassSupported {
			doc.SeveritySupported[severityKey(f.Severity)]++
		}
		if f.DuplicateOf == nil {
			doc.SeverityCandidates[severityKey(f.Severity)]++
		}
		if f.DuplicateOf != nil {
			doc.Findings = append(doc.Findings, f.ToMap())
			continue
		}
		a.Candidates++
		switch f.Assessment {
		case AssessSupported:
			a.Supported++
		case AssessUnresolved:
			a.Unresolved++
		}
		if f.Classification == ClassStaticallySupported {
			a.StaticallySupported++
		}
		if f.Classification == ClassReviewed {
			a.Reviewed++
		}
		if f.Classification == ClassHypothesis {
			a.Hypotheses++
		}
		if f.TestStatus == TestPassed {
			a.Reproduced++
		}
		doc.Findings = append(doc.Findings, f.ToMap())
	}
	doc.Assessment = a
	return doc
}

// Write serializes the Doc to findings.json in resultsDir.
func (d Doc) Write(resultsDir string) (string, error) {
	b, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		return "", err
	}
	out := filepath.Join(resultsDir, FindingsJSONFile)
	return out, os.WriteFile(out, b, 0o644)
}

// Prepare runs the deterministic pipeline on a raw finding set in place: apply
// knowledge normalization, then dedup/fingerprint. Returns the same slice.
func Prepare(findings []Finding) []Finding {
	for i := range findings {
		ApplyKnowledge(&findings[i])
	}
	Dedup(findings)
	return findings
}
