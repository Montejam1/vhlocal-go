// Package sarif emits findings.sarif (SARIF 2.1.0) — a deterministic transform
// of the engine-built findings so vhlocal output drops into GitHub code-scanning
// and any SARIF viewer. Mapping mirrors the Python sarif.py.
package sarif

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"vhlocal/internal/consolidate"
)

const (
	Version         = "2.1.0"
	Schema          = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
	DriverName      = "vhlocal"
	CWETaxonomyGUID = "b7d3f2a0-6c1e-4f5b-9a2d-1e0c4f8b3a11"
	FindingsFile    = "findings.sarif"
	InfoURI         = "https://github.com/vulnhunter/vhlocal"
)

var levelMap = map[string]string{
	"critical": "error", "high+": "error", "high": "error",
	"medium": "warning", "low": "note", "info": "note",
	"informational": "note", "unrated": "none", "unknown": "none",
}

var locRE = regexp.MustCompile(`([\w./+\-]+\.[A-Za-z0-9]{1,6})(?:[:\s]+(\d+))?`)

func level(sev string) string {
	if l, ok := levelMap[strings.ToLower(strings.TrimSpace(sev))]; ok {
		return l
	}
	return "none"
}

func cweNum(cwe string) string {
	m := regexp.MustCompile(`(\d+)`).FindString(cwe)
	return m
}

func ruleID(f consolidate.Finding) string {
	for _, v := range []string{f.NormalizedCWE, f.CWE, f.CWEFamily} {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return "VULN"
}

func substantiated(f consolidate.Finding) bool {
	return f.Classification == consolidate.ClassStaticallySupported || f.Classification == consolidate.ClassReviewed
}

func parseLoc(text string) (string, int, bool) {
	m := locRE.FindStringSubmatch(text)
	if m == nil {
		return "", 0, false
	}
	line := 0
	if m[2] != "" {
		line, _ = strconv.Atoi(m[2])
	}
	return m[1], line, true
}

// Build constructs the SARIF document from findings + run status.
func Build(findings []consolidate.Finding, status consolidate.RunStatus, engineVersion, repo, huntModel string) map[string]any {
	rules := map[string]map[string]any{}
	taxa := map[string]map[string]any{}
	var results []map[string]any

	for _, f := range findings {
		if f.DuplicateOf != nil {
			continue
		}
		rid := ruleID(f)
		num := cweNum(f.NormalizedCWE)
		if num == "" {
			num = cweNum(f.CWE)
		}
		// rule
		if _, ok := rules[rid]; !ok {
			name := f.CanonicalName
			if name == "" {
				name = rid
			}
			rule := map[string]any{
				"id":               rid,
				"name":             strings.ReplaceAll(name, " ", ""),
				"shortDescription": map[string]any{"text": name},
				"properties":       map[string]any{"category": rid},
			}
			if num != "" {
				rule["helpUri"] = "https://cwe.mitre.org/data/definitions/" + num + ".html"
				rule["relationships"] = []map[string]any{{
					"target": map[string]any{"id": "CWE-" + num, "toolComponent": map[string]any{"name": "CWE", "guid": CWETaxonomyGUID}},
					"kinds":  []string{"superset"},
				}}
			}
			rules[rid] = rule
		}
		if num != "" {
			taxa["CWE-"+num] = map[string]any{
				"id": "CWE-" + num, "name": f.CanonicalName,
				"helpUri": "https://cwe.mitre.org/data/definitions/" + num + ".html",
			}
		}

		lvl := "note"
		if substantiated(f) {
			lvl = level(f.Severity)
		}
		kind := "review"
		if substantiated(f) {
			kind = "fail"
		}
		assessReason := f.AssessmentReason
		if assessReason == "" {
			assessReason = "No substantiated review is recorded."
		}
		props := map[string]any{
			"severity": f.Severity, "classification": f.Classification,
			"hypothesisReason": f.HypothesisReason, "assessmentReason": assessReason,
		}
		if num != "" {
			props["cwe"] = f.CWE
			props["cweId"] = "CWE-" + num
			props["cweName"] = f.CanonicalName
		}
		if f.FindingLifecycle != "" {
			props["lifecycle"] = f.FindingLifecycle
		}
		props["findingId"] = f.ID

		res := map[string]any{
			"ruleId":     rid,
			"level":      lvl,
			"kind":       kind,
			"message":    map[string]any{"text": "[" + f.Classification + "; potential severity: " + f.Severity + "] " + f.Title},
			"properties": props,
		}
		if uri, line, ok := parseLoc(f.Location + " " + f.DataFlow); ok {
			region := map[string]any{}
			if line > 0 {
				region["startLine"] = line
			}
			res["locations"] = []map[string]any{{
				"physicalLocation": map[string]any{
					"artifactLocation": map[string]any{"uri": uri},
					"region":           region,
				},
			}}
		}
		if num != "" {
			res["taxa"] = []map[string]any{{"id": "CWE-" + num, "toolComponent": map[string]any{"name": "CWE", "guid": CWETaxonomyGUID}}}
		}
		results = append(results, res)
	}

	// stable rule/taxa ordering
	ruleList := sortedMapValues(rules)
	taxaList := sortedMapValues(taxa)

	execOK := status.ExecutionStatus == "" || status.ExecutionStatus == consolidate.ExecComplete
	inv := map[string]any{"executionSuccessful": execOK}
	var notifs []map[string]any
	for _, r := range status.CoverageDegradedReasons {
		notifs = append(notifs, map[string]any{"level": "warning", "message": map[string]any{"text": r}})
	}
	if len(notifs) > 0 {
		inv["toolExecutionNotifications"] = notifs
	}

	driver := map[string]any{
		"name": DriverName, "informationUri": InfoURI,
		"rules":               ruleList,
		"supportedTaxonomies": []map[string]any{{"name": "CWE", "guid": CWETaxonomyGUID}},
	}
	if engineVersion != "" {
		driver["version"] = engineVersion
	}
	run := map[string]any{
		"tool":        map[string]any{"driver": driver},
		"results":     nonNil(results),
		"invocations": []map[string]any{inv},
		"taxonomies": []map[string]any{{
			"name": "CWE", "guid": CWETaxonomyGUID, "organization": "MITRE",
			"shortDescription": map[string]any{"text": "Common Weakness Enumeration"},
			"taxa":             nonNil(taxaList),
		}},
	}
	if repo != "" || huntModel != "" {
		run["properties"] = map[string]any{"applicationId": filepath.Base(repo), "huntModel": huntModel}
	}
	return map[string]any{"$schema": Schema, "version": Version, "runs": []map[string]any{run}}
}

// Write emits findings.sarif into resultsDir.
func Write(findings []consolidate.Finding, status consolidate.RunStatus, engineVersion, repo, huntModel, resultsDir string) (string, error) {
	doc := Build(findings, status, engineVersion, repo, huntModel)
	b, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return "", err
	}
	out := filepath.Join(resultsDir, FindingsFile)
	return out, os.WriteFile(out, b, 0o644)
}

func sortedMapValues(m map[string]map[string]any) []map[string]any {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sortStrings(keys)
	out := make([]map[string]any, 0, len(keys))
	for _, k := range keys {
		out = append(out, m[k])
	}
	return out
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j-1] > s[j]; j-- {
			s[j-1], s[j] = s[j], s[j-1]
		}
	}
}

func nonNil(s []map[string]any) []map[string]any {
	if s == nil {
		return []map[string]any{}
	}
	return s
}
