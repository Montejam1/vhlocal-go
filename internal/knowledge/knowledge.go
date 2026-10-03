// Package knowledge holds the deterministic CWE-normalization and severity
// tables. These are honesty-critical (constitution Principles I & II): findings
// are ranked and cross-run-matched by these canonical labels, not by model
// judgment. The tables mirror the Python knowledge.py exactly (data-model
// §"CWE normalization" and §"Severity baseline"); do not paraphrase them.
package knowledge

import (
	"regexp"
	"strconv"
	"strings"
)

// CVENotApplicable is the fixed value placed in every first-party finding's cve
// field (first-party code findings have no product CVE).
const CVENotApplicable = "CVE-N/A"

// Family is one canonical vulnerability family.
type Family struct {
	Key       string // e.g. "sql-injection"
	Name      string // canonical display name
	Canonical string // canonical CWE, e.g. "CWE-89"
	Baseline  string // baseline severity tier
	Members   []int  // member CWE numbers
}

// families is the ordered _FAMILIES table. Order matters: a CWE listed in more
// than one family binds to the FIRST family (setdefault semantics).
var families = []Family{
	{"code-injection", "Code Injection", "CWE-94", "High+", []int{94, 95, 96}},
	{"template-injection", "Server-Side Template Injection", "CWE-1336", "High+", []int{1336, 917}},
	{"deserialization", "Insecure Deserialization", "CWE-502", "High+", []int{502}},
	{"command-injection", "OS Command Injection", "CWE-78", "High+", []int{78, 77}},
	{"sql-injection", "SQL Injection", "CWE-89", "High", []int{89}},
	{"nosql-injection", "NoSQL Injection", "CWE-943", "High", []int{943}},
	{"xxe", "XML External Entity (XXE)", "CWE-611", "High", []int{611, 827, 776}},
	{"path-traversal", "Path Traversal", "CWE-22", "High", []int{22, 23, 36, 73}},
	{"ssrf", "Server-Side Request Forgery", "CWE-918", "High", []int{918}},
	{"mass-assignment", "Mass Assignment", "CWE-915", "High", []int{915}},
	{"xss", "Cross-Site Scripting", "CWE-79", "Medium", []int{79, 80, 83, 116}},
	{"open-redirect", "Open Redirect", "CWE-601", "Low", []int{601}},
	{"privilege-escalation", "Privilege Escalation", "CWE-269", "High", []int{269, 266, 267, 250, 648}},
	{"missing-auth", "Missing Authentication", "CWE-306", "High", []int{306, 287, 288, 294, 302}},
	{"access-control", "Broken Access Control", "CWE-284", "High", []int{284, 285, 639, 862, 863, 638, 1220, 807}},
	{"weak-auth", "Weak Authentication / Credential Handling", "CWE-640", "Medium", []int{640, 620, 521, 522, 308, 384}},
	{"weak-random", "Insufficient Randomness", "CWE-330", "Medium", []int{330, 338, 331, 337, 340}},
	{"weak-crypto", "Weak Cryptography", "CWE-327", "Medium", []int{327, 326, 328, 916, 759, 760}},
	{"hardcoded-secret", "Hard-coded Secret", "CWE-798", "Medium", []int{798, 321, 259, 260, 547}},
	{"race-condition", "Race Condition (TOCTOU)", "CWE-362", "Medium", []int{362, 367, 364, 366, 543}},
	{"cors", "CORS Misconfiguration", "CWE-942", "Medium", []int{942, 346}},
	{"rate-limiting", "Missing Rate Limiting", "CWE-799", "Low", []int{799, 307}},
	{"resource-exhaustion", "Uncontrolled Resource Consumption", "CWE-400", "Medium", []int{400, 770, 834, 1050}},
	{"timing", "Observable Timing Discrepancy", "CWE-208", "Low", []int{208, 203, 1254}},
	{"csrf", "Cross-Site Request Forgery", "CWE-352", "Medium", []int{352}},
	{"transport", "Improper Transport / Certificate Handling", "CWE-319", "Medium", []int{319, 295, 297, 311, 523}},
	{"info-disclosure", "Sensitive Information Exposure", "CWE-200", "Medium", []int{200, 201, 209, 215, 532, 538, 213}},
}

// Keys returns every family key in table order. Callers that must cover the whole table —
// the feature-016 remediation guidance table, for example — enumerate it from here rather
// than keeping a second copy that can drift.
func Keys() []string {
	out := make([]string, 0, len(families))
	for i := range families {
		out = append(out, families[i].Key)
	}
	return out
}

// byNum maps a member CWE number to its family (first family wins).
var byNum = func() map[int]*Family {
	m := make(map[int]*Family)
	for i := range families {
		for _, n := range families[i].Members {
			if _, ok := m[n]; !ok {
				m[n] = &families[i]
			}
		}
	}
	return m
}()

// cweNum extracts the numeric part of a CWE string ("CWE-89", "89" -> 89, ok).
func cweNum(cwe string) (int, bool) {
	m := digits.FindString(cwe)
	if m == "" {
		return 0, false
	}
	n, err := strconv.Atoi(m)
	return n, err == nil
}

var digits = regexp.MustCompile(`\d+`)

// FamilyOf returns the family for a CWE string, or nil if unknown.
func FamilyOf(cwe string) *Family {
	if n, ok := cweNum(cwe); ok {
		return byNum[n]
	}
	return nil
}

// NormalizedCWE returns the family's canonical CWE, else "CWE-<num>" if numeric,
// else "".
func NormalizedCWE(cwe string) string {
	if f := FamilyOf(cwe); f != nil {
		return f.Canonical
	}
	if n, ok := cweNum(cwe); ok {
		return "CWE-" + strconv.Itoa(n)
	}
	return ""
}

// CanonicalName returns the family display name, else "".
func CanonicalName(cwe string) string {
	if f := FamilyOf(cwe); f != nil {
		return f.Name
	}
	return ""
}

// severity tiers, most severe first (data-model §Severity).
var sevTiers = []string{"Critical", "High+", "High", "Medium", "Low", "Informational"}

func sevIndex(tier string) int {
	for i, t := range sevTiers {
		if strings.EqualFold(t, tier) {
			return i
		}
	}
	return -1
}

// gated matches text indicating an auth/token precondition that narrows the
// attacker profile, dropping severity one tier (data-model §"-1 tier").
var gated = regexp.MustCompile(`(?i)requires? .*(token|credential|auth|login|session)|internal[- ]?ops|ops[-_ ]?admin|x-internal-token|_wrk_gate|authenticated (user|caller|api)`)

// NormalizedSeverity returns the family baseline severity; if gatedText matches
// the gated pattern, it drops one tier (clamped to Informational). Returns ""
// for an unknown family.
func NormalizedSeverity(cwe, gatedText string) string {
	f := FamilyOf(cwe)
	if f == nil {
		return ""
	}
	idx := sevIndex(f.Baseline)
	if idx < 0 {
		return f.Baseline
	}
	if gated.MatchString(gatedText) {
		idx++
		if idx >= len(sevTiers) {
			idx = len(sevTiers) - 1
		}
	}
	return sevTiers[idx]
}
