package consolidate

import (
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"vhlocal/internal/knowledge"
)

// ApplyKnowledge sets the deterministic normalized layer on a finding: canonical
// CWE/family/name, and the family-baseline severity (dropped one tier when a
// precondition is present). When the normalized severity differs from the raw
// severity, the raw value is preserved in ReportedSeverity and severity/rank are
// replaced by the normalized tier (data-model §severity normalization).
func ApplyKnowledge(f *Finding) {
	f.NormalizedCWE = knowledge.NormalizedCWE(f.CWE)
	f.CanonicalName = knowledge.CanonicalName(f.CWE)
	if fam := knowledge.FamilyOf(f.CWE); fam != nil {
		f.CWEFamily = fam.Key
	}
	if f.CVE == "" {
		f.CVE = CVENotApplicable
	}
	gatedText := strings.Join([]string{f.Exploitability, f.DataFlow, f.EntryPoint, f.Status, f.Title}, " ")
	ns := knowledge.NormalizedSeverity(f.CWE, gatedText)
	if ns != "" {
		f.NormalizedSeverity = ns
		if !strings.EqualFold(ns, f.Severity) {
			f.ReportedSeverity = f.Severity
			f.Severity = ns
			f.SeverityRank = SeverityRankOf(ns)
		}
	}
}

// --- root-cause fingerprint ---

var reFileToken = regexp.MustCompile(`([\w./+\-]+\.[A-Za-z0-9]{1,6})`)
var reCall = regexp.MustCompile(`([A-Za-z_][A-Za-z0-9_]*)\s*\(`)
var reIdent = regexp.MustCompile(`[A-Za-z_][A-Za-z0-9_]*`)

var flowStopwords = map[string]bool{
	"the": true, "a": true, "an": true, "and": true, "or": true, "in": true, "to": true,
	"of": true, "from": true, "via": true, "param": true, "parameter": true, "request": true,
	"user": true, "input": true, "get": true, "post": true, "put": true, "delete": true,
	"api": true, "endpoint": true, "route": true, "handler": true, "func": true, "function": true,
}

// normFile returns the basename of the first file-like token in s.
func normFile(s string) string {
	if m := reFileToken.FindString(s); m != "" {
		return filepath.Base(m)
	}
	return ""
}

// funcHint returns the last function-call name (the sink) in s, lowercased.
func funcHint(s string) string {
	ms := reCall.FindAllStringSubmatch(s, -1)
	if len(ms) == 0 {
		return ""
	}
	return strings.ToLower(ms[len(ms)-1][1])
}

// flowSignature is a comma-joined sorted set of attacker-input identifier names
// drawn from entry_point+data_flow+title, minus stopwords — distinguishing two
// inputs that reach one sink.
func flowSignature(f *Finding) string {
	src := strings.ToLower(f.EntryPoint + " " + f.DataFlow + " " + f.Title)
	set := map[string]bool{}
	for _, id := range reIdent.FindAllString(src, -1) {
		if len(id) < 2 || flowStopwords[id] {
			continue
		}
		set[id] = true
	}
	keys := make([]string, 0, len(set))
	for k := range set {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return strings.Join(keys, ",")
}

// family returns the normalized family key, or a keyword-derived fallback.
func family(f *Finding) string {
	if f.CWEFamily != "" {
		return f.CWEFamily
	}
	if fam := knowledge.FamilyOf(f.CWE); fam != nil {
		return fam.Key
	}
	return familyFromWords(f.Title + " " + f.DataFlow)
}

var familyWords = []struct{ kw, key string }{
	{"xxe", "xxe"}, {"ssti", "template-injection"}, {"nosql", "nosql-injection"},
	{"sql", "sql-injection"}, {"pickle", "deserialization"}, {"deserial", "deserialization"},
	{"open redirect", "open-redirect"}, {"path travers", "path-traversal"},
	{"directory travers", "path-traversal"}, {"command inj", "command-injection"},
	{"os command", "command-injection"}, {"eval", "code-injection"}, {"ssrf", "ssrf"},
	{"xss", "xss"},
}

func familyFromWords(s string) string {
	s = strings.ToLower(s)
	for _, fw := range familyWords {
		if strings.Contains(s, fw.kw) {
			return fw.key
		}
	}
	return ""
}

// titleSignature is the degraded fallback when no file token is present.
func titleSignature(f *Finding) string {
	words := reIdent.FindAllString(strings.ToLower(f.Title), -1)
	var kept []string
	for _, w := range words {
		if len(w) >= 4 && !flowStopwords[w] {
			kept = append(kept, w)
		}
	}
	sort.Strings(kept)
	return strings.Join(kept, "-")
}

// RootCauseKey computes the line-number-free fingerprint used for dedup and
// cross-run matching: "family:file:func:flowsig", with a degraded
// "family::titlesig" fallback when no file is known. Empty disables dedup.
func RootCauseKey(f *Finding) string {
	fam := family(f)
	file := normFile(f.Location + " " + f.DataFlow)
	if file == "" {
		if ts := titleSignature(f); ts != "" && fam != "" {
			return fam + "::" + ts
		}
		return ""
	}
	return fam + ":" + file + ":" + funcHint(f.Location+" "+f.DataFlow) + ":" + flowSignature(f)
}

// Dedup assigns RootCauseKey, ClusterID (canonical kept finding) and DuplicateOf.
// The first finding for a key is canonical; later ones point to it. Findings with
// an empty key are never marked duplicate (dedup disabled for them).
func Dedup(findings []Finding) {
	canonical := map[string]string{} // key -> canonical id
	for i := range findings {
		f := &findings[i]
		f.RootCauseKey = RootCauseKey(f)
		if f.RootCauseKey == "" {
			f.ClusterID = f.ID
			continue
		}
		key := f.RootCauseKey
		if f.StableIdentity != "" {
			key = "candidate:" + f.StableIdentity
		}
		if cid, ok := canonical[key]; ok {
			dup := cid
			f.DuplicateOf = &dup
			f.ClusterID = cid
		} else {
			canonical[key] = f.ID
			f.ClusterID = f.ID
		}
	}
}
