package consolidate

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"vhlocal/internal/source"
)

// Source corroboration (feature 005, FR-024/025): a finding is "statically
// supported" only when the real source at its cited location contains a sink
// pattern for its CWE family — never on a text field / prose data-flow arrow /
// model confidence alone. Ports the authoritative CWE→sink table and logic-CWE
// exclusion from the reference (sweep.py CWE_SINK_PATTERNS / _LOGIC_CWES,
// quality.py check_source_corroborated).
//
// NA kinds carry meaning: "logic" (authorization/logic class — no syntactic sink,
// never supportable on prose), "uncovered" (the checker has no rule — cannot
// assess), "unavailable" (no checkout / unreadable — a re-render; keep the tier via
// the structural signals). Only a FAIL (source present, no sink) refutes support.
//
// Deferred (documented, US4 remainder): the per-class VETO battery
// (XSS HTML-vs-JSON, CORS credentialed-wildcard, weak-random consumer, race
// uniqueness) that DEMOTES some passes; and CWE family-member expansion.

var logicCWEs = map[string]bool{
	"639": true, "862": true, "863": true, "306": true, "285": true, "284": true,
	"269": true, "367": true, "362": true, "200": true, "538": true, "215": true, "16": true,
}

var cweSinkPatterns = map[string][]string{
	"94":   {`\beval\s*\(`, `\bexec\s*\(`, `\bcompile\s*\(`, `render_template_string`, `\bTemplate\s*\(`, `from_string`},
	"95":   {`\beval\s*\(`},
	"96":   {`\bexec\s*\(`, `\beval\s*\(`},
	"502":  {`pickle\.loads?\b`, `cPickle\.loads?`, `yaml\.load\s*\(`, `marshal\.loads?`, `jsonpickle`, `dill\.loads?`},
	"611":  {`etree\.parse`, `etree\.fromstring`, `XMLParser`, `lxml\b`, `parseString`, `minidom\.parse`},
	"79":   {`\|\s*safe\b`, `render_template_string`, `mark_safe`, `\bMarkup\s*\(`, `\bHTMLResponse\s*\(`, `text/html`},
	"1336": {`render_template_string`, `\bTemplate\s*\(`, `from_string`},
	"22":   {`send_file`, `send_from_directory`, `os\.path\.join`, `FileResponse`, `\.write_text\s*\(`, `\.write_bytes\s*\(`, `\bopen\s*\(`, `shutil\.copy`},
	"23":   {`\bopen\s*\(`, `os\.path\.join`, `\.write_bytes\s*\(`, `\.write_text\s*\(`},
	"601":  {`RedirectResponse`, `\bredirect\s*\(`, `HttpResponseRedirect`},
	"918":  {`requests\.(get|post|put|delete|head)\s*\(`, `\burlopen\s*\(`, `httpx\.`, `urllib\.request`},
	"338":  {`random\.(choice|random|randint|randrange|getrandbits|shuffle|sample|uniform)\s*\(`},
	"330":  {`random\.(choice|random|randint|randrange)\s*\(`},
	"327":  {`\bmd5\s*\(`, `\bsha1\s*\(`, `\bDES\b`, `\bECB\b`},
	"89":   {`\.execute\s*\(`, `\.executemany\s*\(`, `\.raw\s*\(`},
	"943":  {`\.find\s*\(`, `\.find_one\s*\(`, `\$where`, `\.aggregate\s*\(`},
	"78":   {`os\.system\s*\(`, `subprocess\.(run|call|Popen|check_output)\s*\(`, `os\.popen\s*\(`},
	"532":  {`\.(info|debug|warning|error)\s*\(.*token`, `logg(er|ing).*(token|secret|password)`},
}

var reFileLine = regexp.MustCompile(`([\w./+\-]+\.\w+):(\d+)`)

func cweNum(cwe string) string {
	return strings.TrimSpace(strings.ReplaceAll(strings.ToUpper(cwe), "CWE-", ""))
}

func isLogicCWE(f *Finding) bool {
	return logicCWEs[cweNum(f.CWE)] || logicCWEs[cweNum(f.NormalizedCWE)]
}

// sinkPatterns returns the authoritative sink patterns for a CWE and a kind note:
// "" (patterns present), "logic" (no syntactic sink), or "uncovered" (no rule).
func sinkPatterns(cwe string) ([]string, string) {
	num := cweNum(cwe)
	if logicCWEs[num] {
		return nil, "logic"
	}
	if pats := cweSinkPatterns[num]; len(pats) > 0 {
		return pats, ""
	}
	return nil, "uncovered"
}

// sourceWindow reads the cited file and returns a ±20-line window around the cited
// line. Only in-tree, unambiguous, non-traversal paths are read.
func sourceWindow(location, repo string) (string, bool) {
	if repo == "" {
		return "", false
	}
	m := reFileLine.FindStringSubmatch(location)
	if m == nil {
		return "", false
	}
	rel := m[1]
	if filepath.IsAbs(rel) || strings.Contains(rel, "..") {
		return "", false
	}
	b, err := source.ReadFile(repo, rel)
	if err != nil {
		return "", false
	}
	lines := strings.Split(string(b), "\n")
	ln, _ := strconv.Atoi(m[2])
	lo := ln - 20
	if lo < 1 {
		lo = 1
	}
	hi := ln + 20
	if hi > len(lines) {
		hi = len(lines)
	}
	if lo > len(lines) {
		return "", false
	}
	return strings.Join(lines[lo-1:hi], "\n"), true
}

// corrob is the source-corroboration outcome. status ∈ {pass,fail,na}.
type corrob struct {
	status string
	kind   string // for na: logic | uncovered | unavailable
	reason string
}

// SourceSupported reports whether the cited source corroborates the finding's CWE
// (a matching sink pattern is present at the cited location). Exported for the
// verification reconciler (US3): a "supported" verdict requires this.
func SourceSupported(f *Finding, repo string) bool {
	return checkSourceCorroborated(f, repo).status == "pass"
}

// SourceRefuted reports whether the cited source DEFINITELY refutes the class: the
// source is present at the cited location but contains no matching sink (a FAIL).
// A logic/authorization class, an unrule'd class, or an unreadable checkout is NA —
// not refuted — so an evidence-backed authorization/logic review is not auto-blocked
// for lacking a syntactic sink (feature 007, FR-024; parity with the reference,
// which blocks only on a source_corroborated FAIL).
func SourceRefuted(f *Finding, repo string) bool {
	return checkSourceCorroborated(f, repo).status == "fail"
}

// ClassEvidenceRefuted reports whether the per-class veto battery refutes support
// for this finding (e.g. XSS reflected into JSON, weak-random with no consumer,
// safe CORS). Exported for the verification reconciler (US3/US4).
func ClassEvidenceRefuted(f *Finding, repo string) bool {
	return checkClassEvidence(f, repo).status == "fail"
}

// ClassPrimaryEvidence reports whether the class-evidence battery ESTABLISHES
// support on its own for a primary-evidence class (CORS) — so the source-sink
// corroboration is not additionally required. Exported for the reconciler.
func ClassPrimaryEvidence(f *Finding, repo string) bool {
	return isPrimaryEvidenceClass(f) && checkClassEvidence(f, repo).status == "pass"
}

// --- class-specific veto battery (feature 005, US4; FR-025) ------------------
// Some classes need more than a sink: the value must reach a security-sensitive
// consumer (weak random), or an HTML (not JSON) response (XSS), or a credentialed
// wildcard CORS. A FAIL here refutes support even when a sink is present; a PASS on
// a PRIMARY-evidence class (CORS) establishes it. Classes with no rule return "na".
var (
	randomCWEs = map[string]bool{"330": true, "338": true}
	xssCWEs    = map[string]bool{"79": true, "80": true, "83": true, "116": true}
	corsCWEs   = map[string]bool{"942": true, "346": true}
	// Broken-access-control classes: a missing-authz/IDOR claim needs a
	// source-grounded review of the effective permission — guard-name detection
	// can neither establish nor refute it, so class evidence is always NA (never a
	// fail on guard absence, never a pass on prose).
	accessControlCWEs = map[string]bool{
		"639": true, "862": true, "863": true, "284": true, "285": true,
		"638": true, "1220": true, "807": true, "566": true, "668": true}

	// SSTI: when the template SOURCE is a constant, rendering attacker data against
	// it does not evaluate the data as template source — the injection claim is
	// refuted (HTML injection would need a separate claim).
	reSSTITitle    = regexp.MustCompile(`(?i)template injection|\bSSTI\b`)
	reTemplateCall = regexp.MustCompile(`(?:\bTemplate|\.from_string)\s*\(\s*([^)]*)`)

	reSecConsumer = regexp.MustCompile(`(?i)(?:\b|\.)(?:token|secret|password|passwd|api[_-]?key|apikey|private[_-]?key|nonce|csrf|xsrf|session[_-]?id|otp|mfa|salt|reset[_-]?token|signature|hmac|jwt|credential)\w*\s*[=:]|set_cookie|session\[|jwt\.(encode|decode)|hmac\.|hashlib\.\w+\(|secrets\.compare_digest|check_password|set_password`)
	reHTMLSink    = regexp.MustCompile(`(?i)HTMLResponse\s*\(|render_template_string|mark_safe|\bMarkup\s*\(|\|\s*safe\b|text/html`)
	reJSONResp    = regexp.MustCompile(`(?i)JSONResponse|\bjsonify\s*\(|application/json|response_model\s*=|media_type\s*=\s*['"]application/json`)
	reCORSMw      = regexp.MustCompile(`(?i)CORSMiddleware|add_middleware|CORS\s*\(`)
	reCORSCreds   = regexp.MustCompile(`(?i)allow_credentials\s*=\s*True|supports_credentials\s*=\s*True`)
	reCORSWild    = regexp.MustCompile(`(?i)allow_origins\s*=\s*\[?\s*['"]\*['"]|origins\s*=\s*\[?\s*['"]\*['"]`)
)

// isPrimaryEvidenceClass reports classes where a class_evidence PASS establishes
// support on its own (no syntactic sink to corroborate) — currently CORS.
func isPrimaryEvidenceClass(f *Finding) bool {
	return corsCWEs[cweNum(f.CWE)] || corsCWEs[cweNum(f.NormalizedCWE)]
}

// enclosingWindow returns a wider (~±40 line) window around the cited location —
// an approximation of the containing function (Go has no Python AST).
func enclosingWindow(f *Finding, repo string) (string, bool) {
	m := reFileLine.FindStringSubmatch(f.Location)
	if repo == "" || m == nil {
		return "", false
	}
	file := m[1]
	line, _ := strconv.Atoi(m[2])
	if filepath.IsAbs(file) || strings.Contains(file, "..") {
		return "", false
	}
	b, err := source.ReadFile(repo, file)
	if err != nil {
		return "", false
	}
	lines := strings.Split(string(b), "\n")
	lo, hi := line-40, line+40
	if lo < 1 {
		lo = 1
	}
	if hi > len(lines) {
		hi = len(lines)
	}
	if lo > len(lines) {
		return "", false
	}
	return strings.Join(lines[lo-1:hi], "\n"), true
}

// checkClassEvidence returns pass/fail/na for the veto battery.
func checkClassEvidence(f *Finding, repo string) corrob {
	num := cweNum(f.CWE)
	if num == "" {
		num = cweNum(f.NormalizedCWE)
	}
	// SSTI is keyed off the title (the CWE alone can be a generic injection class),
	// checked before the CWE-num battery — parity with the reference.
	if reSSTITitle.MatchString(f.Title) {
		if win, ok := enclosingWindow(f, repo); ok {
			calls := reTemplateCall.FindAllStringSubmatch(win, -1)
			if len(calls) > 0 {
				allConst := true
				for _, c := range calls {
					if !isConstStringArg(c[1]) {
						allConst = false
						break
					}
				}
				if allConst {
					return corrob{"fail", "", "template source is constant; rendering attacker data does not evaluate it as template source"}
				}
			}
		}
	}
	switch {
	case accessControlCWEs[num]:
		return corrob{"na", "", "authorization requires a source-grounded review of the claimed permission, object/tenant scope, and control flow; guard-name detection cannot establish effective permissions"}
	case randomCWEs[num]:
		win, ok := sourceWindow(f.Location, repo)
		if !ok {
			return corrob{"fail", "", "cannot establish a security-sensitive consumer for the weak-random value"}
		}
		if reSecConsumer.MatchString(win) {
			return corrob{"pass", "", "the weak-random value reaches a security-sensitive consumer"}
		}
		return corrob{"fail", "", "no security-sensitive use site for the weak-random value"}
	case xssCWEs[num]:
		win, ok := enclosingWindow(f, repo)
		if !ok {
			return corrob{"na", "", "response context undeterminable"}
		}
		if reHTMLSink.MatchString(win) {
			return corrob{"pass", "", "reaches an HTML/unescaped response context"}
		}
		if reJSONResp.MatchString(win) {
			return corrob{"fail", "", "reflected into a JSON response (auto-escaped) — not XSS in a browser"}
		}
		return corrob{"na", "", "response context undeterminable (no clear HTML or JSON sink)"}
	case corsCWEs[num]:
		danger, found := corsDanger(repo)
		if !found {
			return corrob{"na", "", "no CORS configuration found"}
		}
		if danger {
			return corrob{"pass", "", "allow_credentials with a wildcard/reflected origin"}
		}
		return corrob{"fail", "", "CORS configured without credentialed wildcard access"}
	}
	return corrob{"na", "uncovered", "no class-specific rule"}
}

// isConstStringArg reports whether a call's first argument is a constant string
// literal (starts with a quote). An f-string / name / expression is not constant.
func isConstStringArg(arg string) bool {
	s := strings.TrimSpace(arg)
	return len(s) > 0 && (s[0] == '"' || s[0] == '\'')
}

func corsDanger(repo string) (danger, found bool) {
	if repo == "" {
		return false, false
	}
	_ = filepath.WalkDir(repo, func(p string, d os.DirEntry, err error) error {
		if err != nil || danger {
			return nil
		}
		if d.IsDir() || !strings.HasSuffix(p, ".py") {
			return nil
		}
		rel, _ := filepath.Rel(repo, p)
		b, e := source.ReadFile(repo, rel)
		if e != nil {
			return nil
		}
		t := string(b)
		if !reCORSMw.MatchString(t) {
			return nil
		}
		found = true
		if reCORSCreds.MatchString(t) && reCORSWild.MatchString(t) {
			danger = true
		}
		return nil
	})
	return danger, found
}

func checkSourceCorroborated(f *Finding, repo string) corrob {
	if isLogicCWE(f) {
		return corrob{"na", "logic", "authorization/logic class — no syntactic sink to corroborate"}
	}
	cwe := f.CWE
	if cwe == "" {
		cwe = f.NormalizedCWE
	}
	pats, kind := sinkPatterns(cwe)
	if len(pats) == 0 {
		return corrob{"na", kind, "the checker has no sink rule for this class"}
	}
	win, ok := sourceWindow(f.Location, repo)
	if !ok {
		return corrob{"na", "unavailable", "cited source not found/readable to corroborate"}
	}
	for _, p := range pats {
		if re, err := regexp.Compile(p); err == nil && re.MatchString(win) {
			return corrob{"pass", "", "a sink pattern for " + cwe + " is present at the cited location"}
		}
	}
	return corrob{"fail", "", "no sink pattern for " + cwe + " near the cited location"}
}

// SweepSinkPatterns exposes the curated table for deterministic lead enumeration.
// Narrative-derived patterns must never be used for source corroboration.
func SweepSinkPatterns(cwe string) ([]string, string) {
	pats, kind := sinkPatterns(cwe)
	return append([]string(nil), pats...), kind
}
