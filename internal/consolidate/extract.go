package consolidate

import (
	"regexp"
	"strings"

	"vhlocal/internal/phases"
)

// Finding-block header: "### [VULN-001] Title", "## 3. VULN-001 — Title",
// "### NAV-01 — Title — HIGH", etc. Tolerant of the format variance the phase
// agents produce. Text is normalized first (FR-025).
var reFindingHdr = regexp.MustCompile(`(?mi)^#{2,4}\s*\[?((?:VULN|INJ|NAV|LOG|SINK)-\d+)\]?\s*(?:[—:-]\s*)?(.*)$`)

// Field line: "- **CWE**: CWE-89" or "| **CWE** | CWE-89 |".
var reField = regexp.MustCompile(`(?mi)^\s*(?:[-*]\s*)?\|?\s*\*\*([^*|]+)\*\*\s*[:|]\s*(.+?)\s*\|?\s*$`)

// ExtractFindings parses findings from a phase output's markdown. IDs are
// renumbered to VULN-NNN in encounter order for stable global identity, while the
// source local id is preserved in source_id. Returns nil for no findings (the
// caller degrades visibly rather than inventing findings).
func ExtractFindings(markdown, source string) []Finding {
	text := phases.NormalizeText(markdown)
	locs := reFindingHdr.FindAllStringSubmatchIndex(text, -1)
	if len(locs) == 0 {
		return nil
	}
	var out []Finding
	for i, loc := range locs {
		localID := text[loc[2]:loc[3]]
		title := strings.TrimSpace(text[loc[4]:loc[5]])
		bodyStart := loc[1]
		bodyEnd := len(text)
		if i+1 < len(locs) {
			bodyEnd = locs[i+1][0]
		}
		body := text[bodyStart:bodyEnd]

		f := NewFinding("")
		f.Source = source
		f.SourceID = localID
		f.Title = stripMarkup(title)
		fields := parseFields(body)
		f.CWE = firstField(fields, "cwe")
		if sev := firstField(fields, "severity", "sev"); sev != "" {
			f.Severity = SeverityLabel(sev)
			f.SeverityRank = SeverityRankOf(sev)
		}
		f.Location = firstField(fields, "location", "sink", "file")
		f.EntryPoint = firstField(fields, "entry point", "entry-point", "entrypoint", "route", "endpoint")
		f.DataFlow = firstField(fields, "data flow", "data-flow", "flow")
		f.Fix = firstField(fields, "fix", "remediation")
		f.Status = firstField(fields, "status")
		f.ExploitTest = firstField(fields, "exploit test", "test")
		// Also detect a CWE embedded in the title if no field.
		if f.CWE == "" {
			if m := regexp.MustCompile(`(?i)CWE-\d+`).FindString(title + " " + body); m != "" {
				f.CWE = strings.ToUpper(m)
			}
		}
		// A finding with neither a CWE nor a location is too thin to keep.
		if f.CWE == "" && f.Location == "" && f.Title == "" {
			continue
		}
		out = append(out, f)
	}
	// Renumber to VULN-NNN in order.
	for i := range out {
		out[i].ID = "VULN-" + pad3(i+1)
	}
	return out
}

func parseFields(body string) map[string]string {
	m := map[string]string{}
	for _, ln := range strings.Split(body, "\n") {
		if mm := reField.FindStringSubmatch(ln); mm != nil {
			key := strings.ToLower(strings.TrimSpace(mm[1]))
			val := stripMarkup(strings.TrimSpace(mm[2]))
			if _, ok := m[key]; !ok {
				m[key] = val
			}
		}
	}
	return m
}

func firstField(m map[string]string, keys ...string) string {
	for _, k := range keys {
		if v, ok := m[k]; ok && v != "" {
			return v
		}
	}
	return ""
}

func stripMarkup(s string) string {
	s = strings.ReplaceAll(s, "`", "")
	s = strings.ReplaceAll(s, "**", "")
	return strings.TrimSpace(s)
}

func pad3(n int) string {
	switch {
	case n < 10:
		return "00" + itoa(n)
	case n < 100:
		return "0" + itoa(n)
	default:
		return itoa(n)
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
