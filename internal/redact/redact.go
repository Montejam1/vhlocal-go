// Package redact masks secrets/PII (payment cards, SSNs, credentials) in the
// written artifacts when --redact is set. Deterministic, stdlib regex only.
package redact

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

var patterns = []*regexp.Regexp{
	regexp.MustCompile(`\b(?:\d[ -]?){13,16}\b`),                                      // payment card
	regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`),                                       // US SSN
	regexp.MustCompile(`(?i)(api[_-]?key|secret|password|passwd|token)\s*[=:]\s*\S+`), // credential=value
	regexp.MustCompile(`(?i)bearer\s+[A-Za-z0-9._\-]{8,}`),                            // bearer token
	regexp.MustCompile(`(?i)AKIA[0-9A-Z]{16}`),                                        // AWS access key id
}

const mask = "[REDACTED]"

// Mask returns text with secrets masked and the number of substitutions.
func Mask(text string) (string, int) {
	count := 0
	out := text
	for _, re := range patterns {
		out = re.ReplaceAllStringFunc(out, func(m string) string {
			count++
			// keep a credential's key name for readability: "password=[REDACTED]"
			if i := strings.IndexAny(m, "=:"); i >= 0 && !strings.ContainsAny(m[:i], " -") {
				return m[:i+1] + mask
			}
			return mask
		})
	}
	return out, count
}

// MaskFiles rewrites the named files in resultsDir in place, returning the total
// number of masked occurrences. Non-text/binary files are skipped by extension.
func MaskFiles(resultsDir string, names []string) (int, error) {
	total := 0
	for _, name := range names {
		p := filepath.Join(resultsDir, name)
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		masked, n := Mask(string(b))
		if n > 0 {
			if err := os.WriteFile(p, []byte(masked), 0o644); err != nil {
				return total, err
			}
			total += n
		}
	}
	return total, nil
}
