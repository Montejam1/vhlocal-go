package phases

import "strings"

// NormalizeText maps the typographic punctuation gpt-oss and similar models emit
// back to ASCII, so any regex over model output matches. This is load-bearing:
// gpt-oss writes "SG-1" with U+2011 NON-BREAKING HYPHEN, which silently broke
// partition-table parsing and collapsed Phase 2 coverage.
//
// The map is intentionally the exact set the Python phases.normalize_text uses —
// no broader Unicode normalization (NFC/NFKC would over-normalize). Every parser
// over untrusted model output MUST route through this first (constitution
// Principle: untrusted inputs; FR-025).
func NormalizeText(s string) string {
	if s == "" {
		return s
	}
	return punctReplacer.Replace(s)
}

// punctMap is the exact codepoint set (data-model §normalize_text), keyed by hex
// rune value so the bytes are unambiguous.
var punctMap = map[rune]string{
	// hyphens / dashes / minus -> "-"
	0x2010: "-", 0x2011: "-", 0x2012: "-", 0x2013: "-",
	0x2014: "-", 0x2015: "-", 0x2212: "-",
	// no-break (00A0) / figure (2007) / thin (2009) / narrow-no-break (202F) -> " "
	0x00A0: " ", 0x2007: " ", 0x2009: " ", 0x202F: " ",
	// smart quotes
	0x2018: "'", 0x2019: "'", 0x201C: "\"", 0x201D: "\"",
}

var punctReplacer = func() *strings.Replacer {
	pairs := make([]string, 0, len(punctMap)*2)
	for r, repl := range punctMap {
		pairs = append(pairs, string(r), repl)
	}
	return strings.NewReplacer(pairs...)
}()
