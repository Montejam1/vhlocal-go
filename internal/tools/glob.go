package tools

import (
	"regexp"
	"strings"
	"sync"
)

// globMatch reports whether name matches an fnmatch-style pattern with the SAME
// semantics as Python's fnmatch (which the phase prompts and the reference tools
// assume): `*` matches any run of characters INCLUDING `/` (so `**/*.py` and
// `*.py` both match nested paths), `?` matches any single character, and `[...]`
// is a character class (a leading `!` negates). This deliberately differs from Go's
// filepath.Match, whose `*` does not cross `/` and which has no `**` support —
// feature 005 R3 (FR-005).
func globMatch(pattern, name string) bool {
	re, err := compileGlob(pattern)
	if err != nil {
		return false
	}
	return re.MatchString(name)
}

var (
	globCacheMu sync.Mutex
	globCache   = map[string]*regexp.Regexp{}
)

func compileGlob(pattern string) (*regexp.Regexp, error) {
	globCacheMu.Lock()
	if re, ok := globCache[pattern]; ok {
		globCacheMu.Unlock()
		return re, nil
	}
	globCacheMu.Unlock()
	re, err := regexp.Compile(translateGlob(pattern))
	if err != nil {
		return nil, err
	}
	globCacheMu.Lock()
	globCache[pattern] = re
	globCacheMu.Unlock()
	return re, nil
}

// translateGlob converts an fnmatch pattern to an anchored regexp source, mirroring
// Python's fnmatch.translate: `*`→`.*` (spans `/`), `?`→`.`, `[...]`→a class, and
// every other character escaped. The result is a full-string match ((?s) so `.`
// also matches newlines, harmless for path strings).
func translateGlob(pattern string) string {
	var b strings.Builder
	b.WriteString(`(?s)\A`)
	i, n := 0, len(pattern)
	for i < n {
		c := pattern[i]
		i++
		switch c {
		case '*':
			// Collapse consecutive `*` (so `**` behaves like `*`, spanning `/`).
			for i < n && pattern[i] == '*' {
				i++
			}
			b.WriteString(`.*`)
		case '?':
			b.WriteString(`.`)
		case '[':
			j := i
			if j < n && (pattern[j] == '!' || pattern[j] == '^') {
				j++
			}
			if j < n && pattern[j] == ']' {
				j++
			}
			for j < n && pattern[j] != ']' {
				j++
			}
			if j >= n {
				// No closing ']': treat '[' as a literal.
				b.WriteString(`\[`)
			} else {
				class := pattern[i:j]
				i = j + 1
				class = strings.ReplaceAll(class, `\`, `\\`)
				b.WriteByte('[')
				if strings.HasPrefix(class, "!") {
					b.WriteByte('^')
					class = class[1:]
				}
				b.WriteString(class)
				b.WriteByte(']')
			}
		default:
			b.WriteString(regexp.QuoteMeta(string(c)))
		}
	}
	b.WriteString(`\z`)
	return b.String()
}
