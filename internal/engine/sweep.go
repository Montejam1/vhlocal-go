package engine

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"vhlocal/internal/consolidate"
	"vhlocal/internal/source"
	"vhlocal/internal/tools"
)

var sweepCall = regexp.MustCompile(`([A-Za-z_][\w.]*)\s*\(`)

// writeSweep enumerates syntactic leads without promoting them to findings or
// spending model calls. Scope, exclusions and patterns follow Python sweep.py.
func writeSweep(repo, root string, findings []consolidate.Finding) error {
	var b strings.Builder
	b.WriteString("# Phase 3d: Root-cause instance sweep (deterministic)\n\nMatches are leads for review, not confirmed additional vulnerabilities. Test, vendor and generated code is excluded.\n\n")
	if len(findings) == 0 {
		b.WriteString("Skipped: no structurally validated supported candidates.\n")
	}
	for _, f := range findings {
		fmt.Fprintf(&b, "## %s — %s (%s)\n\n", f.ID, f.Title, f.CWE)
		patterns, kind := consolidate.SweepSinkPatterns(f.CWE)
		if kind == "logic" {
			b.WriteString("Authorization/logic finding: no syntactic sink to sweep; instances require behavioral review.\n\n")
			continue
		}
		set := map[string]bool{}
		for _, p := range patterns {
			set[p] = true
		}
		common := map[string]bool{"get": true, "post": true, "str": true, "int": true, "list": true, "dict": true, "len": true, "print": true, "format": true, "join": true, "range": true, "isinstance": true, "super": true, "open": true}
		for _, m := range sweepCall.FindAllStringSubmatch(f.DataFlow+" "+f.Title, -1) {
			token := m[1]
			if strings.Contains(token, ".") || (!common[strings.ToLower(token)] && len(token) > 3) {
				set[regexp.QuoteMeta(token)+`\s*\(`] = true
			}
		}
		patterns = nil
		for p := range set {
			patterns = append(patterns, p)
		}
		sort.Strings(patterns)
		if len(patterns) == 0 {
			b.WriteString("No sink pattern derivable for this class.\n\n")
			continue
		}
		var matchers []*regexp.Regexp
		for _, p := range patterns {
			re, err := regexp.Compile(p)
			if err != nil {
				return err
			}
			matchers = append(matchers, re)
		}
		fmt.Fprintf(&b, "Patterns: `%s`\n\n| File:line | Lead? | Match |\n|---|---|---|\n", strings.Join(patterns, "`, `"))
		origin := strings.SplitN(f.Location, ":", 2)[0]
		lang := sweepLanguage(filepath.Ext(origin))
		err := filepath.WalkDir(repo, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			name := strings.ToLower(d.Name())
			if d.IsDir() {
				if path != repo && (tools.SkipDirs[d.Name()] || strings.HasPrefix(name, "test")) {
					return filepath.SkipDir
				}
				return nil
			}
			if d.Type()&os.ModeSymlink != 0 || strings.HasPrefix(name, "test") || strings.HasPrefix(name, "conftest") {
				return nil
			}
			if ext := filepath.Ext(path); ext == ".md" || (lang != "" && sweepLanguage(ext) != lang) {
				return nil
			}
			rel, err := filepath.Rel(repo, path)
			if err != nil {
				return err
			}
			data, err := source.ReadFile(repo, rel)
			if err != nil {
				return err
			}
			if strings.ContainsRune(string(data), 0) {
				return nil
			}
			for i, line := range strings.Split(string(data), "\n") {
				for _, re := range matchers {
					if re.MatchString(line) {
						loc := fmt.Sprintf("%s:%d", filepath.ToSlash(rel), i+1)
						lead := "**LEAD**"
						if loc == f.Location || strings.HasPrefix(f.Location, loc+"-") {
							lead = "origin"
						}
						text := strings.TrimSpace(line)
						if len(text) > 160 {
							text = text[:160]
						}
						fmt.Fprintf(&b, "| `%s` | %s | `%s` |\n", loc, lead, strings.ReplaceAll(text, "|", "\\|"))
						break
					}
				}
			}
			return nil
		})
		if err != nil {
			return err
		}
		b.WriteString("\n")
	}
	return os.WriteFile(filepath.Join(root, "phase3d_output.md"), []byte(b.String()), 0644)
}

func sweepLanguage(ext string) string {
	switch strings.ToLower(ext) {
	case ".js", ".jsx", ".mjs":
		return "js"
	case ".ts", ".tsx":
		return "ts"
	case ".py", ".go", ".rb", ".php", ".java":
		return strings.ToLower(ext)
	default:
		return ""
	}
}
