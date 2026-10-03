package recognize

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// Classification of a source file in the census.
const (
	ClassProduction  = "production"
	ClassTest        = "test"
	ClassGenerated   = "generated"
	ClassDependency  = "dependency"
	ClassUnreadable  = "unreadable"
	ClassUnsupported = "unsupported"
)

// CensusEntry is one first-party source file's census record (US1, FR-007/008).
type CensusEntry struct {
	Path           string   `json:"path"` // repo-relative
	Language       Language `json:"language,omitempty"`
	Module         string   `json:"module"`
	Classification string   `json:"classification"`
	Reason         string   `json:"reason,omitempty"` // why excluded (non-production)
}

// extLang maps a file extension to a baseline language ("" = unsupported).
var extLang = map[string]Language{
	".py": LangPython, ".go": LangGo,
	".js": LangJavaScript, ".jsx": LangJavaScript, ".mjs": LangJavaScript, ".cjs": LangJavaScript,
	".ts": LangTypeScript, ".tsx": LangTypeScript,
	".java": LangJava, ".kt": LangKotlin, ".kts": LangKotlin,
	".cs": LangCSharp,
	".c":  LangC, ".h": LangC,
	".cc": LangCPP, ".cpp": LangCPP, ".cxx": LangCPP, ".hpp": LangCPP, ".hh": LangCPP,
	".rs": LangRust, ".rb": LangRuby, ".php": LangPHP,
}

// depDirs are dependency/vendor directories excluded from first-party census.
var depDirs = map[string]bool{
	".git": true, "node_modules": true, "vendor": true, "third_party": true, "external": true,
	"deps": true, "dist": true, "build": true, "target": true, "__pycache__": true, ".venv": true,
	"venv": true, ".tox": true, ".mypy_cache": true, ".pytest_cache": true, ".idea": true,
	".vscode": true, "site-packages": true, "bin": true, "obj": true,
}

// LanguageFor returns the baseline language for a path, if recognized.
func LanguageFor(path string) (Language, bool) {
	l, ok := extLang[strings.ToLower(filepath.Ext(path))]
	return l, ok
}

// Census walks repoRoot and classifies first-party source (FR-007/008/010). It is
// static and path-confined; it does not follow symlinks out of the tree and never
// executes anything. Excluded dependencies/generated code are recorded with a
// reason and are NOT production source.
func Census(repoRoot string) ([]CensusEntry, error) {
	var out []CensusEntry
	rootAbs, err := filepath.Abs(repoRoot)
	if err != nil {
		return nil, err
	}
	err = filepath.WalkDir(rootAbs, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // tolerate unreadable entries; a bad file never fails the walk
		}
		if d.IsDir() {
			if p != rootAbs && depDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		// Symlink containment: skip symlinks (never follow out of the tree).
		if d.Type()&fs.ModeSymlink != 0 {
			return nil
		}
		lang, ok := LanguageFor(p)
		if !ok {
			return nil // not a baseline-language source file; not censused
		}
		rel, _ := filepath.Rel(rootAbs, p)
		rel = filepath.ToSlash(rel)
		e := CensusEntry{Path: rel, Language: lang, Module: moduleOf(rel)}
		switch {
		case isTestPath(rel, lang):
			e.Classification, e.Reason = ClassTest, "test file"
		case isGenerated(rel):
			e.Classification, e.Reason = ClassGenerated, "generated code"
		case !readable(p):
			e.Classification, e.Reason = ClassUnreadable, "unreadable"
		default:
			e.Classification = ClassProduction
		}
		out = append(out, e)
		return nil
	})
	return out, err
}

func moduleOf(rel string) string {
	if i := strings.IndexByte(rel, '/'); i >= 0 {
		return rel[:i]
	}
	return "."
}

// isTestPath applies language-appropriate test conventions.
func isTestPath(rel string, lang Language) bool {
	base := strings.ToLower(filepath.Base(rel))
	for _, seg := range strings.Split(rel, "/") {
		if seg == "test" || seg == "tests" || seg == "__tests__" || seg == "spec" {
			return true
		}
	}
	switch lang {
	case LangGo:
		return strings.HasSuffix(base, "_test.go")
	case LangPython:
		return base == "conftest.py" || strings.HasPrefix(base, "test_") || strings.HasSuffix(base, "_test.py")
	case LangJavaScript, LangTypeScript:
		return strings.Contains(base, ".test.") || strings.Contains(base, ".spec.")
	case LangRuby:
		return strings.HasSuffix(base, "_test.rb") || strings.HasSuffix(base, "_spec.rb")
	}
	return false
}

func isGenerated(rel string) bool {
	base := filepath.Base(rel)
	return strings.HasSuffix(base, ".pb.go") || strings.Contains(base, ".generated.") ||
		strings.Contains(base, "_generated") || strings.HasSuffix(base, ".g.dart") ||
		strings.HasSuffix(base, ".designer.cs")
}

func readable(p string) bool {
	f, err := os.Open(p)
	if err != nil {
		return false
	}
	_ = f.Close()
	return true
}
