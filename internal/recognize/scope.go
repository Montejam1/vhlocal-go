package recognize

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
)

// Scope is a resolved enclosing function/method span for a source line.
type Scope struct {
	Start int      // 1-based first line (declaration, incl. Go doc/decorators where applicable)
	End   int      // 1-based last line
	Owner []string // enclosing symbol chain (outer→inner), e.g. ["Server", "handleLogin"]
	Found bool
}

// EnclosingScope returns the containing function/method span + owner chain for a
// 1-based line in source, per language (contract C-S1, FR-028). Go uses the stdlib
// AST; brace-delimited languages use a bracket scanner; Python uses indentation;
// Ruby uses def/end. It performs no execution and needs no target runtime.
func EnclosingScope(lang Language, source []byte, line int) Scope {
	switch lang {
	case LangGo:
		return goScope(source, line)
	case LangPython:
		return indentScope(source, line, []string{"def ", "async def ", "class "})
	case LangRuby:
		return rubyScope(source, line)
	default: // brace-delimited: js/ts/java/kotlin/csharp/c/cpp/rust/php
		return braceScope(source, line)
	}
}

// goScope uses go/ast to find the innermost func/method declaration covering line.
func goScope(source []byte, line int) Scope {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "", source, 0)
	if err != nil || f == nil {
		return braceScope(source, line) // tolerate parse errors with a brace fallback
	}
	best := Scope{}
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok {
			continue
		}
		start := fset.Position(fn.Pos()).Line
		end := fset.Position(fn.End()).Line
		if line < start || line > end {
			continue
		}
		owner := []string{}
		if fn.Recv != nil && len(fn.Recv.List) > 0 {
			owner = append(owner, recvTypeName(fn.Recv.List[0].Type))
		}
		owner = append(owner, fn.Name.Name)
		// Innermost (smallest span) wins.
		if !best.Found || (end-start) < (best.End-best.Start) {
			best = Scope{Start: start, End: end, Owner: owner, Found: true}
		}
	}
	return best
}

func recvTypeName(e ast.Expr) string {
	switch t := e.(type) {
	case *ast.StarExpr:
		return recvTypeName(t.X)
	case *ast.Ident:
		return t.Name
	}
	return ""
}

// braceScope finds the innermost `{ ... }` block enclosing line and treats the
// header line before the opening brace as the declaration start. Comment/string
// aware enough to skip braces inside "..." '...' `...` and // /* */ comments.
func braceScope(source []byte, line int) Scope {
	lines := splitLines(source)
	// Match brace positions by line using a stack over tokens.
	var stack []struct{ line int }
	var spans []struct{ open, close int }
	inBlockComment := false
	for i, ln := range lines {
		inBlockComment = scanBraces(ln, i+1, &stack, &spans, inBlockComment)
	}
	best := Scope{}
	for _, s := range spans {
		// Declaration header is the open-brace line (or the line above if the brace
		// is alone). Use the open line as start; end is the close line.
		start := s.open
		if strings.TrimSpace(lines[s.open-1]) == "{" && s.open > 1 {
			start = s.open - 1
		}
		if line < start || line > s.close {
			continue
		}
		if !best.Found || (s.close-start) < (best.End-best.Start) {
			best = Scope{Start: start, End: s.close, Owner: nil, Found: true}
		}
	}
	return best
}

// scanBraces advances brace matching for one line, returning the updated
// in-block-comment state. It ignores braces inside strings and comments.
func scanBraces(ln string, lineNo int, stack *[]struct{ line int }, spans *[]struct{ open, close int }, inBlock bool) bool {
	i := 0
	for i < len(ln) {
		c := ln[i]
		if inBlock {
			if c == '*' && i+1 < len(ln) && ln[i+1] == '/' {
				inBlock = false
				i += 2
				continue
			}
			i++
			continue
		}
		switch c {
		case '/':
			if i+1 < len(ln) && ln[i+1] == '/' {
				return inBlock // rest of line is a line comment
			}
			if i+1 < len(ln) && ln[i+1] == '*' {
				inBlock = true
				i += 2
				continue
			}
			i++
		case '"', '\'', '`':
			i = skipString(ln, i, c)
		case '{':
			*stack = append(*stack, struct{ line int }{lineNo})
			i++
		case '}':
			if n := len(*stack); n > 0 {
				open := (*stack)[n-1].line
				*stack = (*stack)[:n-1]
				*spans = append(*spans, struct{ open, close int }{open, lineNo})
			}
			i++
		default:
			i++
		}
	}
	return inBlock
}

// skipString returns the index just past a string literal starting at i (quote q).
func skipString(ln string, i int, q byte) int {
	i++ // past opening quote
	for i < len(ln) {
		if ln[i] == '\\' {
			i += 2
			continue
		}
		if ln[i] == q {
			return i + 1
		}
		i++
	}
	return i
}

// indentScope finds the smallest enclosing block introduced by one of the given
// keywords, by significant indentation (Python).
func indentScope(source []byte, line int, keywords []string) Scope {
	lines := splitLines(source)
	if line < 1 || line > len(lines) {
		return Scope{}
	}
	best := Scope{}
	for i := 0; i < len(lines); i++ {
		trimmed := strings.TrimLeft(lines[i], " \t")
		if !hasAnyPrefix(trimmed, keywords) {
			continue
		}
		start := i + 1
		indent := leadingWS(lines[i])
		// extend up across decorator lines at the same indent
		for start > 1 {
			prev := lines[start-2]
			if strings.HasPrefix(strings.TrimLeft(prev, " \t"), "@") && leadingWS(prev) == indent {
				start--
			} else {
				break
			}
		}
		// end: down while indentation greater than the def's (skipping blanks)
		end := i + 1
		for j := i + 1; j < len(lines); j++ {
			if strings.TrimSpace(lines[j]) == "" {
				continue
			}
			if leadingWS(lines[j]) > indent {
				end = j + 1
			} else {
				break
			}
		}
		if line < start || line > end {
			continue
		}
		if !best.Found || (end-start) < (best.End-best.Start) {
			best = Scope{Start: start, End: end, Found: true, Owner: indentOwner(trimmed)}
		}
	}
	return best
}

// rubyScope matches def...end blocks by depth.
func rubyScope(source []byte, line int) Scope {
	lines := splitLines(source)
	type open struct{ line int }
	var stack []open
	type span struct{ start, end int }
	var spans []span
	for i, ln := range lines {
		t := strings.TrimSpace(ln)
		if strings.HasPrefix(t, "def ") || t == "def" || strings.HasPrefix(t, "class ") || strings.HasPrefix(t, "module ") {
			stack = append(stack, open{i + 1})
		} else if t == "end" || strings.HasPrefix(t, "end ") || strings.HasPrefix(t, "end#") {
			if n := len(stack); n > 0 {
				s := stack[n-1]
				stack = stack[:n-1]
				spans = append(spans, span{s.line, i + 1})
			}
		}
	}
	best := Scope{}
	for _, s := range spans {
		if line < s.start || line > s.end {
			continue
		}
		if !best.Found || (s.end-s.start) < (best.End-best.Start) {
			best = Scope{Start: s.start, End: s.end, Found: true}
		}
	}
	return best
}

// helpers

func splitLines(b []byte) []string { return strings.Split(string(b), "\n") }

func leadingWS(s string) int {
	n := 0
	for _, r := range s {
		if r == ' ' || r == '\t' {
			n++
		} else {
			break
		}
	}
	return n
}

func hasAnyPrefix(s string, prefixes []string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}

// indentOwner extracts the declared name from a `def name(`, `async def name(` or
// `class Name(`/`class Name:` line; nil when it cannot be read.
func indentOwner(trimmed string) []string {
	for _, kw := range []string{"async def ", "def ", "class "} {
		if strings.HasPrefix(trimmed, kw) {
			rest := trimmed[len(kw):]
			end := strings.IndexAny(rest, "(:= \t")
			if end < 0 {
				end = len(rest)
			}
			if name := strings.TrimSpace(rest[:end]); name != "" {
				return []string{name}
			}
		}
	}
	return nil
}
