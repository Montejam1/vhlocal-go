package recognize

import "testing"

// T006 (FR-028, C-S1): the Go scope resolver (stdlib go/ast) returns the innermost
// method span + owner chain.
func TestEnclosingScopeGo(t *testing.T) {
	src := []byte(`package p

func (s *Server) Handle(w int) {
	x := 1
	_ = x
}

func Free() {}
`)
	sc := EnclosingScope(LangGo, src, 4) // inside Handle
	if !sc.Found || sc.Start != 3 || sc.End != 6 {
		t.Fatalf("Go scope span wrong: %+v", sc)
	}
	if len(sc.Owner) != 2 || sc.Owner[0] != "Server" || sc.Owner[1] != "Handle" {
		t.Fatalf("Go owner chain wrong: %v", sc.Owner)
	}
}

// T006: brace-based resolver for JS/TS-style code.
func TestEnclosingScopeBrace(t *testing.T) {
	src := []byte("function outer() {\n  const x = 1;\n  return x;\n}\n")
	sc := EnclosingScope(LangJavaScript, src, 3)
	if !sc.Found || sc.Start != 1 || sc.End != 4 {
		t.Fatalf("brace scope wrong: %+v", sc)
	}
}

// T006: brace matching ignores braces inside strings and comments.
func TestEnclosingScopeBraceIgnoresStringsAndComments(t *testing.T) {
	src := []byte("function f() {\n  const s = \"a { b } c\"; // trailing } brace\n  return s;\n}\n")
	sc := EnclosingScope(LangTypeScript, src, 3)
	if !sc.Found || sc.Start != 1 || sc.End != 4 {
		t.Fatalf("brace scope must ignore braces in strings/comments: %+v", sc)
	}
}

// T006: Python indentation resolver.
func TestEnclosingScopePython(t *testing.T) {
	src := []byte("def outer():\n    x = 1\n    return x\n\ndef other():\n    pass\n")
	sc := EnclosingScope(LangPython, src, 3)
	if !sc.Found || sc.Start != 1 || sc.End != 3 {
		t.Fatalf("python scope wrong: %+v", sc)
	}
}

// T006: Ruby def/end resolver.
func TestEnclosingScopeRuby(t *testing.T) {
	src := []byte("def foo\n  bar\nend\n\ndef baz\n  qux\nend\n")
	sc := EnclosingScope(LangRuby, src, 2)
	if !sc.Found || sc.Start != 1 || sc.End != 3 {
		t.Fatalf("ruby scope wrong: %+v", sc)
	}
}
