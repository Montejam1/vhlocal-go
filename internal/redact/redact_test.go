package redact

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMask(t *testing.T) {
	in := "card 4111 1111 1111 1111 ssn 123-45-6789 password=hunter2 bearer abcdef1234567890"
	out, n := Mask(in)
	if n < 4 {
		t.Fatalf("expected >=4 masks, got %d: %q", n, out)
	}
	for _, secret := range []string{"4111 1111 1111 1111", "123-45-6789", "hunter2", "abcdef1234567890"} {
		if strings.Contains(out, secret) {
			t.Errorf("secret not masked: %q in %q", secret, out)
		}
	}
	if !strings.Contains(out, "password=[REDACTED]") {
		t.Errorf("credential key should be kept: %q", out)
	}
}

func TestMaskFiles(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "a.md"), []byte("ssn 123-45-6789"), 0o644)
	os.WriteFile(filepath.Join(dir, "b.md"), []byte("no secrets here"), 0o644)
	n, err := MaskFiles(dir, []string{"a.md", "b.md"})
	if err != nil || n != 1 {
		t.Fatalf("masked=%d err=%v", n, err)
	}
	b, _ := os.ReadFile(filepath.Join(dir, "a.md"))
	if strings.Contains(string(b), "123-45-6789") {
		t.Error("file not redacted")
	}
}
