// Package source confines harness reads to a resolved checkout or artifact root.
package source

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Resolve rejects absolute paths and paths whose symlinks escape root.
func Resolve(root, name string) (string, error) {
	if root == "" || name == "" || filepath.IsAbs(name) {
		return "", fmt.Errorf("path must be root-relative")
	}
	base, err := filepath.EvalSymlinks(root)
	if err != nil {
		return "", err
	}
	base, err = filepath.Abs(base)
	if err != nil {
		return "", err
	}
	path, err := filepath.EvalSymlinks(filepath.Join(base, name))
	if err != nil {
		return "", err
	}
	rel, err := filepath.Rel(base, path)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("path escapes root")
	}
	return path, nil
}

func ReadFile(root, name string) ([]byte, error) {
	path, err := Resolve(root, name)
	if err != nil {
		return nil, err
	}
	return os.ReadFile(path)
}
