// Package authz builds a deterministic authorization map from a repo's
// enumerated entry points: for each route, whether an authentication/session
// check appears in its handler file, and which routes have none (cross-endpoint
// gaps). Written per scan as authz_map.json and available via `vhlocal authz`.
// Heuristic and static-only (no code execution).
package authz

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"

	"vhlocal/internal/inventory"
)

const File = "authz_map.json"

var reAuthCheck = regexp.MustCompile(`(?i)\b(session|login_required|current_user|require_auth|is_authenticated|authorize|@login_required|g\.user|request\.user|verify_token|check_permission|has_role|current_identity)\b`)

// Endpoint is one route with its authorization disposition.
type Endpoint struct {
	Method       string `json:"method"`
	Path         string `json:"path"`
	File         string `json:"file"`
	Line         int    `json:"line"`
	HasAuthCheck bool   `json:"has_auth_check"`
	Evidence     string `json:"evidence"`
}

// Map is the authz_map.json document.
type Map struct {
	Repo      string     `json:"repo"`
	Total     int        `json:"total"`
	Protected int        `json:"protected"`
	Gaps      []Endpoint `json:"gaps"`
	Endpoints []Endpoint `json:"endpoints"`
}

// Build enumerates routes and derives each one's auth disposition by checking its
// handler file for an authentication/session pattern.
func Build(repo string) Map {
	routes, _ := inventory.EnumerateRoutes(repo)
	m := Map{Repo: repo, Endpoints: []Endpoint{}, Gaps: []Endpoint{}}
	// cache file contents
	cache := map[string]bool{}
	for _, r := range routes {
		key := r.File
		has, ok := cache[key]
		if !ok {
			has = fileHasAuth(filepath.Join(repo, r.File))
			cache[key] = has
		}
		ep := Endpoint{Method: r.Method, Path: r.Path, File: r.File, Line: r.Line, HasAuthCheck: has}
		if has {
			ep.Evidence = "auth/session pattern present in " + r.File
			m.Protected++
		} else {
			ep.Evidence = "no auth/session pattern found in handler file"
			m.Gaps = append(m.Gaps, ep)
		}
		m.Endpoints = append(m.Endpoints, ep)
	}
	m.Total = len(m.Endpoints)
	return m
}

func fileHasAuth(path string) bool {
	b, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	return reAuthCheck.Match(b)
}

// Write emits authz_map.json into resultsDir.
func Write(repo, resultsDir string) (string, error) {
	b, err := json.MarshalIndent(Build(repo), "", "  ")
	if err != nil {
		return "", err
	}
	out := filepath.Join(resultsDir, File)
	return out, os.WriteFile(out, b, 0o644)
}
