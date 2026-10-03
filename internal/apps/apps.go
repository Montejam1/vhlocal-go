// Package apps is the applications registry: a repo grouped across its scans,
// with a human name. Stored as applications.json next to the ledger dir. Slug is
// the same stable membank slug of the resolved repo path. Mirrors apps.py.
package apps

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"time"

	"vhlocal/internal/config"
	"vhlocal/internal/membank"
)

var validSlug = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

// IsValidSlug reports whether s is a safe slug (no traversal).
func IsValidSlug(s string) bool {
	return validSlug.MatchString(s) && !containsDotDot(s)
}

func containsDotDot(s string) bool {
	for i := 0; i+1 < len(s); i++ {
		if s[i] == '.' && s[i+1] == '.' {
			return true
		}
	}
	return false
}

// Entry is a registry record. A hidden (forgotten) entry carries only slug+hidden.
type Entry struct {
	Slug    string  `json:"slug"`
	Name    string  `json:"name,omitempty"`
	Repo    string  `json:"repo,omitempty"`
	Created float64 `json:"created,omitempty"`
	Updated float64 `json:"updated,omitempty"`
	Hidden  bool    `json:"hidden,omitempty"`
}

func storePath() string {
	return filepath.Join(filepath.Dir(config.LedgerDir()), "applications.json")
}

func loadAll() map[string]Entry {
	out := map[string]Entry{}
	b, err := os.ReadFile(storePath())
	if err != nil {
		return out
	}
	_ = json.Unmarshal(b, &out)
	return out
}

func saveAll(m map[string]Entry) error {
	if err := os.MkdirAll(filepath.Dir(storePath()), 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	tmp := storePath() + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, storePath())
}

// SlugFor returns the registry slug for a repo path.
func SlugFor(repo string) string { return membank.Slug(repo) }

// Register ensures an entry exists for repo (unnamed), returning its slug.
func Register(repo string) (string, error) {
	slug := membank.Slug(repo)
	all := loadAll()
	if e, ok := all[slug]; !ok || e.Hidden {
		now := float64(time.Now().Unix())
		all[slug] = Entry{Slug: slug, Repo: repo, Created: now, Updated: now}
		if err := saveAll(all); err != nil {
			return slug, err
		}
	}
	return slug, nil
}

// SetName sets/creates the human name for a slug, returning the entry.
func SetName(slug, name, repo string) (Entry, error) {
	all := loadAll()
	e, ok := all[slug]
	now := float64(time.Now().Unix())
	if !ok || e.Hidden {
		e = Entry{Slug: slug, Repo: repo, Created: now}
	}
	e.Name = name
	e.Hidden = false
	e.Updated = now
	if e.Repo == "" {
		e.Repo = repo
	}
	all[slug] = e
	return e, saveAll(all)
}

// Forget hides an application (keeps its reports; the caller deletes the ledger).
func Forget(slug string) error {
	all := loadAll()
	all[slug] = Entry{Slug: slug, Hidden: true}
	return saveAll(all)
}

// Lookup returns the registry entry for a slug (ok=false if unknown/hidden).
func Lookup(slug string) (Entry, bool) {
	e, ok := loadAll()[slug]
	if !ok || e.Hidden {
		return Entry{}, false
	}
	return e, true
}

// List returns non-hidden entries, newest-updated first.
func List() []Entry {
	var out []Entry
	for _, e := range loadAll() {
		if !e.Hidden {
			out = append(out, e)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Updated > out[j].Updated })
	return out
}
