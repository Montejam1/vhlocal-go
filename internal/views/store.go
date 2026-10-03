// Package views persists named saved queue filters/sort for the analyst
// workspace (feature 010, FR-006). It is a per-operator convenience stored under
// ~/.vhlocal/views; each view is one JSON file written atomically (temp+rename),
// mirroring the job-store persistence discipline. It holds no scan evidence.
package views

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"vhlocal/internal/config"
)

// View is a named, reusable set of queue filters and a sort choice.
type View struct {
	ID        string            `json:"id"`
	Name      string            `json:"name"`
	Filters   map[string]string `json:"filters"`
	Sort      map[string]string `json:"sort"`
	CreatedAt float64           `json:"created_at"`
	UpdatedAt float64           `json:"updated_at"`
}

func dir() string { return config.ViewsDir() }

// List returns all saved views, newest-updated first.
func List() ([]View, error) {
	entries, err := os.ReadDir(dir())
	if err != nil {
		if os.IsNotExist(err) {
			return []View{}, nil
		}
		return nil, err
	}
	var out []View
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		if v, ok := load(filepath.Join(dir(), e.Name())); ok {
			out = append(out, v)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].UpdatedAt > out[j].UpdatedAt })
	if out == nil {
		out = []View{}
	}
	return out, nil
}

// Get returns one view by id.
func Get(id string) (View, bool) {
	if !validID(id) {
		return View{}, false
	}
	return load(filepath.Join(dir(), id+".json"))
}

// Save creates or replaces a view. A non-empty name is required (FR-006). When
// v.ID is empty a stable id is derived from the name. It returns the stored view.
func Save(v View) (View, error) {
	if strings.TrimSpace(v.Name) == "" {
		return View{}, errors.New("view name is required")
	}
	if v.ID == "" {
		v.ID = slug(v.Name)
	}
	if !validID(v.ID) {
		return View{}, errors.New("invalid view id")
	}
	now := float64(time.Now().Unix())
	if existing, ok := load(filepath.Join(dir(), v.ID+".json")); ok {
		v.CreatedAt = existing.CreatedAt
	} else {
		v.CreatedAt = now
	}
	v.UpdatedAt = now
	if v.Filters == nil {
		v.Filters = map[string]string{}
	}
	if v.Sort == nil {
		v.Sort = map[string]string{}
	}
	if err := writeAtomic(filepath.Join(dir(), v.ID+".json"), v); err != nil {
		return View{}, err
	}
	return v, nil
}

// Delete removes a view; deleting a missing view is not an error.
func Delete(id string) error {
	if !validID(id) {
		return errors.New("invalid view id")
	}
	err := os.Remove(filepath.Join(dir(), id+".json"))
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func load(path string) (View, bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return View{}, false
	}
	var v View
	if json.Unmarshal(b, &v) != nil || v.ID == "" {
		return View{}, false
	}
	return v, true
}

func writeAtomic(path string, v any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// validID keeps ids to a safe, path-contained slug charset.
func validID(id string) bool {
	if id == "" || len(id) > 128 || strings.ContainsAny(id, "/\\.") {
		return false
	}
	for _, r := range id {
		if !(r == '-' || r == '_' || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')) {
			return false
		}
	}
	return true
}

func slug(name string) string {
	var b strings.Builder
	prevDash := false
	for _, r := range strings.ToLower(strings.TrimSpace(name)) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
			prevDash = false
		default:
			if !prevDash && b.Len() > 0 {
				b.WriteByte('-')
				prevDash = true
			}
		}
	}
	s := strings.Trim(b.String(), "-")
	if s == "" {
		s = "view"
	}
	if len(s) > 96 {
		s = s[:96]
	}
	return s
}
