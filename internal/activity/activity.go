// Package activity is the append-only activity feed backing GET /api/activity.
// Events are JSONL rows; Recent returns them newest-first with optional type and
// scan filters. Nil/empty extra fields are dropped so rows stay compact.
package activity

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Event is one activity row. Extra carries type-specific fields (scan, repo,
// model, findings, ...) merged into the JSON object alongside the core fields.
type Event struct {
	Ts      float64
	Type    string
	Message string
	Extra   map[string]any
}

// MarshalJSON emits {ts,type,message,...extra} with empty extra values dropped.
func (e Event) MarshalJSON() ([]byte, error) {
	m := map[string]any{"ts": e.Ts, "type": e.Type, "message": e.Message}
	for k, v := range e.Extra {
		if v == nil {
			continue
		}
		if s, ok := v.(string); ok && s == "" {
			continue
		}
		m[k] = v
	}
	return json.Marshal(m)
}

// Feed is a file-backed activity log.
type Feed struct {
	mu   sync.Mutex
	path string
}

// New returns a Feed writing to path (created lazily on first Record).
func New(path string) *Feed { return &Feed{path: path} }

// Record appends an event with the current timestamp.
func (f *Feed) Record(typ, message string, extra map[string]any) error {
	ev := Event{Ts: float64(time.Now().UnixNano()) / 1e9, Type: typ, Message: message, Extra: extra}
	b, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := os.MkdirAll(filepath.Dir(f.path), 0o755); err != nil {
		return err
	}
	fh, err := os.OpenFile(f.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer fh.Close()
	_, err = fh.Write(append(b, '\n'))
	return err
}

// rawEvent is used for reading back rows (preserving all fields).
type rawEvent map[string]any

// Recent returns up to limit events newest-first. typePrefix filters by a type
// prefix (e.g. "scan"); scan filters by exact scan id. Both empty = no filter.
func (f *Feed) Recent(limit int, typePrefix, scan string) ([]map[string]any, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fh, err := os.Open(f.path)
	if err != nil {
		if os.IsNotExist(err) {
			return []map[string]any{}, nil
		}
		return nil, err
	}
	defer fh.Close()
	var all []map[string]any
	sc := bufio.NewScanner(fh)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var ev rawEvent
		if json.Unmarshal([]byte(line), &ev) != nil {
			continue
		}
		if typePrefix != "" {
			t, _ := ev["type"].(string)
			if !strings.HasPrefix(t, typePrefix) {
				continue
			}
		}
		if scan != "" {
			s, _ := ev["scan"].(string)
			if s != scan {
				continue
			}
		}
		all = append(all, ev)
	}
	// newest-first by ts
	sort.SliceStable(all, func(i, j int) bool {
		return toF(all[i]["ts"]) > toF(all[j]["ts"])
	})
	if limit > 0 && len(all) > limit {
		all = all[:limit]
	}
	if all == nil {
		all = []map[string]any{}
	}
	return all, nil
}

func toF(v any) float64 {
	if f, ok := v.(float64); ok {
		return f
	}
	return 0
}
