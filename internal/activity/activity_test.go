package activity

import (
	"encoding/json"
	"path/filepath"
	"testing"
)

func TestRecordAndRecentNewestFirst(t *testing.T) {
	f := New(filepath.Join(t.TempDir(), "activity.jsonl"))
	_ = f.Record("scan.started", "started A", map[string]any{"scan": "A", "model": "m"})
	_ = f.Record("scan.completed", "done A", map[string]any{"scan": "A", "findings": 3})
	_ = f.Record("report.deleted", "deleted", map[string]any{"report": "r1"})

	got, err := f.Recent(0, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("want 3 events, got %d", len(got))
	}
	// newest-first
	if got[0]["type"] != "report.deleted" {
		t.Errorf("newest should be report.deleted, got %v", got[0]["type"])
	}
}

func TestRecentFilters(t *testing.T) {
	f := New(filepath.Join(t.TempDir(), "activity.jsonl"))
	_ = f.Record("scan.started", "A", map[string]any{"scan": "A"})
	_ = f.Record("scan.completed", "B", map[string]any{"scan": "B"})
	_ = f.Record("app.named", "named", map[string]any{"app": "x"})

	scanOnly, _ := f.Recent(0, "scan", "")
	if len(scanOnly) != 2 {
		t.Fatalf("type prefix 'scan' => want 2, got %d", len(scanOnly))
	}
	justB, _ := f.Recent(0, "", "B")
	if len(justB) != 1 || justB[0]["scan"] != "B" {
		t.Fatalf("scan filter B => %v", justB)
	}
}

func TestEmptyExtraDropped(t *testing.T) {
	ev := Event{Ts: 1, Type: "t", Message: "m", Extra: map[string]any{"scan": "", "model": "x", "n": nil}}
	b, _ := json.Marshal(ev)
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	if _, ok := m["scan"]; ok {
		t.Error("empty string extra should be dropped")
	}
	if _, ok := m["n"]; ok {
		t.Error("nil extra should be dropped")
	}
	if m["model"] != "x" {
		t.Error("non-empty extra should be kept")
	}
}
