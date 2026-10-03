package engine

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"vhlocal/internal/apps"
	"vhlocal/internal/reports"
)

func TestApplicationIdentityExistsBeforeScanStart(t *testing.T) {
	repo := sinkRepo(t)
	root := t.TempDir()
	dir := filepath.Join(root, "shop_VULNHUNT_RESULTS_m_2026-09-29-000000")
	spec := brokenSpec(repo, dir)
	spec.Phases = []string{"4"}
	spec.AppName = "Store"
	called := false
	_, err := Execute(context.Background(), spec, Providers{Hunt: silentProvider{}}, staticSkill{}, func(kind string, _ map[string]any) {
		if kind != "scan_start" {
			return
		}
		called = true
		b, e := os.ReadFile(filepath.Join(dir, ScanMetaFile))
		if e != nil {
			t.Error(e)
			return
		}
		var m map[string]any
		json.Unmarshal(b, &m)
		if m["schema"] != "partial" || m["app_slug"] != apps.SlugFor(repo) {
			t.Errorf("initial identity: %v", m)
		}
		if e = Regenerate(dir); e == nil {
			t.Error("regenerated an in-flight scan")
		}
		d, ok := apps.BuildDetail(apps.SlugFor(repo), root)
		if !ok || len(d.ScanHistory) != 1 {
			t.Errorf("missing provisional history: %+v", d)
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Fatal("no scan_start")
	}
	r, ok := reports.Load(dir)
	if !ok || r.Slug != apps.SlugFor(repo) {
		t.Fatalf("final identity: %+v", r)
	}
}
