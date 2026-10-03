package engine

import (
	"context"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"vhlocal/internal/client"
	"vhlocal/internal/report"
)

// countingProvider counts Chat calls so a test can prove report building and
// regeneration never consult a model (C-A5, SC-014).
type countingProvider struct {
	inner client.Provider
	n     atomic.Int64
}

func (c *countingProvider) Backend() client.Backend { return c.inner.Backend() }
func (c *countingProvider) Endpoint() string        { return c.inner.Endpoint() }
func (c *countingProvider) Chat(ctx context.Context, req client.ChatRequest) (*client.ChatResponse, error) {
	c.n.Add(1)
	return c.inner.Chat(ctx, req)
}

// T016 (C-A1, C-A5): report_model.json and both reports are byte-identical after
// regeneration, which makes no model call.
func TestReportModelRegeneratesByteIdentical(t *testing.T) {
	repo := filepath.Join(repoRoot(t), "testdata", "vulnapp")
	results := t.TempDir()
	spec := brokenSpec(repo, results)
	spec.Phases = []string{"1", "2", "2b"}
	cp := &countingProvider{inner: &pathWriter{model: "m"}}
	if _, err := Execute(context.Background(), spec, Providers{Hunt: cp}, staticSkill{}, nil); err != nil {
		t.Fatal(err)
	}
	calls := cp.n.Load()
	if calls == 0 {
		t.Fatal("scan made no model calls")
	}
	read := func() (string, string, string) {
		m, _ := os.ReadFile(filepath.Join(results, report.ModelFile))
		md, _ := os.ReadFile(filepath.Join(results, "SCAN_REPORT.md"))
		h, _ := os.ReadFile(filepath.Join(results, "SCAN_REPORT.html"))
		if len(m) == 0 {
			t.Fatal("report_model.json not written")
		}
		return string(m), string(md), string(h)
	}
	m1, md1, h1 := read()
	if err := Regenerate(results); err != nil {
		t.Fatal(err)
	}
	m2, md2, h2 := read()
	if m1 != m2 {
		t.Error("report_model.json differs after regeneration")
	}
	if md1 != md2 || h1 != h2 {
		t.Error("reports differ after regeneration")
	}
	if cp.n.Load() != calls {
		t.Errorf("regeneration made %d model call(s)", cp.n.Load()-calls)
	}
	mdl, err := report.LoadModel(results)
	if err != nil || mdl.Version != report.ModelVersion || mdl.ScanID != filepath.Base(results) {
		t.Errorf("model: %v version=%d scan_id=%q", err, mdl.Version, mdl.ScanID)
	}
}
