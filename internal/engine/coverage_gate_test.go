package engine

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"vhlocal/internal/inventory"
)

// tablePartitionOnly returns a phase-1 output whose partition table covers only
// app/a.py, so a route in app/b.py is uncovered and coverage augmentation has
// something to add.
const phase1TableCoversAOnly = `## Subgraph Partitions

| ID | Subsystem | Entry points |
|----|----|----|
| SG-1 | a | GET /a (app/a.py) |

## Next
(end)
`

func coverageRoutes() []inventory.Route {
	return []inventory.Route{
		{File: "app/a.py", Method: "GET", Path: "/a", Line: 1},
		{File: "app/b.py", Method: "GET", Path: "/b", Line: 1},
	}
}

// Feature 013 (FR-012, SC-003): with enforce_coverage enabled (default), an
// incomplete partition plan is augmented to cover uncovered routes; with it
// disabled, augmentation is skipped but the uncovered scope is still measured and
// disclosed — neither state manufactures complete coverage.
func TestCoverageEnforcementGate(t *testing.T) {
	bTrue := true
	bFalse := false

	run := func(enforce *bool) *RunRecord {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "phase1_output.md"), []byte(phase1TableCoversAOnly), 0o644); err != nil {
			t.Fatal(err)
		}
		rec := &RunRecord{}
		spec := ScanSpec{ResultsDir: dir, MaxPartitions: 8, EnforceCoverage: enforce}
		resolveHuntPartitions(context.Background(), rec, tableRecon{}, spec, coverageRoutes())
		return rec
	}

	// Enabled (explicit true and default nil behave the same).
	for _, enforce := range []*bool{&bTrue, nil} {
		rec := run(enforce)
		if !rec.CoverageEnforced {
			t.Errorf("enforce=%v: CoverageEnforced should be true", enforce)
		}
		if len(rec.CoveragePartitionsAdded) == 0 && len(rec.CoverageFilesAdded) == 0 {
			t.Errorf("enforce=%v: expected coverage augmentation to add the uncovered route", enforce)
		}
	}

	// Disabled: no coverage augmentation applied, but uncovered scope disclosed.
	rec := run(&bFalse)
	if rec.CoverageEnforced {
		t.Error("enforce=false: CoverageEnforced should be false")
	}
	if len(rec.CoveragePartitionsAdded) != 0 {
		t.Errorf("enforce=false: no coverage partitions should be auto-added, got %v", rec.CoveragePartitionsAdded)
	}
	if len(rec.CoverageUncoveredRemaining) == 0 {
		t.Error("enforce=false: uncovered scope must still be disclosed (never manufacture coverage)")
	}
}
