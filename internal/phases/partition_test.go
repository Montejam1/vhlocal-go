package phases

import "testing"

const partTable = `# Phase 1 Reconnaissance

## Subgraph Partitions

| ID | Subsystem | Entry points |
|----|-----------|--------------|
| SG-1 | auth | POST /login, POST /register |
| SG-2 | orders | GET /orders, POST /orders |
| SG-3 | admin | GET /admin/users |

## Next section
(prose that ends the table)
`

// C-1a: a valid Subgraph-Partitions table parses into its partitions.
func TestParsePartitionTable(t *testing.T) {
	parts := ParsePartitionTable(partTable, 8)
	if len(parts) != 3 {
		t.Fatalf("expected 3 partitions, got %d: %+v", len(parts), parts)
	}
	if parts[0].Ident != "SG-1" || parts[1].Ident != "SG-2" || parts[2].Ident != "SG-3" {
		t.Errorf("idents wrong: %+v", parts)
	}
	if parts[0].Description == "" || parts[0].Description == "(no description)" {
		t.Errorf("SG-1 should carry a description, got %q", parts[0].Description)
	}
}

// C-1a: a valid table resolves with source=model_table.
func TestResolvePartitionsModelTable(t *testing.T) {
	res := ResolvePartitions(partTable, 8, nil, nil)
	if res.Source != "model_table" || res.Fallback || len(res.Partitions) != 3 {
		t.Fatalf("model table not used: source=%q fallback=%v n=%d", res.Source, res.Fallback, len(res.Partitions))
	}
}

// C-1b: a malformed table → one corrective JSON repartition (>1 ⇒ model_retry);
// a useless retry → deterministic fallback; recorded parse_error.
func TestResolvePartitionsRetryThenFallback(t *testing.T) {
	malformed := "## Recon\nno partition table here\n"
	retried := false
	repartition := func(text, hint string) string {
		retried = true
		return `[{"id":"SG-1","description":"auth"},{"id":"SG-2","description":"orders"}]`
	}
	res := ResolvePartitions(malformed, 8, nil, repartition)
	if !retried {
		t.Fatal("corrective repartition was not attempted")
	}
	if res.Source != "model_retry" || !res.Fallback || len(res.Partitions) != 2 {
		t.Fatalf("retry not used: source=%q n=%d", res.Source, len(res.Partitions))
	}
	if res.ParseError == "" {
		t.Error("expected a recorded parse_error")
	}

	// A useless retry → deterministic fallback.
	det := func() ([]Partition, bool) {
		return []Partition{{"SG-1", "a"}, {"SG-2", "b"}}, false
	}
	res2 := ResolvePartitions(malformed, 8, det, func(_, _ string) string { return "not json" })
	if res2.Source != "deterministic" || res2.Collapsed {
		t.Fatalf("expected deterministic fallback, got source=%q collapsed=%v", res2.Source, res2.Collapsed)
	}

	// No deterministic structure → single_fallback + collapsed.
	res3 := ResolvePartitions(malformed, 8, func() ([]Partition, bool) { return nil, true }, nil)
	if res3.Source != "single_fallback" || !res3.Collapsed {
		t.Fatalf("expected single_fallback+collapsed, got source=%q collapsed=%v", res3.Source, res3.Collapsed)
	}
}

// C-1c: enumerated route files absent from the plan are appended as coverage
// partitions; over-cap files are recorded as uncovered (never dropped).
func TestAugmentForCoverage(t *testing.T) {
	model := []Partition{{"SG-1", "auth — app/auth.py"}}
	routes := []RouteRef{
		{File: "app/auth.py", Desc: "POST /login (app/auth.py:10)"}, // already covered
		{File: "app/orders.py", Desc: "GET /orders (app/orders.py:5)"},
		{File: "app/admin.py", Desc: "GET /admin (app/admin.py:7)"},
	}
	aug := AugmentForCoverage(model, routes, 8)
	if len(aug.Added) != 2 || len(aug.AddedFiles) != 2 {
		t.Fatalf("expected 2 coverage partitions for the omitted files, got added=%v files=%v", aug.Added, aug.AddedFiles)
	}
	// A tight cap forces over-cap files into uncovered_remaining.
	aug2 := AugmentForCoverage(model, routes, 0) // ceiling = 0 + len(files)=3 → still tight for extras
	capped := AugmentForCoverage([]Partition{{"SG-1", "x"}, {"SG-2", "y"}, {"SG-3", "z"}}, routes, 0)
	_ = aug2
	if len(capped.UncoveredRemaining) == 0 {
		t.Errorf("expected some uncovered_remaining under a tight cap, got %+v", capped)
	}
}
