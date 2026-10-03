package report

import (
	"strings"
	"testing"

	"vhlocal/internal/consolidate"
)

// Feature 016 US3 (FR-008, C-P11, C-P12, SC-005): the grouping corpus.
//
// The reporting unit is one established defect. These cases cover grouped, ungrouped,
// mixed-status, conflicting-group, repeated-location and distinct-defect-on-one-route
// records. In every case each supported record is accounted for exactly once and every
// original evidence reference survives.

// corpusFinding builds one finding record. status is the recorded verification status.
func corpusFinding(id, title, cwe, family, sev, loc, entry, status string, ev ...Evidence) map[string]any {
	f := map[string]any{
		"id": id, "title": title, "cwe": cwe, "cwe_family": family, "severity": sev,
		"location": loc, "entry_point": entry, "verification_status": status,
	}
	if status == "supported" {
		f["from_confirmed"] = true
	}
	if len(ev) > 0 {
		evs := make([]any, 0, len(ev))
		for _, e := range ev {
			evs = append(evs, map[string]any{
				"path": e.Path, "start_line": float64(e.Start), "end_line": float64(e.End), "quote": e.Quote,
			})
		}
		f["verification_record"] = map[string]any{"evidence": evs}
	}
	return f
}

// corpusGroup builds one recorded group.
func corpusGroup(id, family, status string, memberIDs ...string) Group {
	g := Group{ID: id, Family: family, Status: status, Size: len(memberIDs), DecisionStatus: "undecided"}
	for i, mid := range memberIDs {
		role := "occurrence"
		if i == 0 {
			role = "primary"
		}
		g.Members = append(g.Members, GroupMember{ID: mid, Role: role})
	}
	return g
}

func corpusInput(findings []map[string]any, groups []Group) Input {
	return Input{
		Target: "corpus-app", Model: "m", Host: "h",
		Doc: consolidate.Doc{
			RunStatus: consolidate.RunStatus{ExecutionStatus: "complete", CoverageStatus: "complete", ValidationMode: "static_reasoning"},
			Findings:  findings,
			Counts:    map[string]int{},
		},
		Groups: groups,
	}
}

// T054: every supported record appears exactly once in the primary-issue accounting, and
// every original evidence reference is retained.
func TestGroupingCorpusAccountsForEverySupportedRecordOnce(t *testing.T) {
	cases := []struct {
		name       string
		findings   []map[string]any
		groups     []Group
		wantIssues int
	}{
		{
			name: "grouped: three detections of one defect",
			findings: []map[string]any{
				corpusFinding("C1", "Unsafe pickle", "CWE-502", "deserialization", "High", "a.py:10", "POST /a", "supported", Evidence{Path: "a.py", Start: 9, End: 11, Quote: "pickle.loads(b)"}),
				corpusFinding("C2", "Pickle RCE", "CWE-502", "deserialization", "High+", "a.py:10", "POST /a", "supported", Evidence{Path: "a.py", Start: 8, End: 12, Quote: "data = request.body"}),
				corpusFinding("C3", "Deserialization", "CWE-502", "deserialization", "Medium", "a.py:10", "POST /a", "supported"),
			},
			groups:     []Group{corpusGroup("RG-1", "deserialization", "established", "C1", "C2", "C3")},
			wantIssues: 1,
		},
		{
			name: "ungrouped: two defects with no group at all",
			findings: []map[string]any{
				corpusFinding("C1", "SQL injection", "CWE-89", "sql-injection", "High", "b.py:4", "GET /b", "supported"),
				corpusFinding("C2", "Path traversal", "CWE-22", "path-traversal", "Medium", "c.py:7", "GET /c", "supported"),
			},
			wantIssues: 2,
		},
		{
			name: "mixed status: a group whose members are not all supported",
			findings: []map[string]any{
				corpusFinding("C1", "Unsafe pickle", "CWE-502", "deserialization", "High", "a.py:10", "POST /a", "supported"),
				corpusFinding("C2", "Unsafe pickle", "CWE-502", "deserialization", "High", "a.py:10", "POST /a", "rejected"),
				corpusFinding("C3", "Unsafe pickle", "CWE-502", "deserialization", "High", "a.py:10", "POST /a", "unresolved"),
			},
			groups:     []Group{corpusGroup("RG-1", "deserialization", "established", "C1", "C2", "C3")},
			wantIssues: 1,
		},
		{
			name: "conflicting groups: two groups claim the same detection",
			findings: []map[string]any{
				corpusFinding("C1", "Unsafe pickle", "CWE-502", "deserialization", "High", "a.py:10", "POST /a", "supported"),
				corpusFinding("C2", "Unsafe yaml", "CWE-502", "deserialization", "High", "a.py:20", "POST /a", "supported"),
			},
			groups: []Group{
				corpusGroup("RG-1", "deserialization", "established", "C1", "C2"),
				corpusGroup("RG-2", "deserialization", "established", "C2"),
			},
			wantIssues: 1,
		},
		{
			name: "repeated location: three detections cite one line",
			findings: []map[string]any{
				corpusFinding("C1", "Unsafe pickle", "CWE-502", "deserialization", "High", "a.py:10", "POST /a", "supported"),
				corpusFinding("C2", "Unsafe pickle again", "CWE-502", "deserialization", "High", "a.py:10", "POST /a", "supported"),
				corpusFinding("C3", "Unsafe pickle once more", "CWE-502", "deserialization", "High", "a.py:10", "POST /a", "supported"),
			},
			groups:     []Group{corpusGroup("RG-1", "deserialization", "established", "C1", "C2", "C3")},
			wantIssues: 1,
		},
		{
			name: "distinct defects on one route",
			findings: []map[string]any{
				corpusFinding("C1", "Missing authorization", "CWE-862", "access-control", "High", "d.py:5", "POST /d", "supported"),
				corpusFinding("C2", "Path traversal", "CWE-22", "path-traversal", "High", "d.py:5", "POST /d", "supported"),
			},
			groups: []Group{
				corpusGroup("RG-1", "access-control", "established", "C1"),
				corpusGroup("RG-2", "path-traversal", "established", "C2"),
			},
			wantIssues: 2,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := corpusInput(tc.findings, tc.groups)
			m := BuildModel(in)
			issues := m.Presentation.Issues
			if len(issues) != tc.wantIssues {
				t.Errorf("issues = %d, want %d", len(issues), tc.wantIssues)
			}

			// Exactly once: every supported record is a member of exactly one issue, and no
			// non-supported record is a member of any.
			seen := map[string]int{}
			for _, is := range issues {
				for _, mem := range is.Members {
					seen[mem.FindingID]++
				}
			}
			for _, f := range tc.findings {
				id := str(f["id"])
				if isSupported(f) {
					if seen[id] != 1 {
						t.Errorf("supported %s appears in %d issues, want exactly 1", id, seen[id])
					}
				} else if seen[id] != 0 {
					t.Errorf("%s is not supported but appears in %d issues", id, seen[id])
				}
			}
			// Detection counts sum to the supported records, never more.
			total := 0
			for _, is := range issues {
				total += is.DetectionCount
				if is.DetectionCount != len(is.Members) {
					t.Errorf("%s: detection_count %d but %d members", is.Ref, is.DetectionCount, len(is.Members))
				}
			}
			supported := 0
			for _, f := range tc.findings {
				if isSupported(f) {
					supported++
				}
			}
			if total != supported {
				t.Errorf("detections across issues = %d, supported records = %d", total, supported)
			}

			// Every recorded evidence reference survives into its issue.
			md := renderMarkdownModel(in, m)
			for _, f := range tc.findings {
				if !isSupported(f) {
					continue
				}
				for _, e := range evidenceOf(f) {
					want := e.Path
					if !strings.Contains(md, want) {
						t.Errorf("evidence reference %q from %s was dropped", want, str(f["id"]))
					}
				}
			}
		})
	}
}

// T054: repeated citations of one location are one affected location with a citation count.
func TestRepeatedCitationsDoNotInflateLocationCount(t *testing.T) {
	in := corpusInput([]map[string]any{
		corpusFinding("C1", "Unsafe pickle", "CWE-502", "deserialization", "High", "a.py:10", "POST /a", "supported"),
		corpusFinding("C2", "Unsafe pickle again", "CWE-502", "deserialization", "High", "a.py:10", "POST /a", "supported"),
		corpusFinding("C3", "And once more", "CWE-502", "deserialization", "High", "a.py:10", "POST /a", "supported"),
	}, []Group{corpusGroup("RG-1", "deserialization", "established", "C1", "C2", "C3")})
	m := BuildModel(in)
	if len(m.Presentation.Issues) != 1 {
		t.Fatalf("issues = %d, want 1", len(m.Presentation.Issues))
	}
	is := m.Presentation.Issues[0]
	if len(is.Locations) != 1 {
		t.Fatalf("locations = %d, want 1: %+v", len(is.Locations), is.Locations)
	}
	if is.Locations[0].CitationCount != 3 {
		t.Errorf("citation count = %d, want 3", is.Locations[0].CitationCount)
	}
	if is.DetectionCount != 3 {
		t.Errorf("detection count = %d, want 3", is.DetectionCount)
	}
	md := renderMarkdownModel(in, m)
	if !strings.Contains(md, "cited by 3 detections") {
		t.Error("the document does not say how many detections cited the one location")
	}
}

// T055 (FR-008, C-P12): no merge is inferred from a matching title, weakness category or
// route. Without an established group saying so, two detections stay two issues.
func TestNoMergeIsInferredWithoutAnEstablishedGroup(t *testing.T) {
	// Identical title, identical CWE, identical route, identical file — no group.
	in := corpusInput([]map[string]any{
		corpusFinding("C1", "Unsafe pickle", "CWE-502", "deserialization", "High", "a.py:10", "POST /a", "supported"),
		corpusFinding("C2", "Unsafe pickle", "CWE-502", "deserialization", "High", "a.py:10", "POST /a", "supported"),
	}, nil)
	m := BuildModel(in)
	if n := len(m.Presentation.Issues); n != 2 {
		t.Errorf("issues = %d, want 2: a merge was inferred from matching title, weakness and route", n)
	}

	// A group that is recorded but NOT established merges nothing either.
	in2 := corpusInput([]map[string]any{
		corpusFinding("C1", "Unsafe pickle", "CWE-502", "deserialization", "High", "a.py:10", "POST /a", "supported"),
		corpusFinding("C2", "Unsafe pickle", "CWE-502", "deserialization", "High", "a.py:10", "POST /a", "supported"),
	}, []Group{corpusGroup("RG-1", "deserialization", "suggested", "C1", "C2")})
	m2 := BuildModel(in2)
	if n := len(m2.Presentation.Issues); n != 2 {
		t.Errorf("a suggested group merged %d detections into %d issues", 2, n)
	}
}
