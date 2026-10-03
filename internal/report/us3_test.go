package report

import (
	"strings"
	"testing"

	"vhlocal/internal/consolidate"
)

func inputWith(status consolidate.RunStatus, agents []any) Input {
	doc := consolidate.Doc{
		RunStatus: status,
		Counts:    map[string]int{},
		Meta:      map[string]any{"agents": agents},
		Findings:  []map[string]any{},
	}
	return Input{Target: "app", Model: "m", Host: "h", Doc: doc}
}

func agentRow(phase, label, stop string, turns, pt, ct int) any {
	return map[string]any{
		"phase": phase, "label": label, "stopped_reason": stop,
		"turns": float64(turns), "prompt_tokens": float64(pt), "completion_tokens": float64(ct),
	}
}

// C-R1: per-phase outcome table present (Markdown + HTML), with tokens.
func TestPerPhaseTablePresent(t *testing.T) {
	agents := []any{
		agentRow("1", "1", "complete", 5, 1000, 200),
		agentRow("2", "hunt:backend", "max_turns", 80, 50000, 1200),
	}
	in := inputWith(consolidate.RunStatus{ExecutionStatus: "complete"}, agents)
	md := RenderMarkdown(in)
	if !strings.Contains(md, "## Per-phase outcome") || !strings.Contains(md, "hunt:backend") || !strings.Contains(md, "max_turns") {
		t.Errorf("markdown per-phase table missing content:\n%s", md)
	}
	h := RenderHTML(in)
	if !strings.Contains(h, "Per-phase outcome") || !strings.Contains(h, "hunt:backend") || !strings.Contains(h, "50000") {
		t.Errorf("HTML per-phase table missing content")
	}
}

// C-R2 / feature 016 T036: an unreliable run is still flagged prominently, and a clean
// run is still not flagged. The wording changed: the feature-015 banner presented a
// candidate total as findings ("64 finding(s) were produced") and led with phase
// troubleshooting, which FR-003 and SC-002 remove from the opening. The guarantee — an
// empty or partial result is never mistaken for a clean target, and the degradation reasons
// stay available — is unchanged, and the reasons now live in Scan details.
func TestBrokenRunBanner(t *testing.T) {
	broken := inputWith(consolidate.RunStatus{
		ExecutionStatus:         "partial",
		CoverageStatus:          "degraded",
		CoverageDegradedReasons: []string{"recon produced no attack-surface map", "hunt produced no candidates"},
	}, []any{agentRow("1", "1", "tool_repair", 2, 100, 10)})

	md := RenderMarkdown(broken)
	if !strings.Contains(md, "This assessment is not exhaustive") {
		t.Errorf("markdown missing the incomplete-run note:\n%s", md)
	}
	// No candidate total presented as findings, and no phase troubleshooting in the opening.
	opening := md[:strings.Index(md, hdrIssues)]
	for _, bad := range []string{"finding(s) were produced", "requested phases completed"} {
		if strings.Contains(opening, bad) {
			t.Errorf("the opening still carries %q", bad)
		}
	}
	// The run is not presented as a clean target, and the reasons remain available.
	if !strings.Contains(md, "recon produced no attack-surface map") {
		t.Errorf("markdown lost a degradation reason")
	}
	if i := strings.Index(md, "recon produced no attack-surface map"); i < strings.Index(md, hdrScanDetail) {
		t.Error("degradation reasons belong to Scan details, not to the opening")
	}
	h := RenderHTML(broken)
	if !strings.Contains(h, "This assessment is not exhaustive") || !strings.Contains(h, "class=\"broken\"") {
		t.Errorf("HTML missing the incomplete-run note")
	}

	// Clean run: complete, no degraded reasons, coverage not recorded → NO note.
	clean := inputWith(consolidate.RunStatus{ExecutionStatus: "complete"}, []any{agentRow("1", "1", "complete", 5, 100, 10)})
	if strings.Contains(RenderMarkdown(clean), "This assessment is not exhaustive") {
		t.Error("a complete run must NOT show the incomplete-run note (markdown)")
	}
	if strings.Contains(RenderHTML(clean), "class=\"broken\"") {
		t.Error("a complete run must NOT show the incomplete-run note (HTML)")
	}
}
