package engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"vhlocal/internal/citation"

	"vhlocal/internal/agent"
	"vhlocal/internal/client"
	"vhlocal/internal/inventory"
	"vhlocal/internal/phases"
	"vhlocal/internal/tools"
)

// huntBreakerThreshold is the number of consecutive endpoint failures (with no
// success in between) that trips the circuit breaker, short-circuiting the rest of
// the fan-out with a recorded reason (FR-016). Cancellation is excluded.
const huntBreakerThreshold = 3

// runHunt executes Phase 2 as the reference methodology (feature 005, US2): one
// agent per (partition × vulnerability class) in split mode — INJ/NAV/LOG with the
// shared + per-class prompts — or one combined agent per partition; N repeated
// samples merged by candidate identity with vote provenance; a sink-driven pass;
// and a conditional IaC pass. Completion requires every planned deliverable.
//
// Partitions are resolved upstream (feature 006, US1: resolveHuntPartitions) from
// the model's Phase-1 plan with coverage/threat-model augmentation; runHunt fans
// out over whatever partitions it is handed. A canary preflight and budget cap
// (FR-014) guard the fan-out.

// huntCanaryPrompt is the tiny generation used to confirm the hunt transport
// completes a call before the fan-out.
const huntCanaryPrompt = "Reply with exactly one word: READY. Nothing else."

// huntCanary runs one cheap same-endpoint generation. It returns the transport
// error (if any) for the caller to classify — a KindGeneric (transport) failure
// aborts the hunt; a KindToolParse quirk does not.
func huntCanary(ctx context.Context, p client.Provider, model string) error {
	_, err := p.Chat(ctx, client.ChatRequest{Model: model,
		Messages: []client.Message{{Role: "user", Content: huntCanaryPrompt}}})
	return err
}

func runHunt(ctx context.Context, rec *RunRecord, p client.Provider, sb *tools.Sandbox, spec ScanSpec, skill SkillSource, system string, parts []phases.Partition, emit Emit) bool {
	resultsSub := filepath.Join(spec.ResultsDir, "results")
	_ = os.MkdirAll(resultsSub, 0o755)

	shared, _ := skill.Prompt("phase2_shared.md")
	binder := citation.NewBinder(spec.Repo) // feature 015: citation aids (routes enumerated once)
	base, _ := skill.Prompt("phase2_hunt.md")
	maxTurns := phases.PhasesByKey["2"].MaxTurns
	nSamples := spec.HuntSamples
	if nSamples < 1 {
		nSamples = 1
	}
	if nSamples > 5 {
		nSamples = 5
	}
	split := !strings.EqualFold(spec.Phase2Mode, "combined")

	produced := false
	fails := 0
	var votes []voteEntry
	model := roleModel(spec, "2")

	// group list per mode
	groups := phases.ClassGroups
	if !split {
		groups = []phases.ClassGroup{{Code: "ALL", Blurb: "all vulnerability classes"}}
	}

	// Persist the exact assignments so resume cannot accept a stray file or a
	// partial sample merge as a complete hunt. Only this run's files seed 2b.
	planned := []string{}
	for _, part := range parts {
		for _, g := range groups {
			name := part.Slug() + "_" + strings.ToLower(g.Code)
			planned = append(planned, "results/"+name+".md")
			if nSamples > 1 {
				for i := 1; i <= nSamples; i++ {
					planned = append(planned, fmt.Sprintf("results/%s.s%d.md", name, i))
				}
			}
		}
	}
	planned = append(planned, "results/sink_driven.md")
	if spec.IaCLens && hasIaC(spec.Repo) {
		planned = append(planned, "results/iac.md")
	}
	execution := huntExecution{Files: planned}
	if _, err := writeJSON(filepath.Join(spec.ResultsDir, "hunt_execution.json"), execution); err != nil {
		markPhaseFailed(rec, "2", err)
		return false
	}
	for _, name := range planned {
		if err := os.Remove(filepath.Join(spec.ResultsDir, name)); err != nil && !os.IsNotExist(err) {
			markPhaseFailed(rec, "2", err)
			return false
		}
	}

	brk := func() bool {
		if fails >= huntBreakerThreshold {
			if rec.HuntHaltedReason == "" {
				rec.HuntHaltedReason = "circuit breaker: repeated endpoint failures during hunt"
			}
			return true
		}
		return false
	}

	// Budget cap (FR-014): halt the fan-out once spend reaches the configured USD
	// ceiling, recording budget_halted_reason/hunt_halted_reason. USD accounting is
	// not ported (local Ollama is free), so BudgetSpentUSD stays 0 and the cap is
	// inert for local backends — matching the reference, whose cap likewise does not
	// engage for free backends; the canary + circuit-breaker are the effective
	// controls there. The mechanism is live the moment a pricing layer feeds spend.
	budgetTrip := func() bool {
		if rec.MaxBudgetUSD > 0 && rec.BudgetSpentUSD >= rec.MaxBudgetUSD {
			if rec.BudgetHaltedReason == "" {
				rec.BudgetHaltedReason = fmt.Sprintf(
					"budget cap reached: $%.2f spent of $%.2f cap — halting before further hunt fan-out",
					rec.BudgetSpentUSD, rec.MaxBudgetUSD)
			}
			if rec.HuntHaltedReason == "" {
				rec.HuntHaltedReason = rec.BudgetHaltedReason
			}
			return true
		}
		return false
	}

	// Canary preflight (FR-014): one tiny same-endpoint call before the fan-out, so a
	// broken transport is caught for the cost of one short call instead of draining
	// the whole fleet. Only a transport failure aborts; a non-transport quirk
	// (tool-parse) is not fatal — the fleet may still work.
	if err := huntCanary(ctx, recordPrompts(p, rec.prompts, promptMeta{scanTag: spec.ScanTag, phase: "2", label: "hunt:canary", role: "hunt", model: model, kind: "canary"}), model); err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			rec.Cancelled = true
			return false
		}
		var te *client.TransportError
		if errors.As(err, &te) && te.Kind == client.KindToolParse {
			emit.emit("canary", map[string]any{"ok": true, "model": model, "note": "non-transport quirk; proceeding"})
		} else {
			rec.HuntHaltedReason = "hunt canary failed before fan-out: " + err.Error()
			emit.emit("canary", map[string]any{"ok": false, "model": model})
			return false
		}
	} else {
		emit.emit("canary", map[string]any{"ok": true, "model": model})
	}

	if spec.concurrency() > 1 {
		// Bounded parallel fan-out (feature 013, US3, FR-013/014). Units are
		// (partition × class); each writes its own files. Shared record state is folded
		// deterministically in unit order after the pool drains; budget accrues live and
		// thread-safely so the cap can stop scheduling further units. Cancellation stops
		// new scheduling and preserves completed artifacts. Serial behavior (concurrency
		// <=1) is intentionally left byte-identical below.
		if runHuntParallel(ctx, rec, p, sb, spec, skill, system, shared, base, model, maxTurns, nSamples, split, groups, resultsSub, parts, emit, &fails, &produced, &votes, brk, budgetTrip, binder) {
			return false // cancelled mid-fan-out
		}
	} else {
		for _, part := range parts {
			if ctx.Err() != nil || (brk() || budgetTrip()) {
				break
			}
			slug := part.Slug()
			scope := part.Description
			for _, g := range groups {
				if ctx.Err() != nil || (brk() || budgetTrip()) {
					break
				}
				classPrompt := ""
				if split {
					classPrompt, _ = skill.Prompt(g.PromptFile)
				} else {
					for _, cg := range phases.ClassGroups {
						cp, _ := skill.Prompt(cg.PromptFile)
						classPrompt += cp + "\n\n"
					}
				}
				code := strings.ToLower(g.Code)
				outFile := filepath.Join(resultsSub, slug+"_"+code+".md")
				var samples []string
				for si := 1; si <= nSamples; si++ {
					if ctx.Err() != nil || (brk() || budgetTrip()) {
						break
					}
					sfile := outFile
					if nSamples > 1 {
						sfile = filepath.Join(resultsSub, fmt.Sprintf("%s_%s.s%d.md", slug, code, si))
					}
					label := "hunt:" + slug + ":" + code
					if nSamples > 1 {
						label = fmt.Sprintf("%s.s%d", label, si)
					}
					emit.emit("agent_start", map[string]any{"label": label, "model": model, "partition": part.Ident, "class": g.Code})
					task := buildHuntTask(spec, scope, g, shared, base, classPrompt, sfile, assignedHandlers(rec.routes, part)...)
					cfg := agent.Config{Model: model, NumCtx: spec.NumCtx, MaxTurns: maxTurns,
						Temperature: spec.Temperature, MaxOutputTokens: spec.MaxOutputTokens,
						ReasoningEffort: spec.ReasoningEffort, DeliverablePath: sfile}
					pp := recordPrompts(p, rec.prompts, promptMeta{scanTag: spec.ScanTag, phase: "2", label: label, role: "hunt", model: model})
					res, err := agent.Run(ctx, pp, sb, cfg, system, task)
					recordAgent(rec, "2", model, res)
					rec.Agents[len(rec.Agents)-1].Label = label
					rec.Agents[len(rec.Agents)-1].Partition = part.Ident
					rec.Agents[len(rec.Agents)-1].VulnClass = g.Code
					rec.Agents[len(rec.Agents)-1].Produced = res.Produced
					unitValid := err == nil && deliverableValid(sfile)
					if err == nil { // feature 014 (FR-006/017): the deliverable is validated, not the stop
						if unitValid {
							emit.emit("output_written", map[string]any{"label": label, "path": sfile})
						} else {
							emit.emit("validation_failure", map[string]any{"label": label, "path": sfile, "reason": "agent stopped without a valid deliverable"})
						}
					}
					// Feature 014 (US2): per-unit review evidence — reads + validated deliverable.
					rec.units = append(rec.units, unitEvidence{label: label, partSlug: slug, class: g.Code, sample: si,
						deliverable: sfile, valid: unitValid, stopped: res.StoppedReason, produced: res.Produced, reads: res.Reads, attempts: 1})
					// Feature 015 (FR-025): validate every finding's citation; one bounded
					// correction turn with structured feedback when any is invalid.
					if unitValid {
						cst, cres, stillValid := citationCorrection(ctx, recordPrompts(p, rec.prompts, promptMeta{scanTag: spec.ScanTag, phase: "2", label: label + ".citation", role: "hunt", model: model, kind: "repair"}),
							sb, cfg, system, task, sfile, spec.Repo, rec.GitCommit, binder, func() bool { return ctx.Err() == nil && !brk() && !budgetTrip() })
						u := &rec.units[len(rec.units)-1]
						u.citation = &cst
						if cres != nil {
							recordAgent(rec, "2", model, *cres)
							rec.Agents[len(rec.Agents)-1].Label = label + ".citation"
							rec.Agents[len(rec.Agents)-1].Partition = part.Ident
							rec.Agents[len(rec.Agents)-1].VulnClass = g.Code
							u.attempts++
							u.reads = append(u.reads, cres.Reads...)
							unitValid = stillValid
							u.valid = unitValid
							emit.emit("citation_repair", map[string]any{"label": label, "invalid": cst.Invalid, "repaired": cst.Repaired, "remaining": cst.Remaining})
						}
					}
					// Feature 014 (FR-017, US3): a normal stop without a valid deliverable is a
					// FAILED assignment, not a pass — run ONE bounded re-run (same provider/
					// endpoint, fresh context) under ctx/budget/breaker; if it still fails the
					// exact missing path is recorded and the run stays partial.
					if err == nil && !unitValid && ctx.Err() == nil && !brk() && !budgetTrip() {
						emit.emit("retry", map[string]any{"label": label, "attempt": 2, "reason": "deliverable " + huntFileStatus(sfile) + " after a normal stop"})
						res2, err2 := agent.Run(ctx, pp, sb, cfg, system, task)
						recordAgent(rec, "2", model, res2)
						rec.Agents[len(rec.Agents)-1].Label = label + ".retry1"
						rec.Agents[len(rec.Agents)-1].Partition = part.Ident
						rec.Agents[len(rec.Agents)-1].VulnClass = g.Code
						rec.Agents[len(rec.Agents)-1].Produced = res2.Produced
						if err2 != nil && (errors.Is(err2, context.Canceled) || errors.Is(err2, context.DeadlineExceeded)) {
							rec.Cancelled = true
							return false
						}
						unitValid = err2 == nil && deliverableValid(sfile)
						u := &rec.units[len(rec.units)-1]
						u.attempts, u.valid, u.stopped, u.produced = 2, unitValid, res2.StoppedReason, res2.Produced
						u.reads = append(u.reads, res2.Reads...)
						if unitValid {
							emit.emit("output_written", map[string]any{"label": label + ".retry1", "path": sfile})
						} else {
							emit.emit("validation_failure", map[string]any{"label": label + ".retry1", "path": sfile, "reason": "deliverable still " + huntFileStatus(sfile) + " after 1 bounded re-run — failed assignment"})
						}
						if err2 != nil {
							fails++
							markPhaseFailed(rec, "2", err2)
						}
					}
					pt, ct := usageTiles(rec)
					emit.emit("agent_done", map[string]any{"label": label, "turns": res.Turns, "stopped_reason": res.StoppedReason, "prompt_tokens": pt, "completion_tokens": ct})
					if err != nil {
						if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
							rec.Cancelled = true
							return false
						}
						fails++
						markPhaseFailed(rec, "2", err)
						emit.emit("error", map[string]any{"phase": "2", "partition": part.Ident, "class": g.Code, "message": err.Error()})
						continue
					}
					fails = 0
					if b, e := os.ReadFile(sfile); e == nil {
						samples = append(samples, string(b))
					}
				}
				if nSamples > 1 {
					merged, entries := mergeSamples(samples, slug, code)
					_ = os.WriteFile(outFile, []byte(merged), 0o644)
					votes = append(votes, entries...)
				}
				if deliverableValid(outFile) {
					produced = true
				}
			}
		}
	}

	// Feature 014 (FR-015): record units that never ran (cancel/budget/breaker) so
	// their routes read `skipped` with the real reason, then — with coverage
	// enforcement on — schedule ONE bounded follow-up unit per partition that still has
	// unreviewed entry points. With enforcement off the gaps are still computed and
	// disclosed at finalize (never manufactured coverage).
	recordSkippedUnits(rec, parts, groups, nSamples, ctx, brk, budgetTrip)
	if spec.enforceCoverage() && ctx.Err() == nil && !brk() && !budgetTrip() {
		runFollowUpUnits(ctx, rec, p, sb, spec, skill, system, shared, base, model, resultsSub, maxTurns, parts, emit,
			func() bool { return brk() || budgetTrip() })
	}

	// Sink-driven pass: start from sinks and work backward (reference).
	if ctx.Err() == nil && !brk() && !budgetTrip() {
		sinkOut := filepath.Join(resultsSub, "sink_driven.md")
		task := buildSinkTask(spec, shared, base, sinkOut)
		cfg := agent.Config{Model: model, NumCtx: spec.NumCtx, MaxTurns: maxTurns,
			Temperature: spec.Temperature, MaxOutputTokens: spec.MaxOutputTokens,
			ReasoningEffort: spec.ReasoningEffort, DeliverablePath: sinkOut}
		psink := recordPrompts(p, rec.prompts, promptMeta{scanTag: spec.ScanTag, phase: "2", label: "hunt:sink", role: "hunt", model: model})
		res, err := agent.Run(ctx, psink, sb, cfg, system, task)
		recordAgent(rec, "2", model, res)
		rec.Agents[len(rec.Agents)-1].Label = "hunt:sink"
		rec.Agents[len(rec.Agents)-1].Produced = res.Produced
		// Feature 014 (FR-017): one bounded re-run when the pass stopped normally
		// without a valid deliverable.
		if err == nil && !deliverableValid(sinkOut) && ctx.Err() == nil && !brk() && !budgetTrip() {
			emit.emit("retry", map[string]any{"label": "hunt:sink", "attempt": 2, "reason": "deliverable " + huntFileStatus(sinkOut) + " after a normal stop"})
			res2, err2 := agent.Run(ctx, psink, sb, cfg, system, task)
			recordAgent(rec, "2", model, res2)
			rec.Agents[len(rec.Agents)-1].Label = "hunt:sink.retry1"
			rec.Agents[len(rec.Agents)-1].Produced = res2.Produced
			if err2 != nil {
				err = err2
			}
		}
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				rec.Cancelled = true
				return false
			}
			markPhaseFailed(rec, "2", err)
		} else if deliverableValid(sinkOut) {
			produced = true
		}
	}

	// Conditional IaC pass (only when enabled AND the repo actually has IaC).
	if ctx.Err() == nil && !brk() && !budgetTrip() && spec.IaCLens && hasIaC(spec.Repo) {
		iacPrompt, _ := skill.Prompt("phase2_class_iac.md")
		iacOut := filepath.Join(resultsSub, "iac.md")
		task := buildIaCTask(spec, shared, iacPrompt, iacOut)
		cfg := agent.Config{Model: model, NumCtx: spec.NumCtx, MaxTurns: maxTurns,
			Temperature: spec.Temperature, MaxOutputTokens: spec.MaxOutputTokens,
			ReasoningEffort: spec.ReasoningEffort, DeliverablePath: iacOut}
		piac := recordPrompts(p, rec.prompts, promptMeta{scanTag: spec.ScanTag, phase: "2", label: "hunt:iac", role: "hunt", model: model})
		res, err := agent.Run(ctx, piac, sb, cfg, system, task)
		recordAgent(rec, "2", model, res)
		rec.Agents[len(rec.Agents)-1].Label = "hunt:iac"
		rec.Agents[len(rec.Agents)-1].Produced = res.Produced
		if err == nil && !deliverableValid(iacOut) && ctx.Err() == nil && !brk() && !budgetTrip() { // feature 014 (FR-017)
			emit.emit("retry", map[string]any{"label": "hunt:iac", "attempt": 2, "reason": "deliverable " + huntFileStatus(iacOut) + " after a normal stop"})
			res2, err2 := agent.Run(ctx, piac, sb, cfg, system, task)
			recordAgent(rec, "2", model, res2)
			rec.Agents[len(rec.Agents)-1].Label = "hunt:iac.retry1"
			rec.Agents[len(rec.Agents)-1].Produced = res2.Produced
			if err2 != nil {
				err = err2
			}
		}
		if err == nil && deliverableValid(iacOut) {
			produced = true
		}
	}

	if len(votes) > 0 {
		_, _ = writeJSON(filepath.Join(spec.ResultsDir, "hunt_votes.json"), map[string]any{"entries": votes})
	}
	execution.Complete = produced && ctx.Err() == nil && !brk() && !budgetTrip()
	for _, name := range planned {
		if !deliverableValid(filepath.Join(spec.ResultsDir, name)) {
			execution.Complete = false
		}
	}
	// Feature 014 (FR-017): per-file status so a missing/empty deliverable is named
	// exactly (not re-derived by stat'ing disk) and attributed to its unit/attempts;
	// unplanned files under results/ are reported as misplaced, never deleted.
	execution.Detail = huntDetail(spec.ResultsDir, planned, rec.units)
	if _, err := writeJSON(filepath.Join(spec.ResultsDir, "hunt_execution.json"), execution); err != nil {
		markPhaseFailed(rec, "2", err)
		return false
	}
	return execution.Complete
}

// resolveHuntPartitions resolves the Phase-2 partitions the reference way (US1,
// FR-001/002/003): the model's Phase-1 table → one corrective JSON repartition
// (a bounded same-endpoint fresh-context Chat) → deterministic subsystem fallback,
// then coverage + threat-model augmentation. Records source/fallback/collapsed/
// parse-error + coverage/threat accounting; returns the partitions (ident + routes)
// the hunt dispatches over.
func resolveHuntPartitions(ctx context.Context, rec *RunRecord, p client.Provider, spec ScanSpec, routes []inventory.Route) []phases.Partition {
	text := ""
	if b, err := os.ReadFile(filepath.Join(spec.ResultsDir, "phase1_output.md")); err == nil {
		text = string(b)
	}
	deterministic := func() ([]phases.Partition, bool) {
		subs, _ := inventory.FallbackPartitions(routes, spec.MaxPartitions)
		if len(subs) == 0 {
			return nil, true
		}
		out := make([]phases.Partition, 0, len(subs))
		for i, s := range subs {
			out = append(out, phases.Partition{Ident: fmt.Sprintf("SG-%d", i+1), Description: s + " — " + subsystemRouteDesc(routes, s)})
		}
		return out, len(out) <= 1
	}
	repartition := func(t, hint string) string {
		rp := recordPrompts(p, rec.prompts, promptMeta{scanTag: spec.ScanTag, phase: "2", label: "hunt:repartition", role: "hunt", model: roleModel(spec, "2"), kind: "repartition"})
		resp, err := rp.Chat(ctx, client.ChatRequest{Model: roleModel(spec, "2"),
			Messages: []client.Message{
				{Role: "system", Content: "You partition a codebase for security review. " + hint},
				{Role: "user", Content: "Recon output:\n" + clip(t, 8000) + "\n\nEmit ONLY the JSON array."},
			}, NumCtx: spec.NumCtx, MaxOutputTokens: spec.MaxOutputTokens})
		if err != nil {
			return ""
		}
		return resp.Message.Content
	}
	res := phases.ResolvePartitions(text, spec.MaxPartitions, deterministic, repartition)

	refs := make([]phases.RouteRef, 0, len(routes))
	for _, r := range routes {
		refs = append(refs, phases.RouteRef{File: r.File, Desc: fmt.Sprintf("%s %s (%s:%d)", r.Method, r.Path, r.File, r.Line)})
	}
	// Coverage-driven augmentation is ALWAYS measured; whether it is APPLIED is gated
	// by enforce_coverage (feature 013, FR-012). Threat-model augmentation is a
	// distinct mechanism and is applied regardless.
	aug := phases.AugmentForCoverage(res.Partitions, refs, spec.MaxPartitions)
	enforce := spec.enforceCoverage()

	basisParts := aug.Partitions
	if !enforce {
		// Do not auto-augment: use the model/deterministic partitions as-is, and
		// disclose the scope augmentation WOULD have added as unassigned/unreviewed.
		basisParts = res.Partitions
	}
	finalParts := basisParts
	var tmAdded []string
	if b, err := os.ReadFile(filepath.Join(spec.ResultsDir, "threat_model.md")); err == nil {
		finalParts, tmAdded = phases.AugmentFromThreatModel(basisParts, phases.ParseHuntTargets(string(b)))
	}

	rec.PartitionSource = res.Source
	rec.PartitionFallback = res.Fallback
	rec.PartitionParseError = res.ParseError
	rec.PartitionCollapsed = res.Collapsed
	rec.CoverageEnforced = enforce
	if enforce {
		rec.CoveragePartitionsAdded = append(append([]string{}, aug.Added...), tmAdded...)
		rec.CoverageFilesAdded = aug.AddedFiles
		rec.CoverageUncoveredRemaining = aug.UncoveredRemaining
	} else {
		// Nothing coverage-driven was added; disclose the would-have-added scope plus
		// any still-uncovered scope as unassigned/unreviewed (never manufacture coverage).
		rec.CoveragePartitionsAdded = append([]string{}, tmAdded...)
		rec.CoverageFilesAdded = nil
		rec.CoverageUncoveredRemaining = append(append([]string{}, aug.Added...), aug.UncoveredRemaining...)
	}
	rec.ThreatModelPartitions = tmAdded
	idents := make([]string, 0, len(finalParts))
	for _, pt := range finalParts {
		idents = append(idents, pt.Ident)
	}
	rec.Partitions = idents
	return finalParts
}

// subsystemRouteDesc joins up to 6 route descriptions for a subsystem, so the
// hunt task's assigned scope carries concrete routes (FR-001, C-1d).
func subsystemRouteDesc(routes []inventory.Route, sub string) string {
	var descs []string
	for _, r := range routes {
		if r.Subsystem == sub {
			descs = append(descs, fmt.Sprintf("%s %s (%s:%d)", r.Method, r.Path, r.File, r.Line))
			if len(descs) >= 6 {
				descs = append(descs, "…")
				break
			}
		}
	}
	if len(descs) == 0 {
		return "(subsystem " + sub + ")"
	}
	return strings.Join(descs, "; ")
}

func clip(s string, n int) string {
	if len(s) > n {
		return s[:n] + "\n…(truncated)"
	}
	return s
}

func buildHuntTask(spec ScanSpec, part string, g phases.ClassGroup, shared, base, classPrompt, outFile string, handlers ...string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Assignment: Phase 2 — Hunt (%s)\n", g.Code)
	fmt.Fprintf(&b, "**Target repository (read-only):** %s\n", spec.Repo)
	fmt.Fprintf(&b, "**Results directory (your only writable location):** %s\n", spec.ResultsDir)
	fmt.Fprintf(&b, "**Assigned scope (partition/subsystem):** %s\n", part)
	// Feature 015 (FR-016): the unit's assigned handlers by stable id — the
	// "## Handler dispositions" section must name each one.
	if len(handlers) > 0 {
		fmt.Fprintf(&b, "**Assigned handlers (report a disposition for each; ids are `file:line METHOD PATH`):**\n")
		for _, h := range handlers {
			fmt.Fprintf(&b, "- %s\n", h)
		}
	}
	if g.Code != "ALL" {
		fmt.Fprintf(&b, "**Vulnerability class for THIS pass:** %s — %s. Hunt ONLY this class in the assigned scope.\n\n", g.Code, g.Blurb)
	} else {
		b.WriteString("\n")
	}
	if shared != "" {
		b.WriteString(shared + "\n\n")
	}
	if classPrompt != "" {
		b.WriteString(classPrompt + "\n\n")
	} else {
		b.WriteString(base + "\n\n")
	}
	b.WriteString("---\nWrite your findings to this exact path with the Write tool: " + outFile + "\n")
	return b.String()
}

func buildSinkTask(spec ScanSpec, shared, base, outFile string) string {
	return fmt.Sprintf("# Assignment: Phase 2 — Sink-driven pass\n"+
		"**Target repository (read-only):** %s\n**Results directory (your only writable location):** %s\n"+
		"**Assigned scope:** repository-wide, starting FROM dangerous sinks and tracing BACKWARD to attacker-controlled inputs.\n\n%s\n\n%s\n\n---\n"+
		"Write findings to this exact path with the Write tool: %s\n", spec.Repo, spec.ResultsDir, shared, base, outFile)
}

func buildIaCTask(spec ScanSpec, shared, iacPrompt, outFile string) string {
	return fmt.Sprintf("# Assignment: Phase 2 — Infrastructure-as-Code pass\n"+
		"**Target repository (read-only):** %s\n**Results directory (your only writable location):** %s\n\n%s\n\n%s\n\n---\n"+
		"Write IaC findings to this exact path with the Write tool: %s\n", spec.Repo, spec.ResultsDir, shared, iacPrompt, outFile)
}

var iacGlobs = []string{"*.tf", "*.tf.json", "Dockerfile", "docker-compose.yml", "docker-compose.yaml", "*.dockerfile"}

// hasIaC reports whether the repo contains infrastructure-as-code worth a dedicated
// pass (deterministic, cheap). Mirrors engine.py _has_iac (core patterns).
func hasIaC(repo string) bool {
	found := false
	filepath.WalkDir(repo, func(p string, d os.DirEntry, err error) error {
		if err != nil || found {
			return nil
		}
		if d.IsDir() {
			if tools.SkipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		name := d.Name()
		for _, g := range iacGlobs {
			if ok, _ := filepath.Match(g, name); ok {
				found = true
				return filepath.SkipAll
			}
		}
		if strings.HasPrefix(name, "Dockerfile") {
			found = true
			return filepath.SkipAll
		}
		// .github/workflows/*.yml
		if (strings.HasSuffix(name, ".yml") || strings.HasSuffix(name, ".yaml")) && strings.Contains(filepath.ToSlash(p), "/.github/workflows/") {
			found = true
			return filepath.SkipAll
		}
		return nil
	})
	return found
}

// huntExecution is harness-owned evidence of the assignments actually completed.
type huntExecution struct {
	Files    []string `json:"files"`
	Complete bool     `json:"complete"`
	// Detail is the per-file status (feature 014, FR-017) — additive; the legacy
	// Files list stays so older records and resume keep loading.
	Detail []HuntFile `json:"detail,omitempty"`
}

// HuntFile is one planned deliverable's validated status (feature 014, FR-017).
type HuntFile struct {
	Path     string `json:"path"`
	Status   string `json:"status"` // valid | missing | empty | malformed | misplaced | duplicate
	UnitID   string `json:"unit_id,omitempty"`
	Attempts int    `json:"attempts"`
	// Dispositions (feature 015, T051): how many v2 handler-disposition blocks the
	// unit wrote and how the harness judged them; NoDispositions flags a valid
	// deliverable without the section (v1-style exposure only). Filled at finalize.
	Dispositions   *DispositionCounts `json:"dispositions,omitempty"`
	NoDispositions bool               `json:"no_dispositions,omitempty"`
	// Citation (feature 015, FR-025): validation counts and correction turns.
	Citation *CitationStats `json:"citation,omitempty"`
}

// DispositionCounts tallies one unit's handler dispositions (feature 015).
type DispositionCounts struct {
	Parsed   int `json:"parsed"`
	Credited int `json:"credited"`
	Rejected int `json:"rejected"`
}

// Hunt deliverable statuses (feature 014).
const (
	HuntFileValid     = "valid"
	HuntFileMissing   = "missing"
	HuntFileEmpty     = "empty"
	HuntFileMalformed = "malformed"
	HuntFileMisplaced = "misplaced"
	HuntFileDuplicate = "duplicate"
)

// huntFileStatus classifies one planned deliverable (feature 014, FR-017).
func huntFileStatus(path string) string {
	fi, err := os.Stat(path)
	switch {
	case err != nil:
		return HuntFileMissing
	case fi.IsDir():
		if deliverableValid(path) {
			return HuntFileValid
		}
		return HuntFileEmpty
	case fi.Size() == 0:
		return HuntFileEmpty
	}
	return HuntFileValid
}

// huntDetail builds the per-file status list for hunt_execution.json: every planned
// file with its status, owning unit and attempts, plus any unplanned `.md` under
// results/ reported as misplaced (kept on disk — nothing is deleted to pass).
func huntDetail(resultsDir string, planned []string, units []unitEvidence) []HuntFile {
	byPath := map[string]unitEvidence{}
	for _, u := range units {
		if u.deliverable != "" {
			byPath[u.deliverable] = u
		}
	}
	var out []HuntFile
	plannedSet := map[string]bool{}
	for _, name := range planned {
		plannedSet[name] = true
		full := filepath.Join(resultsDir, name)
		hf := HuntFile{Path: name, Status: huntFileStatus(full), Attempts: 1}
		if u, ok := byPath[full]; ok {
			hf.UnitID, hf.Attempts = u.label, u.attempts
			hf.Citation = u.citation
		}
		out = append(out, hf)
	}
	entries, _ := os.ReadDir(filepath.Join(resultsDir, "results"))
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".md") {
			continue
		}
		rel := "results/" + e.Name()
		if plannedSet[rel] || strings.HasSuffix(e.Name(), "_followup.md") {
			continue
		}
		out = append(out, HuntFile{Path: rel, Status: HuntFileMisplaced})
	}
	return out
}

func loadHuntExecution(root string) (huntExecution, bool) {
	var h huntExecution
	b, err := os.ReadFile(filepath.Join(root, "hunt_execution.json"))
	if err != nil || json.Unmarshal(b, &h) != nil || len(h.Files) == 0 {
		return h, false
	}
	for _, name := range h.Files {
		if filepath.IsAbs(name) || strings.Contains(name, "..") || !strings.HasPrefix(name, "results/") {
			return huntExecution{}, false
		}
	}
	return h, true
}

// annotateHuntExecution copies each unit's disposition tally (feature 015, T051)
// onto hunt_execution.json's detail rows so the per-file record says how many v2
// blocks the unit wrote, how many were credited/rejected, and whether the section
// was missing. Additive; a run without the record is left alone.
func annotateHuntExecution(resultsDir string, ru *ReviewUnits) error {
	if ru == nil {
		return nil
	}
	path := filepath.Join(resultsDir, "hunt_execution.json")
	b, err := os.ReadFile(path)
	if err != nil {
		return nil // no hunt record (phase 2 not run) — nothing to annotate
	}
	var h huntExecution
	if json.Unmarshal(b, &h) != nil || len(h.Detail) == 0 {
		return nil
	}
	byLabel := map[string]ReviewUnitRecord{}
	for _, u := range ru.Units {
		byLabel[u.Label] = u
	}
	changed := false
	for i := range h.Detail {
		u, ok := byLabel[h.Detail[i].UnitID]
		if !ok || !u.Valid {
			continue
		}
		h.Detail[i].Dispositions, h.Detail[i].NoDispositions = u.Dispositions, u.NoDispositions
		changed = true
	}
	if !changed {
		return nil
	}
	_, err = writeJSON(path, h)
	return err
}
