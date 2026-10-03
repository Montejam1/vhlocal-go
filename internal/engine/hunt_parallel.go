package engine

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"vhlocal/internal/citation"

	"vhlocal/internal/agent"
	"vhlocal/internal/client"
	"vhlocal/internal/phases"
	"vhlocal/internal/tools"
)

// unitAgent is one agent run captured by a parallel hunt unit, folded into the
// record deterministically after the pool drains.
type unitAgent struct {
	model, label, partIdent, class string
	res                            agent.Result
	// feature 014 (US2/US3): per-sample deliverable, validity and attempts for review evidence
	partSlug, sfile string
	sample          int
	valid           bool
	attempts        int
	citation        *CitationStats
}

// huntUnitResult is the outcome of one (partition × class) unit in the bounded
// parallel fan-out (feature 013, US3). It carries no shared-record mutation so it
// can be produced concurrently and merged in deterministic order.
type huntUnitResult struct {
	agents        []unitAgent
	votes         []voteEntry
	produced      bool
	failedSamples int
	err           error
	cancelled     bool
}

// runHuntParallel runs the (partition × class) hunt units through a bounded
// worker pool sized to spec.concurrency(), then folds results into rec in unit
// order (feature 013, FR-013/014/015). It returns true when cancellation stopped
// the fan-out (the caller then returns not-complete), preserving completed
// artifacts. Never exceeds the concurrency limit. Budget accrues live and
// thread-safely; the cap stops scheduling further units.
func runHuntParallel(
	ctx context.Context, rec *RunRecord, p client.Provider, sb *tools.Sandbox,
	spec ScanSpec, skill SkillSource, system, shared, base, model string,
	maxTurns, nSamples int, split bool, groups []phases.ClassGroup, resultsSub string,
	parts []phases.Partition, emit Emit,
	fails *int, produced *bool, votes *[]voteEntry,
	brk, budgetTrip func() bool, binder *citation.Binder,
) (cancelled bool) {
	if rec.budget == nil {
		rec.budget = &BudgetAccount{}
	}
	limit := spec.concurrency()

	type unit struct {
		part phases.Partition
		g    phases.ClassGroup
	}
	var units []unit
	for _, part := range parts {
		for _, g := range groups {
			units = append(units, unit{part, g})
		}
	}

	var emitMu sync.Mutex
	safeEmit := func(event string, payload map[string]any) {
		emitMu.Lock()
		emit.emit(event, payload)
		emitMu.Unlock()
	}

	// runUnit executes one (partition × class) unit: all its samples, writing its
	// own files. It touches no shared record state except the thread-safe budget
	// account; everything else is returned for ordered folding.
	runUnit := func(u unit) huntUnitResult {
		var ur huntUnitResult
		slug := u.part.Slug()
		scope := u.part.Description
		classPrompt := ""
		if split {
			classPrompt, _ = skill.Prompt(u.g.PromptFile)
		} else {
			for _, cg := range phases.ClassGroups {
				cp, _ := skill.Prompt(cg.PromptFile)
				classPrompt += cp + "\n\n"
			}
		}
		code := strings.ToLower(u.g.Code)
		outFile := filepath.Join(resultsSub, slug+"_"+code+".md")
		var samples []string
		for si := 1; si <= nSamples; si++ {
			if ctx.Err() != nil {
				ur.cancelled = true
				return ur
			}
			sfile := outFile
			if nSamples > 1 {
				sfile = filepath.Join(resultsSub, fmt.Sprintf("%s_%s.s%d.md", slug, code, si))
			}
			label := "hunt:" + slug + ":" + code
			if nSamples > 1 {
				label = fmt.Sprintf("%s.s%d", label, si)
			}
			safeEmit("agent_start", map[string]any{"label": label, "model": model, "partition": u.part.Ident, "class": u.g.Code})
			task := buildHuntTask(spec, scope, u.g, shared, base, classPrompt, sfile, assignedHandlers(rec.routes, u.part)...)
			cfg := agent.Config{Model: model, NumCtx: spec.NumCtx, MaxTurns: maxTurns,
				Temperature: spec.Temperature, MaxOutputTokens: spec.MaxOutputTokens,
				ReasoningEffort: spec.ReasoningEffort, DeliverablePath: sfile}
			pp := recordPrompts(p, rec.prompts, promptMeta{scanTag: spec.ScanTag, phase: "2", label: label, role: "hunt", model: model})
			res, err := agent.Run(ctx, pp, sb, cfg, system, task)
			if err == nil { // feature 014 (FR-006/017): validated deliverable, not the stop
				if deliverableValid(sfile) {
					safeEmit("output_written", map[string]any{"label": label, "path": sfile})
				} else {
					safeEmit("validation_failure", map[string]any{"label": label, "path": sfile, "reason": "agent stopped without a valid deliverable"})
				}
			}
			// Live, thread-safe budget accrual so the cap can gate later scheduling.
			rec.budget.Accrue(rec.Backend, model, res)
			valid := err == nil && deliverableValid(sfile)
			attempts := 1
			var cstats *CitationStats
			if valid {
				cst, cres, stillValid := citationCorrection(ctx, recordPrompts(p, rec.prompts, promptMeta{scanTag: spec.ScanTag, phase: "2", label: label + ".citation", role: "hunt", model: model, kind: "repair"}),
					sb, cfg, system, task, sfile, spec.Repo, rec.GitCommit, binder, func() bool { return ctx.Err() == nil && !budgetTrip() })
				cstats = &cst
				if cres != nil {
					rec.budget.Accrue(rec.Backend, model, *cres)
					attempts++
					res.Reads = append(res.Reads, cres.Reads...)
					res.Turns += cres.Turns
					res.Usage.PromptTokens += cres.Usage.PromptTokens
					res.Usage.CompletionTokens += cres.Usage.CompletionTokens
					valid = stillValid
					safeEmit("citation_repair", map[string]any{"label": label, "invalid": cst.Invalid, "repaired": cst.Repaired, "remaining": cst.Remaining})
				}
			}
			// Feature 014 (FR-017): one bounded re-run of a unit that stopped normally
			// without a valid deliverable (same provider/endpoint), under ctx/budget.
			if err == nil && !valid && ctx.Err() == nil && !budgetTrip() {
				safeEmit("retry", map[string]any{"label": label, "attempt": 2, "reason": "deliverable " + huntFileStatus(sfile) + " after a normal stop"})
				res2, err2 := agent.Run(ctx, pp, sb, cfg, system, task)
				rec.budget.Accrue(rec.Backend, model, res2)
				attempts = 2
				if err2 != nil && (errors.Is(err2, context.Canceled) || errors.Is(err2, context.DeadlineExceeded)) {
					ur.cancelled = true
					return ur
				}
				valid = err2 == nil && deliverableValid(sfile)
				res.Reads = append(res.Reads, res2.Reads...)
				res.StoppedReason, res.Produced = res2.StoppedReason, res2.Produced
				res.Turns += res2.Turns
				res.Usage.PromptTokens += res2.Usage.PromptTokens
				res.Usage.CompletionTokens += res2.Usage.CompletionTokens
				if err2 != nil {
					ur.failedSamples++
					ur.err = err2
				}
			}
			ur.agents = append(ur.agents, unitAgent{model: model, label: label, partIdent: u.part.Ident, class: u.g.Code, res: res,
				partSlug: slug, sfile: sfile, sample: si, valid: valid, attempts: attempts, citation: cstats})
			safeEmit("agent_done", map[string]any{"label": label, "turns": res.Turns, "stopped_reason": res.StoppedReason})
			if err != nil {
				if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
					ur.cancelled = true
					return ur
				}
				ur.failedSamples++
				ur.err = err
				continue
			}
			if b, e := os.ReadFile(sfile); e == nil {
				samples = append(samples, string(b))
			}
		}
		if nSamples > 1 {
			merged, entries := mergeSamples(samples, slug, code)
			_ = os.WriteFile(outFile, []byte(merged), 0o644)
			ur.votes = entries
		}
		if deliverableValid(outFile) {
			ur.produced = true
		}
		return ur
	}

	results := make([]*huntUnitResult, len(units))
	sem := make(chan struct{}, limit)
	var wg sync.WaitGroup
	for i, u := range units {
		// Stop SCHEDULING new units on cancellation or an already-tripped budget
		// (breaker failures are only known after folding; budget accrues live).
		if ctx.Err() != nil || budgetTrip() {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, u unit) {
			defer wg.Done()
			defer func() { <-sem }()
			r := runUnit(u)
			results[i] = &r
		}(i, u)
	}
	wg.Wait()

	// Fold results in deterministic unit order (FR-014).
	for _, r := range results {
		if r == nil {
			continue // unit never scheduled (cancel/budget stop)
		}
		if r.cancelled {
			rec.Cancelled = true
			cancelled = true
		}
		for _, a := range r.agents {
			appendAgent(rec, "2", a.model, a.res)
			rec.Agents[len(rec.Agents)-1].Label = a.label
			rec.Agents[len(rec.Agents)-1].Partition = a.partIdent
			rec.Agents[len(rec.Agents)-1].VulnClass = a.class
			rec.Agents[len(rec.Agents)-1].Produced = a.res.Produced
			// Feature 014 (US2): fold per-unit review evidence in deterministic order.
			rec.units = append(rec.units, unitEvidence{label: a.label, partSlug: a.partSlug, class: a.class, sample: a.sample,
				deliverable: a.sfile, valid: a.valid, stopped: a.res.StoppedReason, produced: a.res.Produced, reads: a.res.Reads, attempts: max(1, a.attempts), citation: a.citation})
		}
		if r.failedSamples > 0 {
			*fails += r.failedSamples
			if r.err != nil {
				markPhaseFailed(rec, "2", r.err)
			}
		}
		*votes = append(*votes, r.votes...)
		if r.produced {
			*produced = true
		}
	}
	syncBudgetSnapshot(rec)
	_ = brk // breaker is evaluated by the caller after this returns (fails updated)
	return cancelled
}
