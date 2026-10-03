package engine

import (
	"fmt"
	"sync"

	"vhlocal/internal/agent"
	"vhlocal/internal/pricing"
)

// BudgetAccount is thread-safe cost accounting for a scan (feature 013, FR-021,
// research R6). It accrues real spend from engine-observed token usage using the
// reviewed pricing table, and tracks calls whose backend/model has no reviewed
// price so they are DISCLOSED rather than reported as a false $0 cost. It is safe
// for concurrent hunt units (US3): all mutation is under the mutex.
//
// Honesty (constitution I): local inference (ollama) is a real, priced $0; a paid
// backend/model absent from the table is unpriced and disclosed, never zero-cost,
// and a cap over unpriced traffic is a best-effort bound with disclosure, never a
// promised strict ceiling.
type BudgetAccount struct {
	mu       sync.Mutex
	spent    float64
	priced   bool // true once at least one priced call was accrued
	unpriced int  // count of calls with no reviewed price (paid backend, unknown)
	// lookup resolves a price; nil means the shipped reviewed table. A test may
	// inject a priced lookup so cap enforcement is exercisable offline without
	// putting unverified vendor prices in the shipped table.
	lookup func(backend, model string) (pricing.Price, bool)
}

// Accrue adds the cost of one agent's usage (all its turns + repairs) for the
// given backend/model. It returns the running total spend.
func (a *BudgetAccount) Accrue(backend, model string, u agent.Result) float64 {
	a.mu.Lock()
	defer a.mu.Unlock()
	lookup := a.lookup
	if lookup == nil {
		lookup = pricing.Lookup
	}
	price, known := lookup(backend, model)
	if known {
		a.spent += price.Cost(u.Usage.PromptTokens, u.Usage.CompletionTokens)
		a.priced = true
	} else {
		a.unpriced++
	}
	return a.spent
}

// Spent returns the accrued spend so far.
func (a *BudgetAccount) Spent() float64 {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.spent
}

// Snapshot returns the accrued spend, whether any call was priced, and how many
// calls were unpriced.
func (a *BudgetAccount) Snapshot() (spent float64, priced bool, unpriced int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.spent, a.priced, a.unpriced
}

// budgetDisclosure builds the honest disclosure string for the record from an
// account snapshot and the configured cap. Empty when there is nothing to
// disclose (cap 0 and everything priced).
func budgetDisclosure(cap float64, spent float64, priced bool, unpriced int) string {
	switch {
	case unpriced > 0 && cap > 0:
		return fmt.Sprintf(
			"budget cap $%.2f is best-effort: %d call(s) ran on a backend/model with no reviewed price and are not counted toward the cap — spend is a lower bound, not a strict ceiling",
			cap, unpriced)
	case unpriced > 0:
		return fmt.Sprintf(
			"%d call(s) ran on a backend/model with no reviewed price; their cost is unknown and reported as unpriced, not $0",
			unpriced)
	case cap > 0 && !priced:
		return fmt.Sprintf(
			"budget cap $%.2f could not be applied: no priced calls were made (e.g. local inference is $0)", cap)
	default:
		return ""
	}
}
