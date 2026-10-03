package engine

import (
	"testing"

	"vhlocal/internal/agent"
	"vhlocal/internal/pricing"
)

// res builds an agent.Result with the given token usage.
func res(pt, ct int) agent.Result {
	var r agent.Result
	r.Usage.PromptTokens = pt
	r.Usage.CompletionTokens = ct
	return r
}

func TestBudgetLocalIsPricedZero(t *testing.T) {
	a := &BudgetAccount{}
	a.Accrue("ollama", "gpt-oss:120b", res(10000, 5000))
	spent, priced, unpriced := a.Snapshot()
	if spent != 0 || !priced || unpriced != 0 {
		t.Errorf("local should be priced $0: spent=%v priced=%v unpriced=%v", spent, priced, unpriced)
	}
}

func TestBudgetUnknownPaidIsDisclosedNotZero(t *testing.T) {
	a := &BudgetAccount{}
	a.Accrue("openai", "unreviewed", res(1000, 1000))
	spent, priced, unpriced := a.Snapshot()
	if spent != 0 || priced || unpriced != 1 {
		t.Errorf("unknown paid call must be unpriced (disclosed), not $0 cost: spent=%v priced=%v unpriced=%v", spent, priced, unpriced)
	}
	if d := budgetDisclosure(0, spent, priced, unpriced); d == "" {
		t.Error("an unpriced call must produce a disclosure string")
	}
}

func TestBudgetPricedAccrualAndCap(t *testing.T) {
	// Inject a priced lookup so real accrual + cap logic is exercisable offline.
	a := &BudgetAccount{lookup: func(_, _ string) (pricing.Price, bool) {
		return pricing.Price{PromptPer1K: 0.01, CompletionPer1K: 0.02}, true
	}}
	a.Accrue("openai", "m", res(1000, 1000)) // 0.01 + 0.02 = 0.03
	a.Accrue("openai", "m", res(1000, 0))    // +0.01 = 0.04
	spent, priced, unpriced := a.Snapshot()
	if priced != true || unpriced != 0 {
		t.Errorf("priced calls: priced=%v unpriced=%v", priced, unpriced)
	}
	if spent < 0.0399 || spent > 0.0401 {
		t.Errorf("spent = %v, want ~0.04", spent)
	}
	// Best-effort disclosure when cap is set but some calls unpriced is separate;
	// here everything is priced so no disclosure needed.
	if d := budgetDisclosure(1.0, spent, priced, unpriced); d != "" {
		t.Errorf("fully-priced spend under cap should not disclose: %q", d)
	}
}

func TestBudgetDisclosureBranches(t *testing.T) {
	if budgetDisclosure(5, 0, false, 2) == "" {
		t.Error("cap + unpriced calls must disclose best-effort")
	}
	if budgetDisclosure(0, 0, false, 1) == "" {
		t.Error("unpriced without cap must disclose unknown cost")
	}
	if budgetDisclosure(5, 0, false, 0) == "" {
		t.Error("cap but no priced calls must disclose non-application")
	}
	if budgetDisclosure(0, 0, true, 0) != "" {
		t.Error("all priced, no cap: nothing to disclose")
	}
}
