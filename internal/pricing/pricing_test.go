package pricing

import "testing"

func TestLookupLocalIsFreeButPriced(t *testing.T) {
	p, known := Lookup("ollama", "gpt-oss:120b")
	if !known {
		t.Fatal("local ollama must be priced (a real $0), not unknown")
	}
	if p.Cost(10000, 10000) != 0 {
		t.Errorf("local inference must cost $0, got %v", p.Cost(10000, 10000))
	}
}

func TestLookupUnknownPaidIsUnpriced(t *testing.T) {
	// A paid backend/model absent from the reviewed table must be reported as
	// unpriced (known=false), never as $0 (FR-021).
	if _, known := Lookup("openai", "some-unreviewed-model"); known {
		t.Error("an unreviewed paid model must be unpriced, not silently $0")
	}
	if _, known := Lookup("openrouter", "x/y"); known {
		t.Error("an unreviewed openrouter model must be unpriced")
	}
}

func TestCostMath(t *testing.T) {
	p := Price{PromptPer1K: 0.001, CompletionPer1K: 0.002}
	if got := p.Cost(1000, 1000); got != 0.003 {
		t.Errorf("Cost(1000,1000) = %v, want 0.003", got)
	}
	if got := p.Cost(0, 0); got != 0 {
		t.Errorf("Cost(0,0) = %v, want 0", got)
	}
}

func TestLookupEmptyBackend(t *testing.T) {
	if _, known := Lookup("", "m"); known {
		t.Error("empty backend must be unknown")
	}
}
