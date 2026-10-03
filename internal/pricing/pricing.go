// Package pricing holds a small, reviewed table mapping a provider backend and
// model to an approximate token price, used only for best-effort budget
// accounting (feature 013, FR-021 / research R6). It is DATA, not a runtime
// dependency: the standard library only, no network, no external calls.
//
// Honesty contract (constitution I, Evidence Integrity):
//   - Local backends (ollama) are free and PRICED — cost is a real $0.
//   - A paid backend/model present in the table returns its reviewed price.
//   - A paid backend/model NOT in the table returns known=false so the caller
//     discloses the call as unpriced rather than reporting a false $0 cost or a
//     false monetary ceiling.
package pricing

import "strings"

// Price is the USD cost per 1,000 tokens for a backend/model.
type Price struct {
	PromptPer1K     float64
	CompletionPer1K float64
}

// Cost returns the USD cost for a call of the given token counts.
func (p Price) Cost(promptTokens, completionTokens int) float64 {
	return float64(promptTokens)/1000*p.PromptPer1K +
		float64(completionTokens)/1000*p.CompletionPer1K
}

// table is the reviewed price list, keyed by "backend/model" (model lowercased,
// exact match) with a per-backend fallback keyed by "backend/*". Extend this
// only with reviewed figures; each entry is a governance-relevant fact.
var table = map[string]Price{
	// Local inference is free but priced (a real, defensible $0 bound).
	"ollama/*": {PromptPer1K: 0, CompletionPer1K: 0},
}

// Lookup returns the price for a backend/model and whether it is known.
//
//   - ollama (and any explicitly free local backend): {0,0}, true.
//   - a paid backend/model in the table: its price, true.
//   - anything else: zero price, false — the caller MUST treat this as
//     "unpriced" and disclose it, never as a $0 cost (FR-021).
func Lookup(backend, model string) (Price, bool) {
	backend = strings.ToLower(strings.TrimSpace(backend))
	model = strings.ToLower(strings.TrimSpace(model))
	if backend == "" {
		return Price{}, false
	}
	if p, ok := table[backend+"/"+model]; ok {
		return p, true
	}
	if p, ok := table[backend+"/*"]; ok {
		return p, true
	}
	return Price{}, false
}
