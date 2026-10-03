package server

// Response-state conventions for the analyst workspace (feature 010, API-X1,
// FR-031/032). Loading / refreshing / stale / disconnected are per-viewer client
// states; the server's contribution is to make three server-observable states
// unambiguous in the payload:
//
//   - a list response distinguishes "empty" (nothing exists) from
//     "filtered_empty" (items exist but the active filter removed them all) and
//     "ok";
//   - a failed detail/refresh/mutation is an explicit error object (via writeErr),
//     never an empty success — so the client can leave a loading/retry affordance,
//     preserve prior data as stale, and never render a failed mutation as saved.
const (
	StateOK            = "ok"
	StateEmpty         = "empty"
	StateFilteredEmpty = "filtered_empty"
)

// ListState classifies a list response from the total items that exist (indexed)
// and the count after filtering (total).
func ListState(indexed, total int) string {
	switch {
	case indexed == 0:
		return StateEmpty
	case total == 0:
		return StateFilteredEmpty
	default:
		return StateOK
	}
}
