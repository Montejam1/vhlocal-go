package parity

import (
	"fmt"
	"reflect"
	"sort"
	"strings"
)

// Divergence names one dimension where two projections differ (feature 006, US2;
// data-model §Differential result). Detail identifies the candidate/entry.
type Divergence struct {
	Dimension string `json:"dimension"`
	Detail    string `json:"detail"`
	Got       string `json:"got"`
	Want      string `json:"want"`
}

func (d Divergence) String() string {
	return fmt.Sprintf("%s[%s]: got %q want %q", d.Dimension, d.Detail, d.Got, d.Want)
}

// Compare diffs a produced projection (got) against the expected one (want) and
// returns the diverging dimensions/candidates. An empty slice means semantic parity.
// Incidental differences never reach here: projections are already sorted/keyed and
// carry no timestamps, temp paths, or raw candidate IDs (that normalization is the
// projector's job — see Project). Compare is the pure semantic diff.
func Compare(got, want Projection) []Divergence {
	var out []Divergence

	if !reflect.DeepEqual(got.Dispatch, want.Dispatch) {
		out = append(out, Divergence{"dispatch", "units", fmtDispatch(got.Dispatch), fmtDispatch(want.Dispatch)})
	}
	if !reflect.DeepEqual(got.Passes, want.Passes) {
		out = append(out, Divergence{"passes", "set", strings.Join(got.Passes, ","), strings.Join(want.Passes, ",")})
	}

	// Candidates compared by norm_id set.
	gc, wc := candIDs(got.Candidates), candIDs(want.Candidates)
	for id := range wc {
		if !gc[id] {
			out = append(out, Divergence{"candidates", id, "absent", "present"})
		}
	}
	for id := range gc {
		if !wc[id] {
			out = append(out, Divergence{"candidates", id, "present", "absent"})
		}
	}

	out = append(out, diffMap("dispositions", got.Dispositions, want.Dispositions)...)
	out = append(out, diffMap("tiers", got.Tiers, want.Tiers)...)
	out = append(out, diffMap("coverage", got.Coverage, want.Coverage)...)

	if !reflect.DeepEqual(got.Handoffs, want.Handoffs) {
		out = append(out, Divergence{"handoffs", "set", strings.Join(got.Handoffs, ","), strings.Join(want.Handoffs, ",")})
	}
	if !reflect.DeepEqual(got.Artifacts, want.Artifacts) {
		out = append(out, Divergence{"artifacts", "set", strings.Join(got.Artifacts, ","), strings.Join(want.Artifacts, ",")})
	}

	if got.RunStatus.Execution != want.RunStatus.Execution {
		out = append(out, Divergence{"run_status", "execution", got.RunStatus.Execution, want.RunStatus.Execution})
	}
	if got.RunStatus.Coverage != want.RunStatus.Coverage {
		out = append(out, Divergence{"run_status", "coverage", got.RunStatus.Coverage, want.RunStatus.Coverage})
	}
	if got.RunStatus.ValidationMode != want.RunStatus.ValidationMode {
		out = append(out, Divergence{"run_status", "validation_mode", got.RunStatus.ValidationMode, want.RunStatus.ValidationMode})
	}
	return out
}

func diffMap(dim string, got, want map[string]string) []Divergence {
	var out []Divergence
	var keys []string
	for k := range want {
		keys = append(keys, k)
	}
	for k := range got {
		if _, ok := want[k]; !ok {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	for _, k := range keys {
		g, w := got[k], want[k]
		if g != w {
			out = append(out, Divergence{dim, k, valueOr(g), valueOr(w)})
		}
	}
	return out
}

func valueOr(s string) string {
	if s == "" {
		return "(absent)"
	}
	return s
}

func candIDs(cs []ProjCandidate) map[string]bool {
	m := map[string]bool{}
	for _, c := range cs {
		m[c.NormID] = true
	}
	return m
}

func fmtDispatch(d []DispatchUnit) string {
	var parts []string
	for _, u := range d {
		parts = append(parts, u.Partition+"/"+u.Class)
	}
	return strings.Join(parts, ",")
}
