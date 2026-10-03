package server

import "testing"

// T005 (FR-031): the list-state classifier distinguishes empty, filtered-empty,
// and ok.
func TestListState(t *testing.T) {
	cases := []struct {
		indexed, total int
		want           string
	}{
		{0, 0, StateEmpty},         // nothing exists
		{5, 0, StateFilteredEmpty}, // items exist, filter removed all
		{5, 3, StateOK},            // some match
	}
	for _, c := range cases {
		if got := ListState(c.indexed, c.total); got != c.want {
			t.Errorf("ListState(%d,%d)=%q want %q", c.indexed, c.total, got, c.want)
		}
	}
}
