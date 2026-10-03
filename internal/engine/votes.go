package engine

import (
	"crypto/sha1"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// Sample merge (feature 005, FR-015): union candidate blocks across N hunt samples
// of one partition/class, grouping by a STABLE identity (cited location + CWE, not
// a text hash) so the same candidate described in different prose collapses into
// one entry whose `votes` counts the distinct samples that reported it. Mirrors
// engine.py _merge_hunt_samples / _block_identity / votes.location_keys.

var (
	reLocKey   = regexp.MustCompile(`[\w./+\-]+\.[A-Za-z0-9]{1,6}:\d+`)
	reBlockCWE = regexp.MustCompile(`(?i)CWE[-\s]?(\d+)`)
	reWS       = regexp.MustCompile(`\s+`)
	reBlockHd  = regexp.MustCompile(`(?m)^#`)
)

func locationKeys(block string) []string {
	set := map[string]bool{}
	for _, m := range reLocKey.FindAllString(block, -1) {
		set[m] = true
	}
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func blockIdentity(block string) string {
	keys := locationKeys(block)
	cwe := ""
	if m := reBlockCWE.FindStringSubmatch(block); m != nil {
		cwe = m[1]
	}
	if len(keys) > 0 || cwe != "" {
		first := ""
		if len(keys) > 0 {
			first = keys[0]
		}
		return "id:" + first + ":" + cwe
	}
	h := sha1.Sum([]byte(reWS.ReplaceAllString(strings.ToLower(block), " ")))
	return "h:" + fmt.Sprintf("%x", h)
}

type voteEntry struct {
	Keys    []string `json:"keys"`
	Votes   int      `json:"votes"`
	Samples int      `json:"samples"`
}

// splitBlocks splits a hunt output into per-candidate blocks at markdown headers.
func splitBlocks(text string) []string {
	idx := reBlockHd.FindAllStringIndex(text, -1)
	if len(idx) == 0 {
		if strings.TrimSpace(text) == "" {
			return nil
		}
		return []string{text}
	}
	var out []string
	for i, m := range idx {
		end := len(text)
		if i+1 < len(idx) {
			end = idx[i+1][0]
		}
		out = append(out, text[m[0]:end])
	}
	return out
}

// mergeSamples unions the sample texts of one unit, returning the merged markdown
// and the per-candidate vote entries (for hunt_votes.json).
func mergeSamples(texts []string, ident, code string) (string, []voteEntry) {
	var real []string
	for _, t := range texts {
		if strings.TrimSpace(t) != "" && !strings.Contains(t, "Agent produced no output") {
			real = append(real, t)
		}
	}
	if len(real) == 0 {
		return "", nil
	}
	if len(real) == 1 {
		return real[0], nil
	}
	type grp struct {
		order   int
		samples map[int]bool
		text    string
	}
	seen := map[string]*grp{}
	order := 0
	for si, t := range real {
		for _, blk := range splitBlocks(t) {
			b := strings.TrimSpace(blk)
			if b == "" {
				continue
			}
			id := blockIdentity(b)
			if g := seen[id]; g == nil {
				seen[id] = &grp{order: order, samples: map[int]bool{si: true}, text: b}
				order++
			} else {
				g.samples[si] = true
				if len(b) > len(g.text) {
					g.text = b
				}
			}
		}
	}
	groups := make([]*grp, 0, len(seen))
	for _, g := range seen {
		groups = append(groups, g)
	}
	sort.Slice(groups, func(i, j int) bool { return groups[i].order < groups[j].order })
	out := []string{
		fmt.Sprintf("# %s / %s — union of %d hunt samples", ident, code, len(real)),
		"",
		fmt.Sprintf("_Candidates below are the UNION across %d independent samples; `votes` is how many DISTINCT samples reported each (grouped by location + class). Phase 2b remains the false-positive filter._", len(real)),
		"",
	}
	var entries []voteEntry
	for _, g := range groups {
		votes := len(g.samples)
		out = append(out, fmt.Sprintf("<!-- votes: %d/%d -->", votes, len(real)), g.text, "")
		if keys := locationKeys(g.text); len(keys) > 0 {
			entries = append(entries, voteEntry{Keys: keys, Votes: votes, Samples: len(real)})
		}
	}
	return strings.Join(out, "\n") + "\n", entries
}
