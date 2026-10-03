package phases

import (
	"encoding/json"
	"regexp"
	"strings"
)

// Partition is one Phase-2 hunt unit (parity with the reference Partition):
// an SG-N identifier and a description carrying the subsystem + concrete routes.
type Partition struct {
	Ident       string
	Description string
}

// Slug is the filesystem-safe form used in results/<slug>_<class>.md.
func (p Partition) Slug() string {
	return strings.ReplaceAll(strings.ToLower(strings.TrimSpace(p.Ident)), " ", "-")
}

// PartitionResolution records HOW the Phase-2 partitions were obtained, so a
// degraded run cannot masquerade as a thorough one (parity with the reference).
type PartitionResolution struct {
	Partitions []Partition
	Source     string // model_table | model_retry | deterministic | single_fallback
	Fallback   bool   // the model's own table was unusable
	ParseError string // why the table failed ("" when it parsed)
	Collapsed  bool   // degenerated to a single whole-repo partition
}

// CoverageAugmentation is the result of forcing every enumerated route file into
// some partition.
type CoverageAugmentation struct {
	Partitions         []Partition
	Added              []string // idents of appended coverage partitions
	AddedFiles         []string // source files those partitions bring in
	UncoveredRemaining []string // files still uncovered (hit the cap)
}

// RouteRef is one enumerated route, passed in so this package need not import
// inventory (avoids an import cycle).
type RouteRef struct {
	File string
	Desc string // e.g. "GET /api/x (file:line)"
}

// PartitionJSONSchemaHint is the corrective-retry contract asked of the model.
const PartitionJSONSchemaHint = `Output ONLY a JSON array, no prose. Each element: ` +
	`{"id": "SG-N", "description": "<subsystem or entry points>"}. Group entry points that ` +
	`share application code into the same partition; aim for one partition per security-relevant ` +
	`subsystem (auth, authorization, file/upload/webhook, config/secrets, operations/admin, core).`

var (
	rePartitionHeading = regexp.MustCompile(`(?i)subgraph[\s\-]*partition`)
	reSGID             = regexp.MustCompile(`(?i)\bSG[\s\-]?(\d+)`)
	reJSONArray        = regexp.MustCompile(`(?s)\[.*\]`)
)

// ParsePartitionTable parses the model's "Subgraph Partitions" markdown table.
// Tolerant of malformed markdown (find the heading, take `|`-rows, pull an SG-N id
// + a 1–3-cell description). Returns nil when nothing parses (the caller decides
// what empty means). Parity with the reference `_parse_partition_table_text`.
func ParsePartitionTable(text string, max int) []Partition {
	text = NormalizeText(text)
	section := text
	if loc := rePartitionHeading.FindStringIndex(text); loc != nil {
		section = text[loc[1]:]
	}
	var out []Partition
	seen := map[string]bool{}
	for _, line := range strings.Split(section, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "|") {
			if len(out) > 0 && line == "" {
				continue
			}
			if len(out) > 0 {
				break // table ended
			}
			continue
		}
		cells := splitCells(line)
		if len(cells) == 0 || allSep(cells) {
			continue
		}
		idm := reSGID.FindStringSubmatch(cells[0])
		if idm == nil {
			continue
		}
		ident := "SG-" + idm[1]
		if seen[ident] {
			continue
		}
		seen[ident] = true
		desc := joinNonEmpty(cells[1:], 3, " | ")
		if desc == "" {
			desc = "(no description)"
		}
		out = append(out, Partition{Ident: ident, Description: desc})
	}
	if max > 0 && len(out) > max {
		out = out[:max]
	}
	return out
}

// ParsePartitionJSON parses the structured corrective-retry contract (a JSON array),
// tolerating prose/fence wrapping. Returns nil on any failure.
func ParsePartitionJSON(text string, max int) []Partition {
	m := reJSONArray.FindString(text)
	if m == "" {
		return nil
	}
	var data []map[string]any
	if json.Unmarshal([]byte(m), &data) != nil {
		return nil
	}
	var out []Partition
	seen := map[string]bool{}
	for i, item := range data {
		ident := strings.TrimSpace(firstString(item, "id", "ident"))
		if idm := reSGID.FindStringSubmatch(ident); idm != nil {
			ident = "SG-" + idm[1]
		} else {
			ident = "SG-" + itoa(i+1)
		}
		if seen[ident] {
			continue
		}
		seen[ident] = true
		desc := strings.TrimSpace(firstString(item, "description", "desc"))
		if desc == "" {
			desc = "(no description)"
		}
		out = append(out, Partition{Ident: ident, Description: desc})
	}
	if max > 0 && len(out) > max {
		out = out[:max]
	}
	return out
}

// ResolvePartitions: model table → one corrective JSON repartition → deterministic
// subsystem fallback → single whole-repo. `deterministic` returns the fallback
// partitions and whether they collapsed to whole-repo; `repartition` (may be nil)
// performs one fresh-context corrective retry. Parity with the reference
// `resolve_partitions`.
func ResolvePartitions(phase1Text string, max int, deterministic func() ([]Partition, bool), repartition func(text, hint string) string) PartitionResolution {
	if parts := ParsePartitionTable(phase1Text, max); len(parts) > 0 {
		return PartitionResolution{Partitions: parts, Source: "model_table"}
	}
	parseErr := "no parseable Subgraph Partitions table"
	if strings.TrimSpace(phase1Text) == "" {
		parseErr = "phase1 output missing"
	}
	if repartition != nil && strings.TrimSpace(phase1Text) != "" {
		if rp := ParsePartitionJSON(repartition(phase1Text, PartitionJSONSchemaHint), max); len(rp) > 1 {
			return PartitionResolution{Partitions: rp, Source: "model_retry", Fallback: true, ParseError: parseErr}
		}
	}
	var det []Partition
	collapsed := true
	if deterministic != nil {
		det, collapsed = deterministic()
	}
	if len(det) == 0 {
		det = []Partition{{Ident: "SG-1", Description: "entire repository"}}
		collapsed = true
	}
	src := "deterministic"
	if collapsed {
		src = "single_fallback"
	}
	return PartitionResolution{Partitions: det, Source: src, Fallback: true, ParseError: parseErr, Collapsed: collapsed}
}

// AugmentForCoverage appends a coverage partition for every enumerated route file
// absent from the model partition descriptions, so no enumerated route goes
// unhunted (the "36 of 100 entry points not reviewed" gap). Over-cap files are
// recorded as uncovered, never dropped. Parity with the reference
// `augment_partitions_for_coverage`.
func AugmentForCoverage(model []Partition, routes []RouteRef, max int) CoverageAugmentation {
	// Files already named in the model plan's descriptions.
	covered := map[string]bool{}
	descs := strings.ToLower(joinDescriptions(model))
	byFile := map[string][]string{}
	var order []string
	for _, r := range routes {
		if r.File == "" {
			continue
		}
		if _, ok := byFile[r.File]; !ok {
			order = append(order, r.File)
		}
		byFile[r.File] = append(byFile[r.File], r.Desc)
		if strings.Contains(descs, strings.ToLower(r.File)) {
			covered[r.File] = true
		}
	}
	aug := CoverageAugmentation{Partitions: append([]Partition{}, model...)}
	next := maxSGNumber(model) + 1
	ceiling := max + len(order) // hard ceiling like the reference
	for _, file := range order {
		if covered[file] {
			continue
		}
		if len(aug.Partitions) >= ceiling {
			aug.UncoveredRemaining = append(aug.UncoveredRemaining, file)
			continue
		}
		ident := "SG-" + itoa(next)
		next++
		desc := "coverage: " + file + " — " + strings.Join(byFile[file], "; ")
		aug.Partitions = append(aug.Partitions, Partition{Ident: ident, Description: desc})
		aug.Added = append(aug.Added, ident)
		aug.AddedFiles = append(aug.AddedFiles, file)
	}
	return aug
}

// AugmentFromThreatModel appends one additive partition per PASTA hunt target whose
// subsystem/paths are not already covered by the plan. Parity with the reference
// `augment_partitions_from_threat_model` (best-effort).
func AugmentFromThreatModel(partitions []Partition, targets []HuntTarget) ([]Partition, []string) {
	out := append([]Partition{}, partitions...)
	var added []string
	descs := strings.ToLower(joinDescriptions(partitions))
	next := maxSGNumber(out) + 1
	for _, t := range targets {
		key := strings.ToLower(t.Subsystem + " " + strings.Join(t.Paths, " "))
		if strings.TrimSpace(key) == "" {
			continue
		}
		covered := t.Subsystem != "" && strings.Contains(descs, strings.ToLower(t.Subsystem))
		for _, p := range t.Paths {
			if p != "" && strings.Contains(descs, strings.ToLower(p)) {
				covered = true
			}
		}
		if covered {
			continue
		}
		ident := "SG-" + itoa(next)
		next++
		desc := "threat-model: " + t.Subsystem + " — " + t.Threat + " (" + strings.Join(t.Paths, ", ") + ")"
		out = append(out, Partition{Ident: ident, Description: desc})
		added = append(added, ident)
		descs += " " + strings.ToLower(desc)
	}
	return out, added
}

// --- helpers ---

func splitCells(line string) []string {
	line = strings.Trim(line, "|")
	parts := strings.Split(line, "|")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		out = append(out, strings.TrimSpace(p))
	}
	return out
}

func allSep(cells []string) bool {
	for _, c := range cells {
		if strings.Trim(c, "-: ") != "" {
			return false
		}
	}
	return true
}

func joinNonEmpty(cells []string, limit int, sep string) string {
	var out []string
	for i, c := range cells {
		if i >= limit {
			break
		}
		if c != "" {
			out = append(out, c)
		}
	}
	return strings.Join(out, sep)
}

func joinDescriptions(ps []Partition) string {
	var b strings.Builder
	for _, p := range ps {
		b.WriteString(p.Description)
		b.WriteByte('\n')
	}
	return b.String()
}

func maxSGNumber(ps []Partition) int {
	n := 0
	for _, p := range ps {
		if m := reSGID.FindStringSubmatch(p.Ident); m != nil {
			if v := atoiN(m[1]); v > n {
				n = v
			}
		}
	}
	return n
}

func firstString(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if v, ok := m[k].(string); ok {
			return v
		}
	}
	return ""
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

func atoiN(s string) int {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			break
		}
		n = n*10 + int(c-'0')
	}
	return n
}
