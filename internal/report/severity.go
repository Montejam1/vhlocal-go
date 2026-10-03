package report

import (
	"sort"
	"strings"
)

// Feature 016 (FR-009, C-P13): the severity PRESENTATION mapping.
//
// This is a display decision, not a reassessment. The recorded rating is never
// changed and never discarded: `High+` shows as High with its original rating kept in
// the issue's OriginalSeverities, an unrecognized label shows as Unrated with its
// original value kept, and a missing rating is never guessed into a plausible tier.
// Nothing here derives a CVSS score, a vendor score, an exploitation likelihood or a
// business-risk score, because the record contains none (C-P14).

// The displayed severity categories, in descending order of seriousness.
const (
	SevCritical      = "Critical"
	SevHigh          = "High"
	SevMedium        = "Medium"
	SevLow           = "Low"
	SevInformational = "Informational"
	SevUnrated       = "Unrated"
)

// DisplaySeverities lists the categories in display order. A severity chart shows
// exactly these, so a reader never meets an internal tier name.
var DisplaySeverities = []string{SevCritical, SevHigh, SevMedium, SevLow, SevInformational, SevUnrated}

// severityDisplayRank orders the displayed categories. Lower is more serious.
var severityDisplayRank = map[string]int{
	SevCritical: 0, SevHigh: 1, SevMedium: 2, SevLow: 3, SevInformational: 4, SevUnrated: 5,
}

// recognizedSeverities maps a recorded rating, case-insensitively, to its displayed
// category. `High+` is the existing internal tier above High and below Critical; it
// displays as High and MUST NOT silently become Critical.
var recognizedSeverities = map[string]string{
	"critical":      SevCritical,
	"high+":         SevHigh,
	"high":          SevHigh,
	"medium":        SevMedium,
	"moderate":      SevMedium,
	"low":           SevLow,
	"informational": SevInformational,
	"info":          SevInformational,
	"unrated":       SevUnrated,
}

// DisplaySeverity maps one recorded rating to its displayed category. An empty or
// unrecognized rating becomes Unrated; the caller retains the original value so the
// technical details can still show what was recorded.
func DisplaySeverity(recorded string) string {
	if d, ok := recognizedSeverities[strings.ToLower(strings.TrimSpace(recorded))]; ok {
		return d
	}
	return SevUnrated
}

// SeverityWasRecorded reports whether a rating was present at all, so a report can say
// "not recorded" instead of implying the scan rated the issue Unrated on purpose.
func SeverityWasRecorded(recorded string) bool {
	return strings.TrimSpace(recorded) != ""
}

// SeverityDiverges reports whether the displayed category differs from the recorded
// rating, which is when the original must be visible in technical details.
func SeverityDiverges(recorded string) bool {
	r := strings.TrimSpace(recorded)
	return r != "" && r != DisplaySeverity(r)
}

// GroupSeverity returns the highest displayed severity among the recorded ratings of a
// primary issue's eligible supported members, plus the distinct original ratings in
// display order. With no ratings at all the result is Unrated and the caller discloses
// that nothing was recorded rather than presenting a guess.
func GroupSeverity(recorded []string) (display string, originals []string) {
	display = SevUnrated
	best := len(DisplaySeverities) // worse than any real rank
	seen := map[string]bool{}
	for _, r := range recorded {
		if !SeverityWasRecorded(r) {
			continue
		}
		d := DisplaySeverity(r)
		if rank, ok := severityDisplayRank[d]; ok && rank < best {
			best, display = rank, d
		}
		if t := strings.TrimSpace(r); !seen[t] {
			seen[t] = true
			originals = append(originals, t)
		}
	}
	// Order the originals by RECORDED seriousness, not by displayed category, so a
	// reader of the technical details sees High+ before High rather than alphabetically.
	sort.SliceStable(originals, func(i, j int) bool {
		ri, rj := recordedSeverityRank(originals[i]), recordedSeverityRank(originals[j])
		if ri != rj {
			return ri < rj
		}
		return originals[i] < originals[j]
	})
	return display, originals
}

// recordedSeverityRank orders recorded ratings, keeping the internal High+ tier
// distinct from High. An unrecognized rating sorts last, so a gap never looks urgent.
var recordedSeverityRank = func() func(string) int {
	order := map[string]int{
		"critical": 0, "high+": 1, "high": 2, "medium": 3, "moderate": 3,
		"low": 4, "informational": 5, "info": 5, "unrated": 6,
	}
	return func(recorded string) int {
		if r, ok := order[strings.ToLower(strings.TrimSpace(recorded))]; ok {
			return r
		}
		return len(order) + 1
	}
}()

// SeverityRankOf exposes the display rank for deterministic ordering. An unknown
// category sorts last rather than first, so a gap never looks urgent.
func SeverityRankOf(display string) int {
	if r, ok := severityDisplayRank[display]; ok {
		return r
	}
	return len(DisplaySeverities)
}

// EmptySeverityCounts returns a counts map carrying every displayed category at zero,
// so a chart shows a real zero instead of omitting the category.
func EmptySeverityCounts() map[string]int {
	out := make(map[string]int, len(DisplaySeverities))
	for _, s := range DisplaySeverities {
		out[s] = 0
	}
	return out
}
