package server

import (
	"bufio"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"vhlocal/internal/config"
	"vhlocal/internal/engine"
	"vhlocal/internal/jobs"
	"vhlocal/internal/logsetup"
)

// Feature 014 (FR-002/003/005/006/009): the scan-evidence endpoints. Every one
// consults the SAME evidence-state resolver so unknown / not_started /
// running_no_files / ready / empty / unavailable are distinguishable — never a
// shared empty list or shared error body (contracts/evidence-api.md).

// Bounds (contracts "Bounds").
const (
	artifactsPageDefault = 200
	artifactsPageMax     = 1000
	promptsPageDefault   = 100
	promptsPageMax       = 500
	logTailDefault       = 500
	logTailMax           = 5000
)

// evidenceDir resolves a job's evidence state, writing the contract response for
// the non-servable states (unknown 404, not_started 202, unavailable 503). It
// returns ok=true for running_no_files / ready / empty, whose directory exists.
func (s *Server) evidenceDir(w http.ResponseWriter, id string) (dir, state string, ok bool) {
	state, dir, reason := s.store.EvidenceState(id)
	switch state {
	case jobs.EvidenceUnknown:
		writeJSON(w, 404, map[string]any{"state": state, "error": "no such job"})
		return "", state, false
	case jobs.EvidenceNotStarted:
		writeJSON(w, 202, map[string]any{"state": state, "reason": reason, "files": []any{}})
		return "", state, false
	case jobs.EvidenceUnavailable:
		writeJSON(w, 503, map[string]any{"state": state, "reason": reason})
		return dir, state, false
	}
	return dir, state, true
}

func qInt(r *http.Request, key string, def int) int {
	if v := r.URL.Query().Get(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func clampInt(n, def, max int) int {
	if n < 1 {
		return def
	}
	if n > max {
		return max
	}
	return n
}

// handleScanArtifacts — paged, state-tagged file list (FR-002/003).
func (s *Server) handleScanArtifacts(w http.ResponseWriter, r *http.Request) {
	dir, state, ok := s.evidenceDir(w, r.PathValue("id"))
	if !ok {
		return
	}
	all, _ := listFiles(dir)["files"].([]map[string]any)
	off := qInt(r, "offset", 0)
	lim := clampInt(qInt(r, "limit", artifactsPageDefault), artifactsPageDefault, artifactsPageMax)
	if off < 0 {
		off = 0
	}
	if off > len(all) {
		off = len(all)
	}
	end := off + lim
	if end > len(all) {
		end = len(all)
	}
	resp := map[string]any{"state": state, "files": all[off:end], "total": len(all)}
	if end < len(all) {
		resp["next_offset"] = end
	}
	writeJSON(w, 200, resp)
}

// handleScanFile — confined file read; states other than servable are distinct.
func (s *Server) handleScanFile(w http.ResponseWriter, r *http.Request) {
	dir, _, ok := s.evidenceDir(w, r.PathValue("id"))
	if !ok {
		return
	}
	serveConfined(w, dir, r.URL.Query().Get("path"))
}

// handleScanPrompts — paged prompt records (FR-005/009). States: ready (≥1
// record) · not_recorded (terminal scan predating capture) · running_no_files ·
// no_records.
func (s *Server) handleScanPrompts(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	dir, state, ok := s.evidenceDir(w, id)
	if !ok {
		return
	}
	after := qInt(r, "after", 0)
	lim := clampInt(qInt(r, "limit", promptsPageDefault), promptsPageDefault, promptsPageMax)
	recs, total := readPromptRecords(filepath.Join(dir, engine.PromptsFile), after, lim)
	resp := map[string]any{"records": recs, "total": total}
	switch {
	case total > 0:
		resp["state"] = "ready"
		if len(recs) > 0 {
			if seq, ok := recs[len(recs)-1]["seq"].(float64); ok && int(seq) < total {
				resp["next_after"] = int(seq)
			}
		}
	case s.legacyNoCapture(id, dir):
		resp["state"] = "not_recorded"
		resp["reason"] = "not recorded by this version of the scanner"
	case state == jobs.EvidenceRunningNoFiles:
		resp["state"] = jobs.EvidenceRunningNoFiles
	default:
		resp["state"] = "no_records"
	}
	writeJSON(w, 200, resp)
}

// legacyNoCapture: a terminal scan whose scan_meta.json lacks prompt_capture_version.
func (s *Server) legacyNoCapture(id, dir string) bool {
	st, _ := s.store.Status(id)
	switch st {
	case jobs.StatusDone, jobs.StatusFailed, jobs.StatusCancelled, jobs.StatusInterrupted:
	default:
		return false
	}
	b, err := os.ReadFile(filepath.Join(dir, engine.ScanMetaFile))
	if err != nil {
		return false
	}
	var meta struct {
		V int `json:"prompt_capture_version"`
	}
	return json.Unmarshal(b, &meta) == nil && meta.V == 0
}

// readPromptRecords returns records with seq > after (up to limit) and the total
// record count. A partially written last line (concurrent append) is skipped.
func readPromptRecords(path string, after, limit int) ([]map[string]any, int) {
	f, err := os.Open(path)
	if err != nil {
		return []map[string]any{}, 0
	}
	defer f.Close()
	out := []map[string]any{}
	total := 0
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	for sc.Scan() {
		var m map[string]any
		if json.Unmarshal(sc.Bytes(), &m) != nil {
			continue // tolerate a mid-write partial line
		}
		total++
		if seq, ok := m["seq"].(float64); ok && int(seq) <= after {
			continue
		}
		if len(out) < limit {
			out = append(out, m)
		}
	}
	return out, total
}

// handleScanLog — tail/cursor window over this scan's tagged lines (FR-006).
// States: ready (≥1 line) · running_no_files · no_lines. JSON, never a prose sentinel.
func (s *Server) handleScanLog(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	_, state, ok := s.evidenceDir(w, id)
	if !ok {
		return
	}
	text, _ := logsetup.ReadLog(config.LogFile(), 0, id, logsetup.DEBUG)
	var lines []string
	if strings.TrimSpace(text) != "" {
		lines = strings.Split(text, "\n")
	}
	total := len(lines)
	after := qInt(r, "after", 0)
	if after < 0 {
		after = 0
	}
	if after > total {
		after = total
	}
	window := lines[after:]
	tail := clampInt(qInt(r, "tail", logTailDefault), logTailDefault, logTailMax)
	if len(window) > tail {
		window = window[len(window)-tail:]
	}
	if window == nil {
		window = []string{}
	}
	resp := map[string]any{"lines": window, "cursor": total, "total": total}
	switch {
	case total > 0:
		resp["state"] = "ready"
	case state == jobs.EvidenceRunningNoFiles:
		resp["state"] = jobs.EvidenceRunningNoFiles
	default:
		resp["state"] = "no_lines"
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, resp)
}
