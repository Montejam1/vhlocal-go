package server

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"vhlocal/internal/assist"
	"vhlocal/internal/attention"
	"vhlocal/internal/client"
	"vhlocal/internal/evidence"
	"vhlocal/internal/findings"
	"vhlocal/internal/reports"
	"vhlocal/internal/review"
	"vhlocal/internal/views"
)

// --- Findings queue & detail (feature 010, US1) ---

// handleFindings serves the cross-scan finding queue. It includes findings from
// ledger-disabled scans (they are read from findings.json, not the ledger) and
// distinguishes a filtered-empty result from no-findings (FR-001/FR-007).
func (s *Server) handleFindings(w http.ResponseWriter, r *http.Request) {
	q := findings.Query{
		Application: r.URL.Query().Get("application"),
		Scan:        r.URL.Query().Get("scan"),
		Severity:    r.URL.Query().Get("severity"),
		SeverityIn:  splitCSV(r.URL.Query().Get("severity_in")),
		Evidence:    r.URL.Query().Get("evidence"),
		Review:      r.URL.Query().Get("review"),
		Path:        r.URL.Query().Get("path"),
		Status:      r.URL.Query().Get("status"),
		Q:           r.URL.Query().Get("q"),
		Sort:        r.URL.Query().Get("sort"),
		Dir:         r.URL.Query().Get("dir"),
	}
	res := findings.Search(s.cfg.ReportsDir, q, review.Disposition)
	writeJSON(w, 200, findingsResponse{Result: res, State: ListState(res.Indexed, res.Total)})
}

// findingsResponse adds the normalized list state (API-X1) to the queue result.
type findingsResponse struct {
	findings.Result
	State string `json:"state"`
}

// handleFinding returns one occurrence's detail (row + raw finding + its review
// record). A missing occurrence yields 404 so the UI can show a useful
// missing-record state (FR-010).
func (s *Server) handleFinding(w http.ResponseWriter, r *http.Request) {
	occ := r.PathValue("occ")
	row, raw, ok := findings.Detail(s.cfg.ReportsDir, occ, review.Disposition)
	if !ok {
		writeErr(w, 404, "no such finding")
		return
	}
	rec, _ := review.Get(row.StableID)
	writeJSON(w, 200, map[string]any{
		"finding": row,
		"raw":     raw,
		"review":  rec,
	})
}

// handleEvidence serves an occurrence's source excerpt (bound to the scanned
// revision — never the working tree) plus its reviewable narrative (FR-011..013).
func (s *Server) handleEvidence(w http.ResponseWriter, r *http.Request) {
	occ := r.PathValue("occ")
	row, raw, ok := findings.Detail(s.cfg.ReportsDir, occ, review.Disposition)
	if !ok {
		writeErr(w, 404, "no such finding")
		return
	}
	meta := s.scanProvenance(row.ScanID)
	writeJSON(w, 200, evidence.Build(meta, raw))
}

// handleComparison serves the baseline diff for an occurrence's scan against an
// operator-selected comparable baseline (FR-023/FR-024).
func (s *Server) handleComparison(w http.ResponseWriter, r *http.Request) {
	occ := r.PathValue("occ")
	row, _, ok := findings.Detail(s.cfg.ReportsDir, occ, review.Disposition)
	if !ok {
		writeErr(w, 404, "no such finding")
		return
	}
	baseline := r.URL.Query().Get("baseline")
	writeJSON(w, 200, findings.Compare(s.cfg.ReportsDir, row.ScanID, baseline))
}

// scanProvenance reads a scan's recorded repo/commit/dirty from scan_meta.json so
// the evidence viewer can bind source to the exact revision.
func (s *Server) scanProvenance(scanID string) evidence.Meta {
	m := evidence.Meta{}
	b, err := os.ReadFile(filepath.Join(s.cfg.ReportsDir, scanID, "scan_meta.json"))
	if err != nil {
		return m
	}
	var meta map[string]any
	if json.Unmarshal(b, &meta) != nil {
		return m
	}
	m.Repo = str(meta["repo"])
	m.Commit = str(meta["git_commit"])
	m.Dirty, _ = meta["git_dirty"].(bool)
	return m
}

// --- Contextual AI (feature 010, US5) ---

// handleAssist runs one finding-scoped contextual action. Provider/destination is
// operator-configured (shown before submission via /api/config) and honored with
// no silent fallback (FR-041). Repeating a request with the same request_id
// returns the stored result rather than resubmitting (FR-042).
func (s *Server) handleAssist(w http.ResponseWriter, r *http.Request) {
	occ := r.PathValue("occ")
	row, raw, ok := findings.Detail(s.cfg.ReportsDir, occ, review.Disposition)
	if !ok {
		writeErr(w, 404, "no such finding")
		return
	}
	b := body(r)
	action := assist.Action(str(b["action"]))
	reqID := str(b["request_id"])

	// No resubmit: return an existing result for the same request_id.
	if prev, ok := assist.Get(row.StableID, action, row.Revision); ok && prev.RequestID == reqID && reqID != "" {
		writeJSON(w, 200, prev)
		return
	}

	prov, err := s.assistProviderFor(b)
	if err != nil {
		writeErr(w, 400, err.Error()) // explicit — no silent fallback (FR-041)
		return
	}
	res := assist.Run(r.Context(), prov, assist.Request{
		StableID: row.StableID, ScanID: row.ScanID, Revision: row.Revision,
		Action: action, RequestID: reqID, Model: str(b["model"]), Finding: raw,
	})
	writeJSON(w, 200, res)
}

func (s *Server) handleAssistGet(w http.ResponseWriter, r *http.Request) {
	occ := r.PathValue("occ")
	action := assist.Action(r.URL.Query().Get("action"))
	row, _, ok := findings.Detail(s.cfg.ReportsDir, occ, review.Disposition)
	if !ok {
		writeErr(w, 404, "no such finding")
		return
	}
	res, ok := assist.Get(row.StableID, action, row.Revision)
	if !ok {
		writeErr(w, 404, "no such assist result")
		return
	}
	writeJSON(w, 200, res)
}

func (s *Server) handleAssistCancel(w http.ResponseWriter, r *http.Request) {
	occ := r.PathValue("occ")
	action := assist.Action(str(body(r)["action"]))
	row, _, ok := findings.Detail(s.cfg.ReportsDir, occ, review.Disposition)
	if !ok {
		writeErr(w, 404, "no such finding")
		return
	}
	res, ok := assist.Cancel(row.StableID, action, row.Revision)
	if !ok {
		writeErr(w, 404, "no such assist result")
		return
	}
	writeJSON(w, 200, res)
}

// assistProviderFor returns the injected provider (tests) or builds one from the
// request's backend/host (prod). It never silently substitutes a provider: a
// missing/invalid configuration is an explicit error (FR-041).
func (s *Server) assistProviderFor(b map[string]any) (client.Provider, error) {
	if s.assistProvider != nil {
		return s.assistProvider, nil
	}
	backend := str(b["provider"])
	if backend == "" {
		backend = "ollama"
	}
	host := str(b["host"])
	if host == "" {
		host = s.cfg.OllamaHost
	}
	return s.provider(backend, host)
}

// --- Dashboard "Needs attention" queues (feature 010, US4) ---

// handleAttention serves the "Needs attention" queues. It is intentionally a
// SEPARATE endpoint from /api/stats: a failure computing queues must not blank or
// block the preserved dashboard metrics (FR-037). stale_days defaults to 7.
func (s *Server) handleAttention(w http.ResponseWriter, r *http.Request) {
	staleDays, _ := strconv.Atoi(r.URL.Query().Get("stale_days"))
	rep := attention.Compute(s.cfg.ReportsDir, staleDays, review.Disposition, time.Now().Unix())
	writeJSON(w, 200, rep)
}

// --- Scan status & artifact manifest (feature 010, US3) ---

// handleScanStatus returns the three independent status axes and per-phase
// outcomes for a scan, distinct from the queue/job status (FR-025/FR-026).
func (s *Server) handleScanStatus(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !reports.SanitizeID(id) {
		writeErr(w, 400, "bad scan id")
		return
	}
	st := scanStatus(filepath.Join(s.cfg.ReportsDir, id))
	if st == nil {
		writeErr(w, 404, "no status for scan")
		return
	}
	writeJSON(w, 200, st)
}

// handleScanManifest returns the validated artifact manifest for a scan, where
// "available" means content-validated, not merely a present filename (FR-027/028).
func (s *Server) handleScanManifest(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !reports.SanitizeID(id) {
		writeErr(w, 400, "bad scan id")
		return
	}
	dir := filepath.Join(s.cfg.ReportsDir, id)
	if fi, err := os.Stat(dir); err != nil || !fi.IsDir() {
		writeErr(w, 404, "no such scan")
		return
	}
	writeJSON(w, 200, map[string]any{"scan": id, "artifacts": reports.Manifest(dir)})
}

// --- Human review decisions (feature 010, US2) ---

func (s *Server) handleGetReview(w http.ResponseWriter, r *http.Request) {
	stable := r.PathValue("stable")
	rec, _ := review.Get(stable) // empty record (needs-review head) when none exists
	writeJSON(w, 200, rec)
}

// handleSubmitReview appends a decision. It enforces the rationale rule and the
// optimistic-version conflict check, returning 409 with the current record when
// the base version is stale so the newer decision is never silently lost
// (FR-018/FR-021).
func (s *Server) handleSubmitReview(w http.ResponseWriter, r *http.Request) {
	stable := r.PathValue("stable")
	b := body(r)
	sub := review.Submission{
		Disposition:         str(b["disposition"]),
		Rationale:           str(b["rationale"]),
		Notes:               str(b["notes"]),
		ScanID:              str(b["scan_id"]),
		Revision:            str(b["revision"]),
		Operator:            str(b["operator"]),
		EvidenceFingerprint: str(b["evidence_fingerprint"]),
		BaseVersion:         toInt(b["base_version"]),
	}
	rec, err := review.Submit(stable, sub)
	switch {
	case err == review.ErrConflict:
		writeJSON(w, 409, map[string]any{"error": err.Error(), "current": rec})
	case err == review.ErrRationaleRequired:
		writeErr(w, 400, err.Error())
	case err != nil:
		writeErr(w, 400, err.Error())
	default:
		writeJSON(w, 200, rec)
	}
}

// --- Saved views (feature 010, US1, FR-006) ---

func (s *Server) handleListViews(w http.ResponseWriter, r *http.Request) {
	list, err := views.List()
	if err != nil {
		writeErr(w, 500, "could not read saved views")
		return
	}
	writeJSON(w, 200, map[string]any{"views": list})
}

func (s *Server) handleSaveView(w http.ResponseWriter, r *http.Request) {
	b := body(r)
	v := views.View{
		ID:      str(b["id"]),
		Name:    str(b["name"]),
		Filters: strMap(b["filters"]),
		Sort:    strMap(b["sort"]),
	}
	saved, err := views.Save(v)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, saved)
}

func (s *Server) handleDeleteView(w http.ResponseWriter, r *http.Request) {
	if err := views.Delete(r.PathValue("id")); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"deleted": r.PathValue("id")})
}

// toInt reads a JSON-number field (float64/int) as int; 0 otherwise.
func toInt(v any) int {
	switch n := v.(type) {
	case float64:
		return int(n)
	case int:
		return n
	}
	return 0
}

// splitCSV splits a comma-separated query value into trimmed, non-empty parts.
func splitCSV(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// strMap coerces a decoded JSON object of string→string (filters/sort payloads).
func strMap(v any) map[string]string {
	m, ok := v.(map[string]any)
	if !ok {
		return nil
	}
	out := map[string]string{}
	for k, val := range m {
		if s, ok := val.(string); ok && strings.TrimSpace(s) != "" {
			out[k] = s
		}
	}
	return out
}
