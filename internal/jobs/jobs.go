// Package jobs is the server's FIFO scan queue: a single worker drains queued
// jobs one at a time (one GPU), persisting state to jobs.json and streaming a
// bounded per-job event ring over SSE. Jobs mid-flight when the process died are
// marked interrupted on reload and never silently re-run (constitution VI).
package jobs

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

func randRead(b []byte) (int, error) { return rand.Read(b) }

func derefS(p *string) any {
	if p == nil {
		return nil
	}
	return *p
}
func derefF(p *float64) any {
	if p == nil {
		return nil
	}
	return *p
}

// Statuses.
const (
	StatusQueued      = "queued"
	StatusRunning     = "running"
	StatusDone        = "done"
	StatusFailed      = "failed"
	StatusCancelled   = "cancelled"
	StatusInterrupted = "interrupted"
)

const maxEventsPerJob = 4000

// Job is one unit of scan work.
type Job struct {
	ID               string         `json:"id"`
	Spec             map[string]any `json:"spec"`
	Status           string         `json:"status"`
	CreatedAt        float64        `json:"created_at"`
	StartedAt        *float64       `json:"started_at"`
	FinishedAt       *float64       `json:"finished_at"`
	ResultsDir       *string        `json:"results_dir"`
	Error            *string        `json:"error"`
	Usage            *string        `json:"usage"`
	Phase            *string        `json:"phase"`
	AgentLabel       *string        `json:"agent_label"`
	AgentIndex       int            `json:"agent_index"`
	AgentTotal       int            `json:"agent_total"`
	PromptTokens     int            `json:"prompt_tokens"`
	CompletionTokens int            `json:"completion_tokens"`
	FindingsCount    int            `json:"findings_count"`
	FindingsStage    string         `json:"findings_stage"`
	CurrentModel     string         `json:"current_model"`
	// Started is set when the engine announced scan_start (feature 014, FR-001) —
	// distinguishes a job that never reached the engine from one running with no files yet.
	Started bool `json:"started"`

	// runtime-only (not persisted directly; rebuilt on load)
	cancel context.CancelFunc
	events []map[string]any
}

// Public returns the JSON view (adds computed elapsed). Pointer fields are
// dereferenced to plain values (or nil) so consumers read strings, not pointers.
func (j *Job) Public() map[string]any {
	m := map[string]any{
		"app_slug": j.Spec["app_slug"], "app_name": j.Spec["app_name"],
		"id": j.ID, "spec": j.Spec, "status": j.Status, "created_at": j.CreatedAt,
		"started_at": derefF(j.StartedAt), "finished_at": derefF(j.FinishedAt),
		"results_dir": derefS(j.ResultsDir), "error": derefS(j.Error), "usage": derefS(j.Usage),
		"phase": derefS(j.Phase), "agent_label": derefS(j.AgentLabel),
		"agent_index": j.AgentIndex, "agent_total": j.AgentTotal, "prompt_tokens": j.PromptTokens,
		"completion_tokens": j.CompletionTokens, "findings_count": j.FindingsCount,
		"findings_stage": j.FindingsStage, "current_model": j.CurrentModel,
	}
	elapsed := 0.0
	if j.StartedAt != nil {
		end := float64(time.Now().Unix())
		if j.FinishedAt != nil {
			end = *j.FinishedAt
		}
		elapsed = end - *j.StartedAt
	}
	m["elapsed"] = elapsed
	return m
}

// UsageSummary formats the engine usage string (parity with Usage.summary()).
func UsageSummary(calls, prompt, completion int, seconds float64, peak int) string {
	tps := 0.0
	if seconds > 0 {
		tps = float64(completion) / seconds
	}
	return fmt.Sprintf("%d calls | %s prompt + %s completion tok | %.1fs | %.1f tok/s | peak prompt %s",
		calls, comma(prompt), comma(completion), seconds, tps, comma(peak))
}

func comma(n int) string {
	s := fmt.Sprintf("%d", n)
	if n < 1000 {
		return s
	}
	// insert thousands separators
	var out []byte
	rem := len(s) % 3
	for i, c := range s {
		if i != 0 && (i-rem)%3 == 0 {
			out = append(out, ',')
		}
		out = append(out, byte(c))
	}
	return string(out)
}

// RunFunc executes a job's scan. It receives the job spec and an emit callback
// that records events; it returns the results dir and any error.
type RunFunc func(ctx context.Context, spec map[string]any, emit func(map[string]any)) (resultsDir string, err error)

// Store is the job queue + persistence.
type Store struct {
	mu    sync.Mutex
	jobs  map[string]*Job
	order []string // creation order
	queue chan string
	run   RunFunc
	path  string
	busy  bool
	// bindOK confines early results-dir binding (feature 014, FR-001): the server
	// sets it to its allow-root check. nil = accept any absolute, clean path.
	bindOK func(dir string) bool
}

// SetBindFilter installs the confinement check applied when a job binds its
// results directory from the engine's scan_start event (feature 014, FR-001).
func (s *Store) SetBindFilter(ok func(dir string) bool) {
	s.mu.Lock()
	s.bindOK = ok
	s.mu.Unlock()
}

// ctxKey keys request-scoped values on the run context.
type ctxKey int

const jobIDKey ctxKey = 1

// IDFromContext returns the job id the worker attached to the run context
// (feature 014): lets the runner tag logs with the job id without changing
// RunFunc's signature.
func IDFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(jobIDKey).(string); ok {
		return v
	}
	return ""
}

// NewStore loads persisted jobs (marking interrupted any that were active) and
// starts the single worker.
func NewStore(path string, run RunFunc) (*Store, error) {
	s := &Store{jobs: map[string]*Job{}, queue: make(chan string, 1024), run: run, path: path}
	s.load()
	go s.worker()
	return s, nil
}

func (s *Store) load() {
	b, err := os.ReadFile(s.path)
	if err != nil {
		return
	}
	var persisted []*Job
	if json.Unmarshal(b, &persisted) != nil {
		return
	}
	for _, j := range persisted {
		if j.Status == StatusRunning || j.Status == StatusQueued {
			j.Status = StatusInterrupted
			msg := "server restarted while job was active"
			j.Error = &msg
			markPartialRecord(j)
		}
		s.jobs[j.ID] = j
		s.order = append(s.order, j.ID)
	}
}

// Only update an engine-owned partial record associated with this persisted job.
// A finished report is never relabeled when recovering queue state.
func markPartialRecord(j *Job) {
	if j.ResultsDir == nil {
		return
	}
	p := filepath.Join(*j.ResultsDir, "scan_meta.json")
	b, err := os.ReadFile(p)
	if err != nil {
		return
	}
	var meta map[string]any
	if json.Unmarshal(b, &meta) != nil || meta["schema"] != "partial" || meta["repo"] != j.Spec["repo"] {
		return
	}
	meta["status"] = j.Status
	b, err = json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return
	}
	if os.WriteFile(p+".tmp", b, 0600) == nil {
		_ = os.Rename(p+".tmp", p)
	}
}

func (s *Store) persist() {
	var list []*Job
	for _, id := range s.order {
		list = append(list, s.jobs[id])
	}
	b, _ := json.MarshalIndent(list, "", "  ")
	tmp := s.path + ".tmp"
	if os.MkdirAll(filepath.Dir(s.path), 0o755) == nil && os.WriteFile(tmp, b, 0o644) == nil {
		_ = os.Rename(tmp, s.path)
	}
}

// Submit enqueues a new job and returns its id.
func (s *Store) Submit(spec map[string]any) string {
	s.mu.Lock()
	id := newID()
	j := &Job{ID: id, Spec: spec, Status: StatusQueued, CreatedAt: float64(time.Now().Unix())}
	s.jobs[id] = j
	s.order = append(s.order, id)
	s.persist()
	s.mu.Unlock()
	s.queue <- id
	return id
}

func (s *Store) worker() {
	for id := range s.queue {
		s.mu.Lock()
		j := s.jobs[id]
		if j == nil || j.Status != StatusQueued {
			s.mu.Unlock()
			continue
		}
		// Feature 014: attach the job id so the runner can tag this run's log lines.
		ctx, cancel := context.WithCancel(context.WithValue(context.Background(), jobIDKey, id))
		j.cancel = cancel
		now := float64(time.Now().Unix())
		j.StartedAt = &now
		j.Status = StatusRunning
		s.busy = true
		s.persist()
		s.mu.Unlock()

		emit := func(ev map[string]any) { s.onEvent(id, ev) }
		resultsDir, err := s.run(ctx, j.Spec, emit)

		s.mu.Lock()
		fin := float64(time.Now().Unix())
		j.FinishedAt = &fin
		if resultsDir != "" {
			j.ResultsDir = &resultsDir
		}
		switch {
		case ctx.Err() != nil:
			j.Status = StatusCancelled
		case err != nil:
			j.Status = StatusFailed
			m := err.Error()
			j.Error = &m
		default:
			j.Status = StatusDone
		}
		j.cancel = nil
		markPartialRecord(j)
		s.busy = false
		s.appendEvent(j, map[string]any{"type": "job_end", "status": j.Status})
		s.persist()
		s.mu.Unlock()
	}
}

// onEvent updates job progress from an engine event and rings it.
func (s *Store) onEvent(id string, ev map[string]any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	j := s.jobs[id]
	if j == nil {
		return
	}
	switch ev["type"] {
	case "scan_start":
		// Feature 014 (FR-001): bind the results directory the moment the engine
		// announces it — confined, then PERSISTED — so evidence endpoints resolve it
		// for the whole run instead of only after the run function returns.
		if rd, ok := ev["results_dir"].(string); ok && rd != "" {
			clean := filepath.Clean(rd)
			confined := filepath.IsAbs(clean) && !hasDotDot(clean) && (s.bindOK == nil || s.bindOK(clean))
			if confined {
				j.ResultsDir = &clean
				j.Started = true
				s.persist()
			}
		}
	case "phase_start":
		ph := fmt.Sprintf("%v — %v", ev["key"], ev["title"])
		j.Phase = &ph
		s.persist() // feature 014 (FR-008): progress survives a restart
	case "agent_start":
		if l, ok := ev["label"].(string); ok {
			j.AgentLabel = &l
		}
		if m, ok := ev["model"].(string); ok {
			j.CurrentModel = m
		}
	case "findings":
		if c, ok := ev["count"].(int); ok {
			j.FindingsCount = c
		}
		if st, ok := ev["stage"].(string); ok {
			j.FindingsStage = st
		}
	}
	// Live progress tiles: any event may carry cumulative token/agent counters
	// (feature 007, T008) — previously these stayed 0 for the whole run.
	if pt, ok := evInt(ev["prompt_tokens"]); ok {
		j.PromptTokens = pt
	}
	if ct, ok := evInt(ev["completion_tokens"]); ok {
		j.CompletionTokens = ct
	}
	if ai, ok := evInt(ev["agent_index"]); ok {
		j.AgentIndex = ai
	}
	if at, ok := evInt(ev["agent_total"]); ok {
		j.AgentTotal = at
	}
	s.appendEvent(j, ev)
}

// Evidence states (feature 014, FR-002): one resolver so every evidence endpoint
// (artifacts/file/prompts/log) distinguishes the same conditions the same way.
const (
	EvidenceUnknown        = "unknown"          // id not in store
	EvidenceNotStarted     = "not_started"      // queued, or ended before the engine announced start
	EvidenceRunningNoFiles = "running_no_files" // bound, dir exists, nothing written yet
	EvidenceReady          = "ready"            // bound, files present
	EvidenceEmpty          = "empty"            // terminal, bound, dir exists, no files
	EvidenceUnavailable    = "unavailable"      // bound but directory missing/unreadable
)

// EvidenceState classifies a job's evidence availability and returns the bound
// results directory (when any) and a reason for unavailable states.
func (s *Store) EvidenceState(id string) (state, dir, reason string) {
	s.mu.Lock()
	j := s.jobs[id]
	var bound string
	var status string
	if j != nil {
		status = j.Status
		if j.ResultsDir != nil {
			bound = *j.ResultsDir
		}
	}
	s.mu.Unlock()
	if j == nil {
		return EvidenceUnknown, "", "no such job"
	}
	if bound == "" {
		return EvidenceNotStarted, "", "the engine has not announced a results directory"
	}
	entries, err := os.ReadDir(bound)
	if err != nil {
		return EvidenceUnavailable, bound, err.Error()
	}
	if len(entries) == 0 {
		switch status {
		case StatusDone, StatusFailed, StatusCancelled, StatusInterrupted:
			return EvidenceEmpty, bound, ""
		}
		return EvidenceRunningNoFiles, bound, ""
	}
	return EvidenceReady, bound, ""
}

// hasDotDot reports whether a path contains a ".." segment.
func hasDotDot(p string) bool {
	for p != "" && p != "/" && p != "." {
		dir, file := filepath.Split(p)
		if file == ".." {
			return true
		}
		next := filepath.Clean(dir)
		if next == p {
			break
		}
		p = next
	}
	return false
}

// evInt reads an int-valued event field, tolerating int and float64 (JSON).
func evInt(v any) (int, bool) {
	switch n := v.(type) {
	case int:
		return n, true
	case float64:
		return int(n), true
	}
	return 0, false
}

func (s *Store) appendEvent(j *Job, ev map[string]any) {
	if _, ok := ev["ts"]; !ok {
		ev["ts"] = float64(time.Now().UnixNano()) / 1e9
	}
	j.events = append(j.events, ev)
	if len(j.events) > maxEventsPerJob {
		j.events = j.events[len(j.events)-maxEventsPerJob:]
	}
}

// Get returns a job's public view.
func (s *Store) Get(id string) (map[string]any, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	j, ok := s.jobs[id]
	if !ok {
		return nil, false
	}
	return j.Public(), true
}

// List returns all jobs newest-first plus busy state.
func (s *Store) List() ([]map[string]any, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]map[string]any, 0, len(s.order))
	ids := append([]string{}, s.order...)
	sort.Slice(ids, func(i, j int) bool {
		return s.jobs[ids[i]].CreatedAt > s.jobs[ids[j]].CreatedAt
	})
	for _, id := range ids {
		out = append(out, s.jobs[id].Public())
	}
	return out, s.busy
}

// EventsSince returns events from offset onward for a job.
func (s *Store) EventsSince(id string, offset int) ([]map[string]any, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	j, ok := s.jobs[id]
	if !ok {
		return nil, false
	}
	if offset < 0 || offset > len(j.events) {
		offset = 0
	}
	return append([]map[string]any{}, j.events[offset:]...), true
}

// Status returns a job's status.
func (s *Store) Status(id string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	j, ok := s.jobs[id]
	if !ok {
		return "", false
	}
	return j.Status, true
}

// Cancel stops a job. A queued job is cancelled immediately; a running job is
// signalled to stop cooperatively. Returns false if not cancellable.
func (s *Store) Cancel(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	j, ok := s.jobs[id]
	if !ok {
		return false
	}
	switch j.Status {
	case StatusQueued:
		j.Status = StatusCancelled
		fin := float64(time.Now().Unix())
		j.FinishedAt = &fin
		s.appendEvent(j, map[string]any{"type": "scan_done", "cancelled": true, "seconds": 0, "usage": ""})
		s.appendEvent(j, map[string]any{"type": "job_end", "status": StatusCancelled})
		s.persist()
		return true
	case StatusRunning:
		if j.cancel != nil {
			j.cancel()
		}
		return true
	default:
		return false
	}
}

// Busy reports whether a scan is currently running.
func (s *Store) Busy() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.busy
}

func newID() string {
	b := make([]byte, 6)
	if _, err := randRead(b); err != nil {
		return fmt.Sprintf("%012x", time.Now().UnixNano())
	}
	return fmt.Sprintf("%x", b)
}
