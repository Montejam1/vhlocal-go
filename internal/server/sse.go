package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"
)

// handleEvents streams a job's events over SSE: replay from ?offset= then live,
// with a keepalive comment every 15s. The stream closes on a job_end event or a
// terminal status after a keepalive (mirrors the Python SSE contract).
func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if _, ok := s.store.Status(id); !ok {
		writeErr(w, 404, "no such job")
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeErr(w, 500, "streaming unsupported")
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(200)

	offset := 0
	if o, err := strconv.Atoi(r.URL.Query().Get("offset")); err == nil && o >= 0 {
		offset = o
	}

	send := func(ev map[string]any) bool {
		b, _ := json.Marshal(ev)
		if _, err := fmt.Fprintf(w, "data: %s\n\n", b); err != nil {
			return false
		}
		flusher.Flush()
		return true
	}

	ctx := r.Context()
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	lastActivity := time.Now()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			evs, ok := s.store.EventsSince(id, offset)
			if !ok {
				return
			}
			if len(evs) > 0 {
				for _, ev := range evs {
					if !send(ev) {
						return
					}
					offset++
					if ev["type"] == "job_end" {
						return // stream closes on job_end
					}
				}
				lastActivity = time.Now()
			} else if time.Since(lastActivity) >= 15*time.Second {
				if _, err := fmt.Fprint(w, ": keepalive\n\n"); err != nil {
					return
				}
				flusher.Flush()
				lastActivity = time.Now()
				if st, _ := s.store.Status(id); isTerminal(st) {
					return
				}
			}
		}
	}
}

func isTerminal(status string) bool {
	switch status {
	case "done", "failed", "cancelled", "interrupted":
		return true
	}
	return false
}
