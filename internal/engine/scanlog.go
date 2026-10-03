package engine

import (
	"fmt"
	"sort"
	"strings"

	"vhlocal/internal/config"
	"vhlocal/internal/logsetup"
	"vhlocal/internal/redact"
)

// Feature 014 (FR-006/007): the scan-tagged operational log. The engine subscribes
// to its own events (and adds fine-grained ones) and writes bounded, redacted lines
// to the central log via logsetup, tagged with the job id (server) or scan tag
// (CLI) so the Log endpoint's tag filter recovers exactly this run's slice — after
// completion and across server restarts. Never persists credentials.

// scanLogClampBytes bounds a single line's detail (contracts "Bounds").
const scanLogClampBytes = 2 * 1024

type scanLog struct{ l *logsetup.Logger }

// newScanLog opens the central log for the given tag; nil when disabled/unopenable
// (logging must never fail a scan).
func newScanLog(tag string) *scanLog {
	if tag == "" {
		return nil
	}
	l, err := logsetup.New(config.LogFile(), tag, false, logsetup.DEBUG)
	if err != nil {
		return nil
	}
	return &scanLog{l: l}
}

func (s *scanLog) close() {
	if s != nil && s.l != nil {
		_ = s.l.Close()
	}
}

// line writes one tagged, bounded, redacted line: "[<label>] <event>: <detail>".
func (s *scanLog) line(level logsetup.Level, label, event, detail string) {
	if s == nil || s.l == nil {
		return
	}
	detail, _ = redact.Mask(reCredURL.ReplaceAllString(detail, "://[redacted]@"))
	if len(detail) > scanLogClampBytes {
		detail = detail[:scanLogClampBytes] + " …[truncated]"
	}
	if label == "" {
		label = "-"
	}
	s.l.Log(level, "[%s] %s: %s", label, event, detail)
}

// withScanLog wraps an Emit so every engine event also produces a log line
// before reaching the original sink (SSE / CLI).
func withScanLog(emit Emit, lg *scanLog) Emit {
	if lg == nil {
		return emit
	}
	return func(event string, payload map[string]any) {
		lg.fromEvent(event, payload)
		emit.emit(event, payload)
	}
}

// fromEvent maps engine events to log lines.
func (s *scanLog) fromEvent(event string, p map[string]any) {
	label := firstNonEmpty(pstr(p, "label"), pstr(p, "key"))
	switch event {
	case "scan_start":
		s.line(logsetup.INFO, "-", "scan_start", kv(p, "repo", "results_dir", "model", "phases"))
	case "phase_start":
		s.line(logsetup.INFO, label, "phase_start", kv(p, "title"))
	case "phase_skip":
		s.line(logsetup.INFO, label, "phase_skip", kv(p, "reason"))
	case "phase_done":
		s.line(logsetup.INFO, label, "phase_done", kv(p, "seconds", "produced"))
	case "agent_start":
		s.line(logsetup.DEBUG, label, "agent_start", kv(p, "model", "partition", "class"))
	case "agent_done":
		s.line(logsetup.INFO, label, "agent_stop", kv(p, "stopped_reason", "turns", "produced", "attempt"))
	case "output_written":
		s.line(logsetup.INFO, label, "output_written", kv(p, "path"))
	case "validation_failure":
		s.line(logsetup.WARNING, label, "validation_failure", kv(p, "path", "reason"))
	case "retry":
		s.line(logsetup.WARNING, label, "retry", kv(p, "attempt", "reason"))
	case "tool_failure":
		s.line(logsetup.WARNING, label, "tool_failure", kv(p, "class", "operation", "message"))
	case "citation_repair":
		s.line(logsetup.INFO, label, "citation_repair", kv(p, "invalid", "repaired", "remaining"))
	case "citation_invalid":
		s.line(logsetup.WARNING, label, "citation_invalid", kv(p, "code", "received"))
	case "amendment":
		s.line(logsetup.INFO, label, "amendment", kv(p, "candidate", "identity"))
	case "error":
		s.line(logsetup.ERROR, label, "error", kv(p, "phase", "kind", "message"))
	case "canary":
		s.line(logsetup.INFO, "hunt:canary", "canary", kv(p, "ok", "model", "note"))
	case "resume_invalidated":
		s.line(logsetup.WARNING, "-", "resume_invalidated", kv(p, "reason"))
	case "findings":
		s.line(logsetup.INFO, "-", "findings", kv(p, "count", "stage"))
	case "diagram":
		s.line(logsetup.INFO, label, "diagram", kv(p, "summary"))
	case "artifacts":
		s.line(logsetup.WARNING, "-", "artifact_errors", kv(p, "errors", "stage"))
	case "scan_done":
		s.line(logsetup.INFO, "-", "terminal", kv(p, "seconds", "cancelled", "aborted"))
	}
}

func pstr(p map[string]any, k string) string {
	if v, ok := p[k]; ok && v != nil {
		return fmt.Sprint(v)
	}
	return ""
}

// kv renders selected payload keys as "k=v" pairs in a stable order.
func kv(p map[string]any, keys ...string) string {
	var parts []string
	for _, k := range keys {
		if v, ok := p[k]; ok && v != nil {
			parts = append(parts, fmt.Sprintf("%s=%v", k, v))
		}
	}
	sort.Strings(parts)
	return strings.Join(parts, " ")
}
