// Package logsetup provides the central log: one shared file that every entry
// point (CLI, server, worker) writes to, with each line tagged by scan id so one
// scan's slice is recoverable even after the process is gone. Levels mirror the
// Python tool: DEBUG < INFO < WARNING < ERROR < CRITICAL.
package logsetup

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Level is a log severity.
type Level int

const (
	DEBUG Level = iota
	INFO
	WARNING
	ERROR
	CRITICAL
)

var levelNames = map[Level]string{DEBUG: "DEBUG", INFO: "INFO", WARNING: "WARNING", ERROR: "ERROR", CRITICAL: "CRITICAL"}
var levelByName = map[string]Level{"DEBUG": DEBUG, "INFO": INFO, "WARNING": WARNING, "ERROR": ERROR, "CRITICAL": CRITICAL}

// ParseLevel maps a name (case-insensitive) to a Level, defaulting to INFO.
func ParseLevel(s string) Level {
	if l, ok := levelByName[strings.ToUpper(strings.TrimSpace(s))]; ok {
		return l
	}
	return INFO
}

// Logger writes tagged lines to the central log file and (optionally) stderr.
type Logger struct {
	mu       sync.Mutex
	path     string
	f        *os.File
	scanTag  string
	toStderr bool
	minLevel Level
}

// Line format (parseable by ReadLog): "<RFC3339> <LEVEL> [<scanTag>] message".
const tsLayout = time.RFC3339

// New opens (creating dirs as needed) the central log at path. scanTag tags every
// line ("" for untagged/global lines). toStderr also echoes to stderr; minLevel
// filters what is written.
func New(path, scanTag string, toStderr bool, minLevel Level) (*Logger, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, err
	}
	return &Logger{path: path, f: f, scanTag: scanTag, toStderr: toStderr, minLevel: minLevel}, nil
}

// Close closes the underlying file.
func (l *Logger) Close() error {
	if l.f == nil {
		return nil
	}
	return l.f.Close()
}

// Log writes one line at the given level (no-op below minLevel).
func (l *Logger) Log(level Level, format string, args ...any) {
	if level < l.minLevel {
		return
	}
	msg := fmt.Sprintf(format, args...)
	tag := l.scanTag
	line := fmt.Sprintf("%s %s [%s] %s\n", time.Now().UTC().Format(tsLayout), levelNames[level], tag, msg)
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.f != nil {
		_, _ = l.f.WriteString(line)
	}
	if l.toStderr {
		fmt.Fprint(os.Stderr, line)
	}
}

func (l *Logger) Debug(f string, a ...any)   { l.Log(DEBUG, f, a...) }
func (l *Logger) Info(f string, a ...any)    { l.Log(INFO, f, a...) }
func (l *Logger) Warning(f string, a ...any) { l.Log(WARNING, f, a...) }
func (l *Logger) Error(f string, a ...any)   { l.Log(ERROR, f, a...) }

// ReadLog reads the central log at path, returning up to `tail` lines
// (0 = all), filtered to a scan tag (empty = any) and a minimum level. Lines are
// returned oldest→newest.
func ReadLog(path string, tail int, scanTag string, minLevel Level) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", err
	}
	defer f.Close()
	var lines []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	for sc.Scan() {
		ln := sc.Text()
		if scanTag != "" && !strings.Contains(ln, "["+scanTag+"]") {
			continue
		}
		if minLevel > DEBUG && !meetsLevel(ln, minLevel) {
			continue
		}
		lines = append(lines, ln)
	}
	if tail > 0 && len(lines) > tail {
		lines = lines[len(lines)-tail:]
	}
	return strings.Join(lines, "\n"), nil
}

// meetsLevel reports whether a formatted line's level is >= minLevel.
func meetsLevel(line string, min Level) bool {
	// line: "<ts> <LEVEL> [tag] msg"
	parts := strings.SplitN(line, " ", 3)
	if len(parts) < 2 {
		return true
	}
	if lvl, ok := levelByName[parts[1]]; ok {
		return lvl >= min
	}
	return true
}
