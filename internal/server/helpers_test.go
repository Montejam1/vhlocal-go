package server

import (
	"testing"
	"time"
)

func waitTerminal(t *testing.T, s *Server, id string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if st, ok := s.store.Status(id); ok && isTerminal(st) {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("job did not reach terminal state")
}

func timeoutC(t *testing.T) <-chan time.Time {
	return time.After(10 * time.Second)
}

func firstN(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
