package server

import (
	"io/fs"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// handleStatic serves the embedded browser UI (WebFS is rooted at the web dir).
func (s *Server) handleStatic(w http.ResponseWriter, r *http.Request) {
	p := r.URL.Path
	var rel string
	switch {
	case p == "/" || p == "/index.html":
		rel = "index.html"
	case p == "/legacy" || p == "/legacy.html":
		rel = "index.legacy.html"
	case p == "/classic" || p == "/classic.html":
		rel = "index.classic.html"
	case strings.HasPrefix(p, "/static/"):
		rel = strings.TrimPrefix(p, "/static/")
	case p == "/app" || strings.HasPrefix(p, "/app/"):
		sub := strings.TrimPrefix(strings.TrimPrefix(p, "/app"), "/")
		last := sub
		if i := strings.LastIndexByte(sub, '/'); i >= 0 {
			last = sub[i+1:]
		}
		if strings.HasPrefix(sub, "assets/") || strings.Contains(last, ".") {
			rel = "app/" + sub
		} else {
			rel = "app/index.html" // SPA deep-link fallback
		}
	default:
		writeErr(w, 404, "not found")
		return
	}
	s.serveEmbedded(w, rel)
}

func (s *Server) serveEmbedded(w http.ResponseWriter, rel string) {
	if s.cfg.WebFS == nil {
		writeErr(w, 404, "not found")
		return
	}
	clean := filepath.ToSlash(filepath.Clean(rel))
	if strings.HasPrefix(clean, "..") {
		writeErr(w, 404, "not found")
		return
	}
	b, err := fs.ReadFile(s.cfg.WebFS, clean)
	if err != nil {
		writeErr(w, 404, "not found")
		return
	}
	ct := mime.TypeByExtension(filepath.Ext(clean))
	if ct == "" {
		ct = "application/octet-stream"
	}
	w.Header().Set("Content-Type", ct)
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
	w.Header().Set("Pragma", "no-cache")
	_, _ = w.Write(b)
}

// listFiles returns {root, files:[{path,size}]} for a results directory
// (recursive, dotfiles excluded, sorted).
func listFiles(dir string) map[string]any {
	type fe struct {
		Path string `json:"path"`
		Size int64  `json:"size"`
	}
	var files []fe
	filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if strings.HasPrefix(d.Name(), ".") {
			return nil
		}
		rel, _ := filepath.Rel(dir, p)
		if fi, err := d.Info(); err == nil {
			files = append(files, fe{Path: filepath.ToSlash(rel), Size: fi.Size()})
		}
		return nil
	})
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	out := make([]map[string]any, 0, len(files))
	for _, f := range files {
		out = append(out, map[string]any{"path": f.Path, "size": f.Size})
	}
	return map[string]any{"root": dir, "files": out}
}

// serveConfined reads a file by relative path, confined to root (traversal
// structurally refused).
func serveConfined(w http.ResponseWriter, root, rel string) {
	if strings.TrimSpace(rel) == "" {
		writeErr(w, 400, "path required")
		return
	}
	rootAbs, _ := filepath.Abs(root)
	target := filepath.Join(rootAbs, rel)
	targetAbs, _ := filepath.Abs(target)
	if !within(targetAbs, rootAbs) {
		writeErr(w, 403, "path escapes results directory")
		return
	}
	// Feature 014 (FR-025): absence is 404; a file that exists but cannot be read
	// (permissions, I/O) is a 500 — a server error must never be reported as absence.
	fi, err := os.Stat(targetAbs)
	if err != nil {
		if os.IsNotExist(err) {
			writeErr(w, 404, "not found")
			return
		}
		writeErr(w, 500, "cannot stat file: "+err.Error())
		return
	}
	if fi.IsDir() {
		writeErr(w, 404, "not found")
		return
	}
	b, err := os.ReadFile(targetAbs)
	if err != nil {
		writeErr(w, 500, "cannot read file: "+err.Error())
		return
	}
	ct := "text/plain; charset=utf-8"
	if strings.HasSuffix(targetAbs, ".html") {
		ct = "text/html; charset=utf-8"
	} else if strings.HasSuffix(targetAbs, ".json") {
		ct = "application/json; charset=utf-8"
	} else if strings.HasSuffix(targetAbs, ".jsonl") {
		ct = "application/x-ndjson; charset=utf-8"
	}
	w.Header().Set("Content-Type", ct)
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(b)
}
