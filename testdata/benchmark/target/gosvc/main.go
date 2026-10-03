package main

import (
	"net/http"
	"os/exec"
	"path/filepath"
	"strings"
)

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /ping", pingHandler)
	mux.HandleFunc("GET /ping/safe", pingSafeHandler)
	mux.HandleFunc("GET /files", filesHandler)
	mux.HandleFunc("GET /files/safe", filesSafeHandler)
	mux.HandleFunc("GET /fetch", fetchHandler)
	mux.HandleFunc("GET /fetch/safe", fetchSafeHandler)
	http.ListenAndServe("127.0.0.1:8080", mux)
}

func pingHandler(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	out, _ := exec.Command("sh", "-c", "ping -c1 "+host).CombinedOutput()
	w.Write(out)
}

func pingSafeHandler(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	if strings.ContainsAny(host, " ;|&$`") {
		http.Error(w, "bad host", 400)
		return
	}
	out, _ := exec.Command("ping", "-c1", host).CombinedOutput()
	w.Write(out)
}

func filesHandler(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	http.ServeFile(w, r, "/srv/files/"+name)
}

func filesSafeHandler(w http.ResponseWriter, r *http.Request) {
	name := filepath.Base(r.URL.Query().Get("name"))
	http.ServeFile(w, r, filepath.Join("/srv/files", name))
}

func fetchHandler(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("url")
	resp, err := http.Get(target)
	if err != nil {
		http.Error(w, err.Error(), 502)
		return
	}
	defer resp.Body.Close()
	w.WriteHeader(resp.StatusCode)
}

func fetchSafeHandler(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("url")
	if !strings.HasPrefix(target, "https://api.example.internal/") {
		http.Error(w, "forbidden target", 403)
		return
	}
	resp, err := http.Get(target)
	if err != nil {
		http.Error(w, err.Error(), 502)
		return
	}
	defer resp.Body.Close()
	w.WriteHeader(resp.StatusCode)
}
