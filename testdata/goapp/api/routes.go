package api

import (
	"net/http"
	"os/exec"
)

// RegisterRoutes wires the HTTP surface. A fake route in this comment must be
// ignored: mux.HandleFunc("GET /commented", nope)
func RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /users/{id}", getUser) // supported-candidate target (command injection)
	mux.HandleFunc("POST /login", login)       // defended target
	mux.HandleFunc("GET /health", health)      // unrelated sibling (must stay not_reviewed)
}

func getUser(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	// vulnerable: user input flows into a shell command
	_ = exec.Command("sh", "-c", "id "+id).Run()
}

func login(w http.ResponseWriter, r *http.Request) {
	// defended: constant command, no user input reaches it
	_ = exec.Command("true").Run()
}

func health(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }
