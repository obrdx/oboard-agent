package main

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/OboardProject/oboard-agent/kernel/oboard-sb/internal/authorization"
	"github.com/OboardProject/oboard-agent/kernel/oboard-sb/internal/minibox"
)

// registerAuthorizationHandler exposes the Agent-only authorization endpoints
// on the Unix local API. POST /authorization/config installs {lease, deny};
// POST /authorization/deny records emergency denials; GET
// /authorization/status returns the installed identity only.
func registerAuthorizationHandler(mux *http.ServeMux, listen string, tracker *minibox.RateLimitTracker) {
	if !strings.HasPrefix(listen, "unix:") {
		return
	}
	mux.HandleFunc("/authorization/connectivity", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", 405)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 1024)
		var body struct {
			Disconnected *bool `json:"disconnected"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Disconnected == nil {
			http.Error(w, "invalid connectivity state", 400)
			return
		}
		tracker.SetControllerDisconnected(*body.Disconnected)
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("/authorization/config", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", 405)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 16<<20)
		var body struct {
			minibox.AuthorizationUpdate
			authorization.Lease
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "invalid authorization snapshot", 400)
			return
		}
		update := body.AuthorizationUpdate
		if update.Lease == nil {
			// An Agent that predates the wrapped body posts the lease itself.
			bare := body.Lease
			if bare.Revision <= 0 && bare.IssuedAt == "" {
				http.Error(w, "invalid authorization snapshot", 400)
				return
			}
			update.Lease = &bare
		}
		if err := tracker.ApplyAuthorization(update); err != nil {
			http.Error(w, "authorization update rejected", 409)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "status": tracker.AuthorizationStatus()})
	})
	mux.HandleFunc("/authorization/deny", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", 405)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 4<<20)
		var body struct {
			Keys     []string `json:"keys"`
			Revision int64    `json:"revision"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || len(body.Keys) == 0 {
			http.Error(w, "invalid deny request", 400)
			return
		}
		closed, err := tracker.DenyAuthorization(body.Keys, body.Revision)
		if err != nil {
			http.Error(w, "deny rejected", 409)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "closed": closed, "status": tracker.AuthorizationStatus()})
	})
	mux.HandleFunc("/authorization/status", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", 405)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(tracker.AuthorizationStatus())
	})
}
