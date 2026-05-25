package handler

import (
	"encoding/json"
	"net/http"

	"haproxy-github-oauth/internal/session"
)

type verifyResponse struct {
	Login string   `json:"login"`
	Teams []string `json:"teams"`
}

// Verify returns an http.Handler for GET /auth/verify.
// It reads the _auth cookie and returns the decoded claims as JSON, or 401.
func Verify(store *session.Store) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("_auth")
		if err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		claims, err := store.Verify(cookie.Value)
		if err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		resp := verifyResponse{Login: claims.Subject, Teams: claims.Teams}
		if err = json.NewEncoder(w).Encode(resp); err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
		}
	})
}
