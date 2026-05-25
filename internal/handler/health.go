// Package handler provides HTTP handlers for the auth service endpoints.
package handler

import (
	"net/http"
)

// Health returns an http.Handler that responds to GET /healthz with {"status":"ok"}.
func Health() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})
}
