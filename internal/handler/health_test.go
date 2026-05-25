package handler_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"haproxy-github-oauth/internal/handler"
)

func TestHealth(t *testing.T) {
	tests := []struct {
		name            string
		method          string
		wantStatus      int
		wantBody        string
		wantContentType string
	}{
		{
			name:            "GET returns 200 with JSON body",
			method:          http.MethodGet,
			wantStatus:      http.StatusOK,
			wantBody:        `{"status":"ok"}`,
			wantContentType: "application/json",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequestWithContext(context.Background(), tc.method, "/healthz", nil)
			rr := httptest.NewRecorder()

			handler.Health().ServeHTTP(rr, req)

			require.Equal(t, tc.wantStatus, rr.Code)
			assert.Equal(t, tc.wantBody, rr.Body.String())
			assert.Equal(t, tc.wantContentType, rr.Header().Get("Content-Type"))
		})
	}
}
