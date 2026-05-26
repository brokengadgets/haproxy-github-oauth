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

func TestRateLimit(t *testing.T) {
	// Inner handler that always returns 200.
	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	t.Run("allows requests within burst", func(t *testing.T) {
		// burst=3: first 3 requests must succeed
		h := handler.RateLimit(inner, 1, 3)
		for i := range 3 {
			req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
			req.RemoteAddr = "10.0.0.1:1234"
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, req)
			assert.Equal(t, http.StatusOK, rr.Code, "request %d should be allowed", i+1)
		}
	})

	t.Run("rejects requests exceeding burst", func(t *testing.T) {
		// burst=2: third request must be rejected
		h := handler.RateLimit(inner, 1, 2)
		for range 2 {
			req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
			req.RemoteAddr = "10.0.0.2:5678"
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, req)
			require.Equal(t, http.StatusOK, rr.Code)
		}
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
		req.RemoteAddr = "10.0.0.2:5678"
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusTooManyRequests, rr.Code)
	})

	t.Run("different IPs have independent limits", func(t *testing.T) {
		h := handler.RateLimit(inner, 1, 1)
		for _, ip := range []string{"10.0.0.3:1", "10.0.0.4:2", "10.0.0.5:3"} {
			req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
			req.RemoteAddr = ip
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, req)
			assert.Equal(t, http.StatusOK, rr.Code, "first request from %s should be allowed", ip)
		}
	})

	t.Run("uses X-Forwarded-For when present", func(t *testing.T) {
		h := handler.RateLimit(inner, 1, 1)
		// First request via proxy succeeds.
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
		req.RemoteAddr = "127.0.0.1:9999"
		req.Header.Set("X-Forwarded-For", "203.0.113.1")
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusOK, rr.Code)

		// Second request from same forwarded IP is rejected (burst exhausted).
		req2 := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
		req2.RemoteAddr = "127.0.0.1:9999"
		req2.Header.Set("X-Forwarded-For", "203.0.113.1")
		rr2 := httptest.NewRecorder()
		h.ServeHTTP(rr2, req2)
		assert.Equal(t, http.StatusTooManyRequests, rr2.Code)
	})
}
