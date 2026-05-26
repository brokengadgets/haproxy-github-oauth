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

func TestLogout(t *testing.T) {
	t.Run("clears _auth cookie and redirects to /", func(t *testing.T) {
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/logout", nil)
		req.AddCookie(&http.Cookie{Name: "_auth", Value: "sometoken"}) //nolint:gosec // test-only request cookie
		rr := httptest.NewRecorder()

		handler.Logout(".example.com").ServeHTTP(rr, req)

		require.Equal(t, http.StatusFound, rr.Code)
		assert.Equal(t, "/", rr.Header().Get("Location"))

		var authCookie *http.Cookie
		for _, c := range rr.Result().Cookies() {
			if c.Name == "_auth" {
				authCookie = c
				break
			}
		}
		require.NotNil(t, authCookie, "_auth cookie must be present in response to clear it")
		assert.Equal(t, "", authCookie.Value, "cookie value must be empty")
		assert.Equal(t, -1, authCookie.MaxAge, "MaxAge must be -1 to delete the cookie")
		assert.True(t, authCookie.HttpOnly)
		assert.True(t, authCookie.Secure)
	})

	t.Run("works even when no _auth cookie is present", func(t *testing.T) {
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/logout", nil)
		rr := httptest.NewRecorder()

		handler.Logout(".example.com").ServeHTTP(rr, req)

		require.Equal(t, http.StatusFound, rr.Code)
		assert.Equal(t, "/", rr.Header().Get("Location"))
	})
}
