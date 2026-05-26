package handler_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"haproxy-github-oauth/internal/auth"
	"haproxy-github-oauth/internal/handler"
)

func TestLogin(t *testing.T) {
	client := auth.NewClient("client-id", "client-secret", "https://auth.example.com")

	t.Run("redirects to GitHub with state cookie", func(t *testing.T) {
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/login", nil)
		rr := httptest.NewRecorder()

		handler.Login(client, "supersecretcookiesigningkey1234").ServeHTTP(rr, req)

		require.Equal(t, http.StatusFound, rr.Code)

		location := rr.Header().Get("Location")
		require.NotEmpty(t, location)

		parsed, err := url.Parse(location)
		require.NoError(t, err)
		assert.Equal(t, "github.com", parsed.Host)
		assert.Equal(t, "/login/oauth/authorize", parsed.Path)

		scope := parsed.Query().Get("scope")
		assert.True(t, strings.Contains(scope, "read:org"))
		assert.True(t, strings.Contains(scope, "read:user"))

		state := parsed.Query().Get("state")
		assert.NotEmpty(t, state)

		var stateCookie *http.Cookie
		for _, c := range rr.Result().Cookies() {
			if c.Name == "oauth_state" {
				stateCookie = c
				break
			}
		}
		require.NotNil(t, stateCookie, "oauth_state cookie must be set")
		assert.True(t, stateCookie.HttpOnly)
		assert.Equal(t, http.SameSiteLaxMode, stateCookie.SameSite)
	})

	t.Run("preserves rd in oauth_rd cookie", func(t *testing.T) {
		rd := "https://gitea.example.com/dashboard"
		req := httptest.NewRequestWithContext(
			context.Background(), http.MethodGet,
			"/login?rd="+url.QueryEscape(rd), nil,
		)
		rr := httptest.NewRecorder()
		handler.Login(client, "supersecretcookiesigningkey1234").ServeHTTP(rr, req)

		require.Equal(t, http.StatusFound, rr.Code)

		var rdCookie *http.Cookie
		for _, c := range rr.Result().Cookies() {
			if c.Name == "oauth_rd" {
				rdCookie = c
				break
			}
		}
		require.NotNil(t, rdCookie, "oauth_rd cookie must be set when rd param is given")
		assert.Equal(t, rd, rdCookie.Value)
		assert.True(t, rdCookie.HttpOnly)
		assert.Equal(t, http.SameSiteLaxMode, rdCookie.SameSite)
	})

	t.Run("no oauth_rd cookie when rd is absent", func(t *testing.T) {
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/login", nil)
		rr := httptest.NewRecorder()
		handler.Login(client, "supersecretcookiesigningkey1234").ServeHTTP(rr, req)

		for _, c := range rr.Result().Cookies() {
			assert.NotEqual(t, "oauth_rd", c.Name, "oauth_rd cookie must not be set when rd is absent")
		}
	})

	t.Run("each request generates a unique state", func(t *testing.T) {
		states := make(map[string]struct{})
		for i := range 5 {
			_ = i
			req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/login", nil)
			rr := httptest.NewRecorder()
			handler.Login(client, "supersecretcookiesigningkey1234").ServeHTTP(rr, req)
			require.Equal(t, http.StatusFound, rr.Code)
			loc := rr.Header().Get("Location")
			parsed, err := url.Parse(loc)
			require.NoError(t, err)
			state := parsed.Query().Get("state")
			require.NotEmpty(t, state)
			states[state] = struct{}{}
		}
		assert.Len(t, states, 5, "each request must generate a unique state")
	})
}
