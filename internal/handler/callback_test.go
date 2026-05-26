package handler_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"haproxy-github-oauth/internal/auth"
	"haproxy-github-oauth/internal/handler"
	"haproxy-github-oauth/internal/session"
)

const (
	callbackSecret    = "a-secret-that-is-at-least-32-chars!!"
	callbackCookieSec = "a-secret-that-is-at-least-32-chars!!"
	callbackBaseURL   = "https://auth.example.com"
)

type fakeGitHubTeam struct {
	Slug         string        `json:"slug"`
	Organization fakeGitHubOrg `json:"organization"`
}

type fakeGitHubOrg struct {
	Login string `json:"login"`
}

func makeCallbackState(t *testing.T) (state, signedState string) {
	t.Helper()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/login", nil)
	rr := httptest.NewRecorder()
	client := auth.NewClient("client-id", "client-secret", callbackBaseURL)
	handler.Login(client, callbackCookieSec).ServeHTTP(rr, req)
	require.Equal(t, http.StatusFound, rr.Code)

	loc := rr.Header().Get("Location")
	parsed, err := url.Parse(loc)
	require.NoError(t, err)
	state = parsed.Query().Get("state")
	require.NotEmpty(t, state)

	for _, c := range rr.Result().Cookies() {
		if c.Name == "oauth_state" {
			signedState = c.Value
			break
		}
	}
	require.NotEmpty(t, signedState)
	return state, signedState
}

func makeGitHubMockServer(t *testing.T, teams []fakeGitHubTeam) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/login/oauth/access_token":
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprint(w, `{"access_token":"fake-token","token_type":"bearer"}`)
		case "/user/teams":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(teams)
		default:
			http.NotFound(w, r)
		}
	}))
}

func testStateCookie(signedState string) *http.Cookie {
	return &http.Cookie{ //nolint:gosec // test-only request cookie; Secure/HttpOnly not applicable to client requests
		Name:  "oauth_state",
		Value: signedState,
	}
}

func TestCallback_HappyPath(t *testing.T) {
	teams := []fakeGitHubTeam{
		{Slug: "admins", Organization: fakeGitHubOrg{Login: "myorg"}},
	}
	ghSrv := makeGitHubMockServer(t, teams)
	defer ghSrv.Close()

	state, signedState := makeCallbackState(t)
	store := session.New(callbackSecret, 8*time.Hour)
	authClient := auth.NewClientWithBaseURL("client-id", "client-secret", callbackBaseURL, ghSrv.URL)
	authClient.SetTokenURL(ghSrv.URL + "/login/oauth/access_token")

	req := httptest.NewRequestWithContext(
		context.Background(),
		http.MethodGet,
		"/callback?code=abc123&state="+state+"&rd="+url.QueryEscape(callbackBaseURL+"/dashboard"),
		nil,
	)
	req.AddCookie(testStateCookie(signedState))
	rr := httptest.NewRecorder()

	handler.Callback(authClient, store, callbackBaseURL, callbackCookieSec).ServeHTTP(rr, req)

	require.Equal(t, http.StatusFound, rr.Code)

	var authCookie *http.Cookie
	for _, c := range rr.Result().Cookies() {
		if c.Name == "_auth" {
			authCookie = c
			break
		}
	}
	require.NotNil(t, authCookie, "_auth cookie must be set")
	assert.True(t, authCookie.HttpOnly)
	assert.True(t, authCookie.Secure)

	claims, err := store.Verify(authCookie.Value)
	require.NoError(t, err)
	assert.Equal(t, []string{"myorg/admins"}, claims.Teams)
}

func TestCallback_BadState(t *testing.T) {
	ghSrv := makeGitHubMockServer(t, nil)
	defer ghSrv.Close()

	store := session.New(callbackSecret, 8*time.Hour)
	authClient := auth.NewClientWithBaseURL("client-id", "client-secret", callbackBaseURL, ghSrv.URL)

	req := httptest.NewRequestWithContext(
		context.Background(),
		http.MethodGet,
		"/callback?code=abc123&state=wrongstate",
		nil,
	)
	req.AddCookie(testStateCookie("differentstate.badsig"))
	rr := httptest.NewRecorder()

	handler.Callback(authClient, store, callbackBaseURL, callbackCookieSec).ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestCallback_OpenRedirectPrevention(t *testing.T) {
	teams := []fakeGitHubTeam{{Slug: "admins", Organization: fakeGitHubOrg{Login: "myorg"}}}
	ghSrv := makeGitHubMockServer(t, teams)
	defer ghSrv.Close()

	state, signedState := makeCallbackState(t)
	store := session.New(callbackSecret, 8*time.Hour)
	authClient := auth.NewClientWithBaseURL("client-id", "client-secret", callbackBaseURL, ghSrv.URL)
	authClient.SetTokenURL(ghSrv.URL + "/login/oauth/access_token")

	tests := []struct {
		name       string
		rd         string
		wantStatus int
		wantLoc    string
	}{
		{"external host", "https://evil.com/steal", http.StatusBadRequest, ""},
		{"protocol-relative", "//evil.com/steal", http.StatusBadRequest, ""},
		{"suffix confusion", "https://evilexample.com/", http.StatusBadRequest, ""},
		{"no rd defaults to base", "", http.StatusFound, callbackBaseURL + "/"},
		{"same host", callbackBaseURL + "/dashboard", http.StatusFound, callbackBaseURL + "/dashboard"},
		{"sibling subdomain", "https://gitea.example.com/dashboard", http.StatusFound, "https://gitea.example.com/dashboard"},
		{"nested sibling subdomain", "https://sub.gitea.example.com/", http.StatusFound, "https://sub.gitea.example.com/"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			target := "/callback?code=abc&state=" + state
			if tc.rd != "" {
				target += "&rd=" + url.QueryEscape(tc.rd)
			}
			req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, target, nil)
			req.AddCookie(testStateCookie(signedState))
			rr := httptest.NewRecorder()

			handler.Callback(authClient, store, callbackBaseURL, callbackCookieSec).ServeHTTP(rr, req)

			assert.Equal(t, tc.wantStatus, rr.Code)
			if tc.wantLoc != "" {
				assert.Equal(t, tc.wantLoc, rr.Header().Get("Location"))
			}
		})
	}
}
