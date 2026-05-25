//go:build integration

package integration_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"haproxy-github-oauth/internal/auth"
	"haproxy-github-oauth/internal/handler"
	"haproxy-github-oauth/internal/session"
)

const (
	integSecret = "integration-test-secret-32-chars!!"
)

// ghTeam mirrors the GitHub API team object shape.
type ghTeam struct {
	Slug         string `json:"slug"`
	Organization struct {
		Login string `json:"login"`
	} `json:"organization"`
}

// startMockGitHub returns a test server that acts as both the GitHub OAuth
// token endpoint and the GitHub API teams endpoint.
func startMockGitHub(t *testing.T, login string, teams []ghTeam) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/login/oauth/access_token":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"access_token":"fake-token","token_type":"bearer","login":%q}`, login)
		case "/user/teams":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(teams)
		default:
			http.NotFound(w, r)
		}
	}))
}

// buildMux assembles the same handler mux as cmd/server/main.go.
func buildMux(baseURL, ghAPIBaseURL, ghTokenURL, secret string) http.Handler {
	store := session.New(secret, 8*time.Hour)
	client := auth.NewClientWithBaseURL("client-id", "client-secret", baseURL, ghAPIBaseURL)
	client.SetTokenURL(ghTokenURL)

	mux := http.NewServeMux()
	mux.Handle("GET /healthz", handler.Health())
	mux.Handle("GET /login", handler.Login(client, secret))
	mux.Handle("GET /callback", handler.Callback(client, store, baseURL, secret))
	mux.Handle("GET /auth/verify", handler.Verify(store))
	return mux
}

// noRedirectClient returns an http.Client that captures cookies but does not
// follow redirects, so tests can inspect redirect targets.
func noRedirectClient() *http.Client {
	jar, _ := cookiejar.New(nil)
	return &http.Client{
		Jar: jar,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// fullFlowClient returns an http.Client that follows redirects and keeps
// cookies across requests — used for the verify step after the cookie is set.
func fullFlowClient() *http.Client {
	jar, _ := cookiejar.New(nil)
	return &http.Client{Jar: jar}
}

func TestIntegration_FullLoginFlow(t *testing.T) {
	teams := []ghTeam{
		{Slug: "engineers", Organization: struct{ Login string `json:"login"` }{Login: "acme"}},
	}
	gh := startMockGitHub(t, "alice", teams)
	defer gh.Close()

	// Use an unstarted server so we can inject baseURL into the mux.
	appSrv := httptest.NewUnstartedServer(nil)
	appSrv.Start()
	defer appSrv.Close()
	baseURL := appSrv.URL

	appSrv.Config.Handler = buildMux(baseURL, gh.URL, gh.URL+"/login/oauth/access_token", integSecret)

	client := noRedirectClient()

	// ── Step 1: GET /login ────────────────────────────────────────────────────
	loginResp, err := client.Get(baseURL + "/login")
	require.NoError(t, err)
	loginResp.Body.Close()
	require.Equal(t, http.StatusFound, loginResp.StatusCode)

	loc := loginResp.Header.Get("Location")
	require.NotEmpty(t, loc, "login must redirect")

	locURL, err := url.Parse(loc)
	require.NoError(t, err)
	state := locURL.Query().Get("state")
	require.NotEmpty(t, state, "state must be present in redirect URL")

	// The oauth_state cookie is stored in the jar.
	cookies := client.Jar.Cookies(mustParseURL(baseURL))
	var oauthStateCookie *http.Cookie
	for _, c := range cookies {
		if c.Name == "oauth_state" {
			oauthStateCookie = c
			break
		}
	}
	require.NotNil(t, oauthStateCookie, "oauth_state cookie must be set after /login")

	// ── Step 2: GET /callback (simulating GitHub redirect back) ───────────────
	rdTarget := baseURL + "/dashboard"
	callbackURL := fmt.Sprintf("%s/callback?code=testcode&state=%s&rd=%s",
		baseURL, state, url.QueryEscape(rdTarget))

	cbResp, err := client.Get(callbackURL)
	require.NoError(t, err)
	cbResp.Body.Close()
	require.Equal(t, http.StatusFound, cbResp.StatusCode, "callback must redirect after success")
	assert.Equal(t, rdTarget, cbResp.Header.Get("Location"), "callback must redirect to rd param")

	// The _auth cookie must be set.
	var authCookie *http.Cookie
	for _, c := range client.Jar.Cookies(mustParseURL(baseURL)) {
		if c.Name == "_auth" {
			authCookie = c
			break
		}
	}
	require.NotNil(t, authCookie, "_auth cookie must be set after /callback")

	// ── Step 3: GET /auth/verify ──────────────────────────────────────────────
	verifyResp, err := client.Get(baseURL + "/auth/verify")
	require.NoError(t, err)
	defer verifyResp.Body.Close()
	require.Equal(t, http.StatusOK, verifyResp.StatusCode)

	var claims map[string]any
	require.NoError(t, json.NewDecoder(verifyResp.Body).Decode(&claims))
	assert.Equal(t, "alice", claims["login"])

	teamsRaw, ok := claims["teams"].([]any)
	require.True(t, ok, "teams must be an array")
	require.Len(t, teamsRaw, 1)
	assert.Equal(t, "acme/engineers", teamsRaw[0])
}

func TestIntegration_ExpiredJWTRejected(t *testing.T) {
	gh := startMockGitHub(t, "bob", nil)
	defer gh.Close()

	appSrv := httptest.NewUnstartedServer(nil)
	appSrv.Start()
	defer appSrv.Close()
	baseURL := appSrv.URL
	appSrv.Config.Handler = buildMux(baseURL, gh.URL, gh.URL+"/login/oauth/access_token", integSecret)

	// Issue an already-expired token directly.
	expiredStore := session.New(integSecret, -1*time.Second)
	expiredToken, err := expiredStore.Issue("bob", []string{"acme/devs"})
	require.NoError(t, err)

	req, err := http.NewRequest(http.MethodGet, baseURL+"/auth/verify", nil)
	require.NoError(t, err)
	req.AddCookie(&http.Cookie{Name: "_auth", Value: expiredToken})

	resp, err := fullFlowClient().Do(req)
	require.NoError(t, err)
	resp.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestIntegration_TamperedJWTRejected(t *testing.T) {
	gh := startMockGitHub(t, "carol", nil)
	defer gh.Close()

	appSrv := httptest.NewUnstartedServer(nil)
	appSrv.Start()
	defer appSrv.Close()
	baseURL := appSrv.URL
	appSrv.Config.Handler = buildMux(baseURL, gh.URL, gh.URL+"/login/oauth/access_token", integSecret)

	store := session.New(integSecret, 8*time.Hour)
	validToken, err := store.Issue("carol", []string{"acme/staff"})
	require.NoError(t, err)

	// Tamper: flip a character in the signature (last segment).
	parts := strings.Split(validToken, ".")
	require.Len(t, parts, 3, "JWT must have 3 parts")
	sig := []byte(parts[2])
	sig[0] ^= 0x01
	parts[2] = string(sig)
	tamperedToken := strings.Join(parts, ".")

	req, err := http.NewRequest(http.MethodGet, baseURL+"/auth/verify", nil)
	require.NoError(t, err)
	req.AddCookie(&http.Cookie{Name: "_auth", Value: tamperedToken})

	resp, err := fullFlowClient().Do(req)
	require.NoError(t, err)
	resp.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestIntegration_TeamACLClaim(t *testing.T) {
	teams := []ghTeam{
		{Slug: "backend", Organization: struct{ Login string `json:"login"` }{Login: "myorg"}},
		{Slug: "infra", Organization: struct{ Login string `json:"login"` }{Login: "myorg"}},
	}
	gh := startMockGitHub(t, "dave", teams)
	defer gh.Close()

	appSrv := httptest.NewUnstartedServer(nil)
	appSrv.Start()
	defer appSrv.Close()
	baseURL := appSrv.URL
	appSrv.Config.Handler = buildMux(baseURL, gh.URL, gh.URL+"/login/oauth/access_token", integSecret)

	client := noRedirectClient()

	loginResp, err := client.Get(baseURL + "/login")
	require.NoError(t, err)
	loginResp.Body.Close()

	loc, _ := url.Parse(loginResp.Header.Get("Location"))
	state := loc.Query().Get("state")

	cbURL := fmt.Sprintf("%s/callback?code=testcode&state=%s&rd=%s",
		baseURL, state, url.QueryEscape(baseURL+"/"))
	cbResp, err := client.Get(cbURL)
	require.NoError(t, err)
	cbResp.Body.Close()
	require.Equal(t, http.StatusFound, cbResp.StatusCode)

	verifyResp, err := client.Get(baseURL + "/auth/verify")
	require.NoError(t, err)
	defer verifyResp.Body.Close()
	require.Equal(t, http.StatusOK, verifyResp.StatusCode)

	var claims map[string]any
	require.NoError(t, json.NewDecoder(verifyResp.Body).Decode(&claims))

	teamsRaw, _ := claims["teams"].([]any)
	var gotTeams []string
	for _, tt := range teamsRaw {
		gotTeams = append(gotTeams, tt.(string))
	}
	assert.ElementsMatch(t, []string{"myorg/backend", "myorg/infra"}, gotTeams)
}

func mustParseURL(s string) *url.URL {
	u, err := url.Parse(s)
	if err != nil {
		panic(err)
	}
	return u
}
