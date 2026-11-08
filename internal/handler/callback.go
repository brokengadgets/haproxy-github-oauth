package handler

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"

	"haproxy-github-oauth/internal/auth"
	"haproxy-github-oauth/internal/session"
)

// CallbackOption configures optional access-control checks in Callback.
type CallbackOption func(*callbackConfig)

type callbackConfig struct {
	requiredOrg  string
	allowedTeams []string
}

// WithOrg restricts login to users belonging to at least one team in org, and
// filters issued JWT team claims to that organization.
func WithOrg(org string) CallbackOption {
	return func(cfg *callbackConfig) {
		cfg.requiredOrg = org
	}
}

// WithAllowedTeams restricts login to users belonging to at least one of the
// specified "org/team-slug" entries.
func WithAllowedTeams(teams []string) CallbackOption {
	return func(cfg *callbackConfig) {
		cfg.allowedTeams = teams
	}
}

// Callback returns an http.Handler for GET /callback.
// It validates the OAuth state, exchanges the code for a token, fetches team
// memberships, enforces optional org/team allowlists, issues a JWT session
// cookie, and redirects to the `rd` parameter.
func Callback(client *auth.Client, store *session.Store, baseURL, cookieSecret, cookieDomain string, opts ...CallbackOption) http.Handler {
	cfg := &callbackConfig{}
	for _, opt := range opts {
		opt(cfg)
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := validateState(r, cookieSecret); err != nil {
			http.Error(w, "bad state: "+err.Error(), http.StatusBadRequest)
			return
		}

		code := r.URL.Query().Get("code")
		oauthToken, err := client.OAuthConfig().Exchange(r.Context(), code)
		if err != nil {
			http.Error(w, "token exchange failed", http.StatusBadGateway)
			return
		}

		teams, err := client.FetchTeams(r.Context(), oauthToken.AccessToken)
		if err != nil {
			http.Error(w, "team fetch failed", http.StatusBadGateway)
			return
		}

		filteredTeams, allowed := filterAndAuthorizeTeams(teams, cfg.requiredOrg, cfg.allowedTeams)
		if !allowed {
			http.Error(w, "forbidden: insufficient organization or team membership", http.StatusForbidden)
			return
		}

		loginStr, _ := oauthToken.Extra("login").(string)
		if loginStr == "" {
			if fetchedLogin, loginErr := client.FetchUserLogin(r.Context(), oauthToken.AccessToken); loginErr == nil {
				loginStr = fetchedLogin
			}
		}

		tokenStr, err := store.Issue(loginStr, filteredTeams)
		if err != nil {
			http.Error(w, "session issue failed", http.StatusInternalServerError)
			return
		}

		clearTransientOAuthCookies(w)

		http.SetCookie(w, &http.Cookie{
			Name:     "_auth",
			Value:    tokenStr,
			Path:     "/",
			Domain:   cookieDomain,
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteLaxMode,
		})

		rdVal := ""
		if rdCookie, rdErr := r.Cookie("oauth_rd"); rdErr == nil {
			rdVal = rdCookie.Value
		}
		rd, err := validateRedirect(rdVal, baseURL)
		if err != nil {
			http.Error(w, "invalid redirect: "+err.Error(), http.StatusBadRequest)
			return
		}
		http.Redirect(w, r, rd, http.StatusFound) //nolint:gosec // rd is validated against BASE_URL host by validateRedirect
	})
}

func clearTransientOAuthCookies(w http.ResponseWriter) {
	for _, name := range []string{"oauth_state", "oauth_rd"} {
		http.SetCookie(w, &http.Cookie{
			Name:     name,
			Value:    "",
			Path:     "/",
			MaxAge:   -1,
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteLaxMode,
		})
	}
}

func filterAndAuthorizeTeams(teams []string, requiredOrg string, allowedTeams []string) ([]string, bool) {
	filtered := teams
	if requiredOrg != "" {
		prefix := strings.ToLower(requiredOrg) + "/"
		filtered = make([]string, 0, len(teams))
		for _, t := range teams {
			if strings.HasPrefix(strings.ToLower(t), prefix) {
				filtered = append(filtered, t)
			}
		}
		if len(filtered) == 0 {
			return nil, false
		}
	}

	if len(allowedTeams) > 0 {
		matched := false
		for _, t := range filtered {
			for _, allowed := range allowedTeams {
				if strings.EqualFold(t, allowed) {
					matched = true
					break
				}
			}
			if matched {
				break
			}
		}
		if !matched {
			return nil, false
		}
	}

	return filtered, true
}

func validateState(r *http.Request, cookieSecret string) error {
	stateParam := r.URL.Query().Get("state")
	cookie, err := r.Cookie("oauth_state")
	if err != nil {
		return fmt.Errorf("missing oauth_state cookie")
	}

	verified, ok := VerifyStateSignature(cookie.Value, cookieSecret)
	if !ok {
		return fmt.Errorf("invalid state signature")
	}
	if verified != stateParam {
		return fmt.Errorf("state mismatch")
	}
	return nil
}

func validateRedirect(rd, baseURL string) (string, error) {
	if rd == "" {
		return baseURL + "/", nil
	}
	if strings.HasPrefix(rd, "//") {
		return "", fmt.Errorf("protocol-relative URLs not allowed")
	}
	parsed, err := url.Parse(rd)
	if err != nil {
		return "", fmt.Errorf("invalid redirect URL")
	}
	base, err := url.Parse(baseURL)
	if err != nil {
		return "", fmt.Errorf("invalid base URL")
	}
	if !isSiblingHost(parsed.Hostname(), base.Hostname()) {
		return "", fmt.Errorf("redirect host %q not allowed", parsed.Host)
	}
	return rd, nil
}

// isSiblingHost returns true if host is the same as baseHost or shares the
// same parent domain (i.e. is a sibling subdomain). This allows the auth
// service to redirect back to any service on the same domain after login while
// still blocking open-redirect attacks to external hosts.
func isSiblingHost(host, baseHost string) bool {
	if host == "" || baseHost == "" {
		return false
	}
	if host == baseHost {
		return true
	}
	if net.ParseIP(baseHost) != nil {
		return false
	}
	dot := strings.Index(baseHost, ".")
	if dot < 0 {
		return false
	}
	// Only strip the leading subdomain label (e.g. "auth" from "auth.example.com")
	// when the remainder still contains at least one dot ("example.com").
	// If baseHost is an apex domain ("example.com"), require a subdomain of baseHost.
	parentSuffix := "." + baseHost
	if strings.Contains(baseHost[dot+1:], ".") {
		parentSuffix = baseHost[dot:]
	}
	return strings.HasSuffix(host, parentSuffix)
}
