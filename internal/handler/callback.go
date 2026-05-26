package handler

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"haproxy-github-oauth/internal/auth"
	"haproxy-github-oauth/internal/session"
)

// Callback returns an http.Handler for GET /callback.
// It validates the OAuth state, exchanges the code for a token, fetches team
// memberships, issues a JWT session cookie, and redirects to the `rd` parameter.
func Callback(client *auth.Client, store *session.Store, baseURL, cookieSecret, cookieDomain string) http.Handler {
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

		login := oauthToken.Extra("login")
		loginStr, _ := login.(string)

		tokenStr, err := store.Issue(loginStr, teams)
		if err != nil {
			http.Error(w, "session issue failed", http.StatusInternalServerError)
			return
		}

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
	if host == baseHost {
		return true
	}
	dot := strings.Index(baseHost, ".")
	if dot < 0 {
		return false
	}
	return strings.HasSuffix(host, baseHost[dot:])
}
