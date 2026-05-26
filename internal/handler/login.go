package handler

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"

	"haproxy-github-oauth/internal/auth"
)

// Login returns an http.Handler that redirects to GitHub OAuth, setting a
// signed CSRF state cookie.
func Login(client *auth.Client, cookieSecret string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		state, signedState, err := generateSignedState(cookieSecret)
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		http.SetCookie(w, &http.Cookie{
			Name:     "oauth_state",
			Value:    signedState,
			Path:     "/",
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteLaxMode,
			MaxAge:   300,
		})

		if rd := r.URL.Query().Get("rd"); rd != "" {
			http.SetCookie(w, &http.Cookie{
				Name:     "oauth_rd",
				Value:    rd,
				Path:     "/",
				HttpOnly: true,
				Secure:   true,
				SameSite: http.SameSiteLaxMode,
				MaxAge:   300,
			})
		}

		http.Redirect(w, r, client.AuthCodeURL(state), http.StatusFound)
	})
}

// generateSignedState returns a random state token and its HMAC-signed form
// (state + "." + hex(HMAC-SHA256(state, secret))) for CSRF protection.
func generateSignedState(secret string) (state, signed string, err error) {
	b := make([]byte, 16)
	if _, err = rand.Read(b); err != nil {
		return "", "", fmt.Errorf("generate state: %w", err)
	}
	state = hex.EncodeToString(b)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(state))
	signed = state + "." + hex.EncodeToString(mac.Sum(nil))
	return state, signed, nil
}

// VerifyStateSignature validates that signedState was produced by generateSignedState
// using the same secret, and returns the raw state token.
func VerifyStateSignature(signedState, secret string) (string, bool) {
	if len(signedState) < 33 || signedState[32] != '.' {
		return "", false
	}
	state := signedState[:32]
	gotSig := signedState[33:]

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(state))
	wantSig := hex.EncodeToString(mac.Sum(nil))

	if !hmac.Equal([]byte(gotSig), []byte(wantSig)) {
		return "", false
	}
	return state, true
}
