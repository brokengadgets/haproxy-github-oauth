package handler

import (
	"net/http"
)

// Logout returns an http.Handler for GET /logout.
// It clears the _auth session cookie and redirects to /.
func Logout(cookieDomain string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{
			Name:     "_auth",
			Value:    "",
			Path:     "/",
			Domain:   cookieDomain,
			MaxAge:   -1,
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteLaxMode,
		})
		http.Redirect(w, r, "/", http.StatusFound)
	})
}
