package handler_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"haproxy-github-oauth/internal/handler"
	"haproxy-github-oauth/internal/session"
)

const verifySecret = "a-secret-that-is-at-least-32-chars!!"

func TestVerify(t *testing.T) {
	store := session.New(verifySecret, 8*time.Hour)

	validToken, err := store.Issue("octocat", []string{"myorg/admins", "myorg/devs"})
	require.NoError(t, err)

	expiredStore := session.New(verifySecret, -1*time.Second)
	expiredToken, err := expiredStore.Issue("octocat", []string{"myorg/admins"})
	require.NoError(t, err)

	tests := []struct {
		name       string
		cookie     *http.Cookie
		wantStatus int
		wantBody   string
	}{
		{
			name:       "valid JWT returns 200 with claims JSON",
			cookie:     &http.Cookie{Name: "_auth", Value: validToken}, //nolint:gosec // test-only request cookie
			wantStatus: http.StatusOK,
			wantBody:   `"login":"octocat"`,
		},
		{
			name:       "expired JWT returns 401",
			cookie:     &http.Cookie{Name: "_auth", Value: expiredToken}, //nolint:gosec // test-only request cookie
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "tampered JWT returns 401",
			cookie:     &http.Cookie{Name: "_auth", Value: validToken[:len(validToken)-4] + "XXXX"}, //nolint:gosec // test-only request cookie
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "missing cookie returns 401",
			cookie:     nil,
			wantStatus: http.StatusUnauthorized,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/auth/verify", nil)
			if tc.cookie != nil {
				req.AddCookie(tc.cookie)
			}
			rr := httptest.NewRecorder()

			handler.Verify(store).ServeHTTP(rr, req)

			require.Equal(t, tc.wantStatus, rr.Code)
			if tc.wantBody != "" {
				assert.Contains(t, rr.Body.String(), tc.wantBody)
			}
		})
	}
}
