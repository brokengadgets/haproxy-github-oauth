package session_test

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"haproxy-github-oauth/internal/session"
)

const testSecret = "a-secret-that-is-at-least-32-chars!!"

func TestIssueAndVerify_RoundTrip(t *testing.T) {
	store := session.New(testSecret, 8*time.Hour)

	token, err := store.Issue("octocat", []string{"myorg/admins", "myorg/devs"})
	require.NoError(t, err)
	require.NotEmpty(t, token)

	claims, err := store.Verify(token)
	require.NoError(t, err)

	assert.Equal(t, "octocat", claims.Subject)
	assert.Equal(t, []string{"myorg/admins", "myorg/devs"}, claims.Teams)
}

func TestVerify_ExpiredToken(t *testing.T) {
	store := session.New(testSecret, -1*time.Second)

	token, err := store.Issue("octocat", []string{"myorg/admins"})
	require.NoError(t, err)

	_, err = store.Verify(token)
	require.Error(t, err)
}

func TestVerify_TamperedSignature(t *testing.T) {
	store := session.New(testSecret, 8*time.Hour)

	token, err := store.Issue("octocat", []string{"myorg/admins"})
	require.NoError(t, err)

	tampered := token[:len(token)-4] + "XXXX"

	_, err = store.Verify(tampered)
	require.Error(t, err)
}

func TestVerify_WrongSecret(t *testing.T) {
	issuer := session.New(testSecret, 8*time.Hour)
	verifier := session.New("different-secret-that-is-also-32chars!", 8*time.Hour)

	token, err := issuer.Issue("octocat", []string{"myorg/admins"})
	require.NoError(t, err)

	_, err = verifier.Verify(token)
	require.Error(t, err)
}

func TestIssue_ClaimsContainExpAndIat(t *testing.T) {
	store := session.New(testSecret, 8*time.Hour)

	token, err := store.Issue("octocat", []string{"myorg/admins"})
	require.NoError(t, err)

	parsed, _, err := jwt.NewParser().ParseUnverified(token, &session.Claims{})
	require.NoError(t, err)

	claims, ok := parsed.Claims.(*session.Claims)
	require.True(t, ok)

	now := time.Now()
	assert.WithinDuration(t, now, claims.IssuedAt.Time, 5*time.Second)
	assert.WithinDuration(t, now.Add(8*time.Hour), claims.ExpiresAt.Time, 5*time.Second)
}

func TestIssue_EmptyTeams(t *testing.T) {
	store := session.New(testSecret, 8*time.Hour)

	token, err := store.Issue("octocat", []string{})
	require.NoError(t, err)

	claims, err := store.Verify(token)
	require.NoError(t, err)
	assert.Empty(t, claims.Teams)
}
