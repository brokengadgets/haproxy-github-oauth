package auth_test

import (
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"haproxy-github-oauth/internal/auth"
)

func TestNewClient(t *testing.T) {
	c := auth.NewClient("client-id", "client-secret", "https://auth.example.com")
	require.NotNil(t, c)
}

func TestAuthCodeURL(t *testing.T) {
	c := auth.NewClient("client-id", "client-secret", "https://auth.example.com")

	rawURL := c.AuthCodeURL("test-state-123")

	parsed, err := url.Parse(rawURL)
	require.NoError(t, err)

	assert.Equal(t, "github.com", parsed.Host)
	assert.Equal(t, "/login/oauth/authorize", parsed.Path)

	q := parsed.Query()
	assert.Equal(t, "client-id", q.Get("client_id"))
	assert.Equal(t, "test-state-123", q.Get("state"))

	scope := q.Get("scope")
	assert.True(t, strings.Contains(scope, "read:org"), "scope must contain read:org, got: %s", scope)
	assert.True(t, strings.Contains(scope, "read:user"), "scope must contain read:user, got: %s", scope)
}
