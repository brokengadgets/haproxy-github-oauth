package config_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"haproxy-github-oauth/internal/config"
)

func setEnv(t *testing.T, pairs map[string]string) {
	t.Helper()
	for k, v := range pairs {
		t.Setenv(k, v)
	}
}

func validEnv() map[string]string {
	return map[string]string{
		"GITHUB_CLIENT_ID":     "client-id",
		"GITHUB_CLIENT_SECRET": "client-secret",
		"GITHUB_ORG":           "my-org",
		"JWT_SECRET":           "a-secret-that-is-at-least-32-chars!!",
		"BASE_URL":             "https://auth.example.com",
		"COOKIE_DOMAIN":        ".example.com",
	}
}

func TestLoad_ValidConfig(t *testing.T) {
	setEnv(t, validEnv())

	cfg, err := config.Load()
	require.NoError(t, err)

	assert.Equal(t, "client-id", cfg.GitHubClientID)
	assert.Equal(t, "my-org", cfg.GitHubOrg)
	assert.Equal(t, ":4180", cfg.ListenAddr)
	assert.Equal(t, 8*time.Hour, cfg.SessionDuration)
	assert.Empty(t, cfg.AllowedTeams)
}

func TestLoad_MissingRequiredFields(t *testing.T) {
	tests := []struct {
		name    string
		missing string
	}{
		{"missing client id", "GITHUB_CLIENT_ID"},
		{"missing client secret", "GITHUB_CLIENT_SECRET"},
		{"missing org", "GITHUB_ORG"},
		{"missing jwt secret", "JWT_SECRET"},
		{"missing base url", "BASE_URL"},
		{"missing cookie domain", "COOKIE_DOMAIN"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			env := validEnv()
			delete(env, tc.missing)
			setEnv(t, env)
			t.Setenv(tc.missing, "")

			_, err := config.Load()
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.missing)
		})
	}
}

func TestLoad_JWTSecretTooShort(t *testing.T) {
	env := validEnv()
	env["JWT_SECRET"] = "tooshort"
	setEnv(t, env)

	_, err := config.Load()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "JWT_SECRET")
}

func TestLoad_CustomSessionDuration(t *testing.T) {
	env := validEnv()
	env["SESSION_DURATION"] = "24h"
	setEnv(t, env)

	cfg, err := config.Load()
	require.NoError(t, err)
	assert.Equal(t, 24*time.Hour, cfg.SessionDuration)
}

func TestLoad_InvalidSessionDuration(t *testing.T) {
	env := validEnv()
	env["SESSION_DURATION"] = "notaduration"
	setEnv(t, env)

	_, err := config.Load()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "SESSION_DURATION")
}

func TestLoad_AllowedTeams(t *testing.T) {
	env := validEnv()
	env["ALLOWED_TEAMS"] = "my-org/admins, my-org/developers"
	setEnv(t, env)

	cfg, err := config.Load()
	require.NoError(t, err)
	assert.Equal(t, []string{"my-org/admins", "my-org/developers"}, cfg.AllowedTeams)
}

func TestLoad_CustomListenAddr(t *testing.T) {
	env := validEnv()
	env["LISTEN_ADDR"] = ":8080"
	setEnv(t, env)

	cfg, err := config.Load()
	require.NoError(t, err)
	assert.Equal(t, ":8080", cfg.ListenAddr)
}
