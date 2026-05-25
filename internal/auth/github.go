// Package auth handles GitHub OAuth flow and team membership fetching.
package auth

import (
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
)

// Client wraps the OAuth2 config for GitHub authentication.
type Client struct {
	oauthCfg   *oauth2.Config
	apiBaseURL string
}

// NewClient constructs a Client targeting the real GitHub API.
func NewClient(clientID, clientSecret, baseURL string) *Client {
	return NewClientWithBaseURL(clientID, clientSecret, baseURL, "https://api.github.com")
}

// NewClientWithBaseURL constructs a Client with a custom GitHub API base URL (for testing).
func NewClientWithBaseURL(clientID, clientSecret, baseURL, apiBaseURL string) *Client {
	return &Client{
		oauthCfg: &oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			Endpoint:     github.Endpoint,
			RedirectURL:  baseURL + "/callback",
			Scopes:       []string{"read:org", "read:user"},
		},
		apiBaseURL: apiBaseURL,
	}
}

// AuthCodeURL returns the GitHub OAuth authorization URL for the given state value.
func (c *Client) AuthCodeURL(state string) string {
	return c.oauthCfg.AuthCodeURL(state, oauth2.AccessTypeOnline)
}

// OAuthConfig returns the underlying oauth2.Config for token exchange.
func (c *Client) OAuthConfig() *oauth2.Config {
	return c.oauthCfg
}

// SetTokenURL overrides the OAuth2 token endpoint (used in tests).
func (c *Client) SetTokenURL(u string) {
	c.oauthCfg.Endpoint.TokenURL = u
}
