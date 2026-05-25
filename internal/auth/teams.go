package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
)

type teamResponse struct {
	Slug         string  `json:"slug"`
	Organization orgInfo `json:"organization"`
}

type orgInfo struct {
	Login string `json:"login"`
}

var linkNextRe = regexp.MustCompile(`<([^>]+)>;\s*rel="next"`)

// FetchTeams calls the GitHub API to retrieve all team memberships for the
// authenticated user and returns them as "org/team-slug" strings.
func (c *Client) FetchTeams(ctx context.Context, accessToken string) ([]string, error) {
	nextURL := c.apiBaseURL + "/user/teams"
	var teams []string

	for nextURL != "" {
		batch, next, err := c.fetchTeamsPage(ctx, accessToken, nextURL)
		if err != nil {
			return nil, err
		}
		teams = append(teams, batch...)
		nextURL = next
	}
	return teams, nil
}

func (c *Client) fetchTeamsPage(ctx context.Context, accessToken, url string) ([]string, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, "", fmt.Errorf("build teams request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("fetch teams: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck // best-effort close; error unactionable here

	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("github api returned status %d", resp.StatusCode)
	}

	var raw []teamResponse
	if err = json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return nil, "", fmt.Errorf("decode teams response: %w", err)
	}

	teams := make([]string, 0, len(raw))
	for _, t := range raw {
		teams = append(teams, t.Organization.Login+"/"+t.Slug)
	}

	next := parseNextLink(resp.Header.Get("Link"))
	return teams, next, nil
}

func parseNextLink(header string) string {
	if m := linkNextRe.FindStringSubmatch(header); len(m) == 2 {
		return m[1]
	}
	return ""
}
