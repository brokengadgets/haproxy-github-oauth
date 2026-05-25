package auth_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"haproxy-github-oauth/internal/auth"
)

type fakeTeam struct {
	Slug         string      `json:"slug"`
	Organization fakeOrgInfo `json:"organization"`
}

type fakeOrgInfo struct {
	Login string `json:"login"`
}

func TestFetchTeams_SinglePage(t *testing.T) {
	teams := []fakeTeam{
		{Slug: "admins", Organization: fakeOrgInfo{Login: "myorg"}},
		{Slug: "devs", Organization: fakeOrgInfo{Login: "myorg"}},
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/user/teams", r.URL.Path)
		assert.Equal(t, "Bearer test-token", r.Header.Get("Authorization"))
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(teams) //nolint:errcheck,gosec // test only
	}))
	defer srv.Close()

	client := auth.NewClientWithBaseURL("client-id", "client-secret", "https://auth.example.com", srv.URL)
	got, err := client.FetchTeams(context.Background(), "test-token")
	require.NoError(t, err)
	assert.Equal(t, []string{"myorg/admins", "myorg/devs"}, got)
}

func TestFetchTeams_Pagination(t *testing.T) {
	page1 := []fakeTeam{{Slug: "admins", Organization: fakeOrgInfo{Login: "myorg"}}}
	page2 := []fakeTeam{{Slug: "devs", Organization: fakeOrgInfo{Login: "myorg"}}}

	var srvURL string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		page := r.URL.Query().Get("page")
		w.Header().Set("Content-Type", "application/json")
		if page == "2" {
			json.NewEncoder(w).Encode(page2) //nolint:errcheck,gosec // test only
			return
		}
		w.Header().Set("Link", fmt.Sprintf(`<%s/user/teams?page=2>; rel="next"`, srvURL))
		json.NewEncoder(w).Encode(page1) //nolint:errcheck,gosec // test only
	}))
	defer srv.Close()
	srvURL = srv.URL

	client := auth.NewClientWithBaseURL("client-id", "client-secret", "https://auth.example.com", srv.URL)
	got, err := client.FetchTeams(context.Background(), "test-token")
	require.NoError(t, err)
	assert.Equal(t, []string{"myorg/admins", "myorg/devs"}, got)
}

func TestFetchTeams_APIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = fmt.Fprint(w, `{"message":"Bad credentials"}`)
	}))
	defer srv.Close()

	client := auth.NewClientWithBaseURL("client-id", "client-secret", "https://auth.example.com", srv.URL)
	_, err := client.FetchTeams(context.Background(), "bad-token")
	require.Error(t, err)
}
