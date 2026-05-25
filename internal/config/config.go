// Package config loads and validates application configuration from environment variables.
package config

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
)

// Config holds all application configuration.
type Config struct {
	GitHubClientID     string
	GitHubClientSecret string
	GitHubOrg          string
	JWTSecret          string
	BaseURL            string
	CookieDomain       string
	ListenAddr         string
	SessionDuration    time.Duration
	AllowedTeams       []string
}

// Load reads configuration from environment variables and returns a validated Config.
func Load() (*Config, error) {
	cfg := &Config{
		ListenAddr: getEnvDefault("LISTEN_ADDR", ":4180"),
	}

	var errs []string

	required := map[string]*string{
		"GITHUB_CLIENT_ID":     &cfg.GitHubClientID,
		"GITHUB_CLIENT_SECRET": &cfg.GitHubClientSecret,
		"GITHUB_ORG":           &cfg.GitHubOrg,
		"JWT_SECRET":           &cfg.JWTSecret,
		"BASE_URL":             &cfg.BaseURL,
		"COOKIE_DOMAIN":        &cfg.CookieDomain,
	}
	for name, dst := range required {
		val := os.Getenv(name)
		if val == "" {
			errs = append(errs, fmt.Sprintf("%s is required", name))
			continue
		}
		*dst = val
	}

	if len(cfg.JWTSecret) > 0 && len(cfg.JWTSecret) < 32 {
		errs = append(errs, "JWT_SECRET must be at least 32 characters")
	}

	dur := getEnvDefault("SESSION_DURATION", "8h")
	d, err := time.ParseDuration(dur)
	if err != nil {
		errs = append(errs, fmt.Sprintf("SESSION_DURATION is not a valid duration: %s", dur))
	} else {
		cfg.SessionDuration = d
	}

	if raw := os.Getenv("ALLOWED_TEAMS"); raw != "" {
		for _, t := range strings.Split(raw, ",") {
			if t = strings.TrimSpace(t); t != "" {
				cfg.AllowedTeams = append(cfg.AllowedTeams, t)
			}
		}
	}

	if len(errs) > 0 {
		return nil, errors.New(strings.Join(errs, "; "))
	}

	return cfg, nil
}

func getEnvDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
