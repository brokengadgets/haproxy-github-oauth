// Package main is the entry point for the haproxy-github-oauth server.
package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"golang.org/x/time/rate"

	"haproxy-github-oauth/internal/auth"
	"haproxy-github-oauth/internal/config"
	"haproxy-github-oauth/internal/handler"
	"haproxy-github-oauth/internal/metrics"
	"haproxy-github-oauth/internal/session"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		slog.Error("config error", "err", err)
		os.Exit(1)
	}

	authClient := auth.NewClient(cfg.GitHubClientID, cfg.GitHubClientSecret, cfg.BaseURL)
	sessionStore := session.New(cfg.JWTSecret, cfg.SessionDuration)

	m := metrics.New()

	mux := http.NewServeMux()
	mux.Handle("GET /metrics", m.Handler())
	mux.Handle("GET /healthz", m.Wrap("/healthz", handler.Health()))
	// 10 req/s per IP, burst 20 — guards against brute-force OAuth initiation.
	mux.Handle("GET /login", m.Wrap("/login", handler.RateLimit(handler.Login(authClient, cfg.JWTSecret), rate.Limit(10), 20)))
	mux.Handle("GET /callback", m.Wrap("/callback", handler.RateLimit(handler.Callback(authClient, sessionStore, cfg.BaseURL, cfg.JWTSecret, cfg.CookieDomain), rate.Limit(10), 20)))
	mux.Handle("GET /logout", m.Wrap("/logout", handler.Logout(cfg.CookieDomain)))
	mux.Handle("GET /auth/verify", m.Wrap("/auth/verify", handler.Verify(sessionStore)))

	srv := &http.Server{
		Addr:         cfg.ListenAddr,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go func() {
		slog.Info("starting server", "addr", cfg.ListenAddr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("server error", "err", err)
			os.Exit(1)
		}
	}()

	<-ctx.Done()
	slog.Info("shutting down")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		slog.Error("shutdown error", "err", err)
	}
}
