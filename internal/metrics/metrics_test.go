package metrics_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"haproxy-github-oauth/internal/metrics"
)

func newGetReq(path string) *http.Request {
	return httptest.NewRequestWithContext(context.Background(), http.MethodGet, path, nil)
}

func metricsOutput(t *testing.T, m *metrics.Metrics) string {
	t.Helper()
	rr := httptest.NewRecorder()
	m.Handler().ServeHTTP(rr, newGetReq("/metrics"))
	require.Equal(t, http.StatusOK, rr.Code)
	return rr.Body.String()
}

func TestMetrics_RequestsCountedByStatus(t *testing.T) {
	m := metrics.New()

	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	redir := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/", http.StatusFound) })
	bad := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { http.Error(w, "nope", http.StatusBadRequest) })

	h200 := m.Wrap("/test", ok)
	h302 := m.Wrap("/login", redir)
	h400 := m.Wrap("/cb", bad)

	for range 3 {
		h200.ServeHTTP(httptest.NewRecorder(), newGetReq("/test"))
	}
	for range 2 {
		h302.ServeHTTP(httptest.NewRecorder(), newGetReq("/login"))
	}
	h400.ServeHTTP(httptest.NewRecorder(), newGetReq("/cb"))

	assert.InDelta(t, 3.0, testutil.ToFloat64(m.RequestsTotal.WithLabelValues("GET", "/test", "200")), 0.01)
	assert.InDelta(t, 2.0, testutil.ToFloat64(m.RequestsTotal.WithLabelValues("GET", "/login", "302")), 0.01)
	assert.InDelta(t, 1.0, testutil.ToFloat64(m.RequestsTotal.WithLabelValues("GET", "/cb", "400")), 0.01)
}

func TestMetrics_DurationRecorded(t *testing.T) {
	m := metrics.New()
	h := m.Wrap("/slow", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	h.ServeHTTP(httptest.NewRecorder(), newGetReq("/slow"))

	out := metricsOutput(t, m)
	assert.Contains(t, out, `http_request_duration_seconds_count{method="GET",path="/slow"} 1`)
}

func TestMetrics_ImplicitStatus200(t *testing.T) {
	m := metrics.New()
	h := m.Wrap("/body", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "hello")
	}))
	h.ServeHTTP(httptest.NewRecorder(), newGetReq("/body"))

	assert.InDelta(t, 1.0, testutil.ToFloat64(m.RequestsTotal.WithLabelValues("GET", "/body", "200")), 0.01)
}

func TestMetrics_Handler(t *testing.T) {
	m := metrics.New()
	m.Wrap("/ping", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(httptest.NewRecorder(), newGetReq("/ping"))

	out := metricsOutput(t, m)
	assert.True(t, strings.Contains(out, "http_requests_total"), "must contain http_requests_total")
	assert.True(t, strings.Contains(out, "http_request_duration_seconds"), "must contain duration histogram")
}
