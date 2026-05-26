// Package metrics provides Prometheus instrumentation for the HTTP server.
package metrics

import (
	"net/http"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Metrics holds the Prometheus counters and histograms for the server.
type Metrics struct {
	reg             *prometheus.Registry
	RequestsTotal   *prometheus.CounterVec
	RequestDuration *prometheus.HistogramVec
}

// New creates a Metrics instance backed by a fresh (non-global) registry.
func New() *Metrics {
	reg := prometheus.NewRegistry()

	requests := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "http_requests_total",
		Help: "Total HTTP requests partitioned by method, path, and status code.",
	}, []string{"method", "path", "status"})

	duration := prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "http_request_duration_seconds",
		Help:    "HTTP request latency in seconds.",
		Buckets: prometheus.DefBuckets,
	}, []string{"method", "path"})

	reg.MustRegister(requests, duration)

	return &Metrics{reg: reg, RequestsTotal: requests, RequestDuration: duration}
}

// Handler returns an http.Handler that serves Prometheus metrics.
func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.reg, promhttp.HandlerOpts{})
}

// Wrap instruments h with request count and latency metrics labelled by path.
func (m *Metrics) Wrap(path string, h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sw := &statusWriter{ResponseWriter: w}
		start := time.Now()
		h.ServeHTTP(sw, r)
		elapsed := time.Since(start).Seconds()
		m.RequestsTotal.WithLabelValues(r.Method, path, strconv.Itoa(sw.status())).Inc()
		m.RequestDuration.WithLabelValues(r.Method, path).Observe(elapsed)
	})
}

// statusWriter wraps http.ResponseWriter to capture the written status code.
type statusWriter struct {
	http.ResponseWriter
	code    int
	written bool
}

func (sw *statusWriter) WriteHeader(code int) {
	if !sw.written {
		sw.code = code
		sw.written = true
	}
	sw.ResponseWriter.WriteHeader(code)
}

func (sw *statusWriter) Write(b []byte) (int, error) {
	if !sw.written {
		sw.code = http.StatusOK
		sw.written = true
	}
	return sw.ResponseWriter.Write(b) //nolint:wrapcheck // intentional pass-through
}

func (sw *statusWriter) status() int {
	if sw.written {
		return sw.code
	}
	return http.StatusOK
}
