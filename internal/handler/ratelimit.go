package handler

import (
	"net/http"
	"strings"
	"sync"

	"golang.org/x/time/rate"
)

// RateLimit wraps h with a per-IP token-bucket rate limiter.
// r is the sustained request rate (requests/second); burst is the maximum burst size.
func RateLimit(h http.Handler, r rate.Limit, burst int) http.Handler {
	type entry struct {
		limiter *rate.Limiter
	}
	var mu sync.Mutex
	limiters := make(map[string]*entry)

	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		ip := clientIP(req)

		mu.Lock()
		e, ok := limiters[ip]
		if !ok {
			e = &entry{limiter: rate.NewLimiter(r, burst)}
			limiters[ip] = e
		}
		lim := e.limiter
		mu.Unlock()

		if !lim.Allow() {
			http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
			return
		}
		h.ServeHTTP(w, req)
	})
}

// clientIP returns the client IP from X-Forwarded-For (first entry) or RemoteAddr.
func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if idx := strings.IndexByte(xff, ','); idx >= 0 {
			return strings.TrimSpace(xff[:idx])
		}
		return strings.TrimSpace(xff)
	}
	// Strip port from RemoteAddr.
	addr := r.RemoteAddr
	if idx := strings.LastIndexByte(addr, ':'); idx >= 0 {
		return addr[:idx]
	}
	return addr
}
