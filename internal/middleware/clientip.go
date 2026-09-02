// Package middleware provides HTTP middlewares for client IP, authentication, rate limiting, and telemetry.
package middleware

import (
	"context"
	"net"
	"net/http"
	"strings"
)

type clientIPKey struct{}

// ClientIPMiddleware extracts and validates the real client IP based on trusted proxy configuration.
func ClientIPMiddleware(trustedProxies []*net.IPNet) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := resolveClientIP(r, trustedProxies)
			ctx := context.WithValue(r.Context(), clientIPKey{}, ip)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// GetClientIP extracts the resolved client IP from context.
func GetClientIP(ctx context.Context) string {
	if ip, ok := ctx.Value(clientIPKey{}).(string); ok && ip != "" {
		return ip
	}
	return "127.0.0.1"
}

// SetClientIP returns a new context with the specified client IP (useful in testing).
func SetClientIP(ctx context.Context, ip string) context.Context {
	return context.WithValue(ctx, clientIPKey{}, ip)
}

func resolveClientIP(r *http.Request, trustedProxies []*net.IPNet) string {
	remoteHost, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		remoteHost = r.RemoteAddr
	}
	remoteIP := net.ParseIP(remoteHost)
	if remoteIP == nil {
		return remoteHost
	}

	// If remote IP is not a trusted proxy, do not trust any forwarding headers.
	if !isIPTrusted(remoteIP, trustedProxies) {
		return remoteIP.String()
	}

	// Check X-Forwarded-For (leftmost untrusted IP or first IP)
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		ips := strings.Split(xff, ",")
		for i := len(ips) - 1; i >= 0; i-- {
			candidateStr := strings.TrimSpace(ips[i])
			candidateIP := net.ParseIP(candidateStr)
			if candidateIP != nil && !isIPTrusted(candidateIP, trustedProxies) {
				return candidateIP.String()
			}
		}
		// If all were trusted proxies, return the first
		if len(ips) > 0 {
			first := strings.TrimSpace(ips[0])
			if net.ParseIP(first) != nil {
				return first
			}
		}
	}

	// Check X-Real-IP
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		realIP := strings.TrimSpace(xri)
		if parsed := net.ParseIP(realIP); parsed != nil {
			return parsed.String()
		}
	}

	return remoteIP.String()
}

func isIPTrusted(ip net.IP, trustedProxies []*net.IPNet) bool {
	for _, subnet := range trustedProxies {
		if subnet.Contains(ip) {
			return true
		}
	}
	return false
}
