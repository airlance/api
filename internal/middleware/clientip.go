package middleware

import (
	"context"
	"net"
	"net/http"
	"strings"
)

type clientIPKey struct{}

func ClientIPMiddleware(trustedProxies []*net.IPNet) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := resolveClientIP(r, trustedProxies)
			ctx := context.WithValue(r.Context(), clientIPKey{}, ip)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func GetClientIP(ctx context.Context) string {
	if ip, ok := ctx.Value(clientIPKey{}).(string); ok && ip != "" {
		return ip
	}
	return "127.0.0.1"
}

func SetClientIP(ctx context.Context, ip string) context.Context {
	return context.WithValue(ctx, clientIPKey{}, ip)
}

func IsTrustedProxy(remoteAddr string, trustedProxies []*net.IPNet) bool {
	remoteHost, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		remoteHost = remoteAddr
	}
	remoteIP := net.ParseIP(remoteHost)
	if remoteIP == nil {
		return false
	}
	return isIPTrusted(remoteIP, trustedProxies)
}

func IsIPInCIDRs(ip string, cidrs []*net.IPNet) bool {
	parsed := net.ParseIP(ip)
	return parsed != nil && isIPTrusted(parsed, cidrs)
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

	if !isIPTrusted(remoteIP, trustedProxies) {
		return remoteIP.String()
	}

	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		ips := strings.Split(xff, ",")
		for i := len(ips) - 1; i >= 0; i-- {
			candidateStr := strings.TrimSpace(ips[i])
			candidateIP := net.ParseIP(candidateStr)
			if candidateIP != nil && !isIPTrusted(candidateIP, trustedProxies) {
				return candidateIP.String()
			}
		}

		if len(ips) > 0 {
			first := strings.TrimSpace(ips[0])
			if net.ParseIP(first) != nil {
				return first
			}
		}
	}

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
