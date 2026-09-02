package middleware

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestClientIPMiddleware_DirectConnection(t *testing.T) {
	_, trustedSubnet, _ := net.ParseCIDR("10.0.0.0/8")
	trustedProxies := []*net.IPNet{trustedSubnet}

	mw := ClientIPMiddleware(trustedProxies)

	req := httptest.NewRequest("GET", "/healthz", nil)
	req.RemoteAddr = "203.0.113.195:12345"
	req.Header.Set("X-Forwarded-For", "198.51.100.1") // Untrusted peer spoofing header

	var capturedIP string
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedIP = GetClientIP(r.Context())
	}))

	handler.ServeHTTP(httptest.NewRecorder(), req)

	if capturedIP != "203.0.113.195" {
		t.Errorf("expected peer IP 203.0.113.195 since peer is untrusted, got %s", capturedIP)
	}
}

func TestClientIPMiddleware_TrustedProxy(t *testing.T) {
	_, trustedSubnet, _ := net.ParseCIDR("10.0.0.0/8")
	trustedProxies := []*net.IPNet{trustedSubnet}

	mw := ClientIPMiddleware(trustedProxies)

	req := httptest.NewRequest("GET", "/healthz", nil)
	req.RemoteAddr = "10.0.0.5:12345"
	req.Header.Set("X-Forwarded-For", "198.51.100.42, 10.0.0.2")

	var capturedIP string
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedIP = GetClientIP(r.Context())
	}))

	handler.ServeHTTP(httptest.NewRecorder(), req)

	if capturedIP != "198.51.100.42" {
		t.Errorf("expected client IP 198.51.100.42 from XFF header, got %s", capturedIP)
	}
}
