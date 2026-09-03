package http

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"airlance.org/api/internal/config"
)

func TestCORS_NativeEndpointsDenyBrowserOrigin(t *testing.T) {
	s := &Server{
		cfg: &config.Config{
			WebAuthnRPOrigins: []string{"https://app.airlance.org"},
		},
	}

	dummyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := s.corsMiddleware(dummyHandler)

	t.Run("browser origin to native endpoint is blocked", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/native/auth/passkey/login/verify", nil)
		req.Header.Set("Origin", "https://app.airlance.org")
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusForbidden {
			t.Fatalf("expected 403 Forbidden on browser calling native endpoint, got %d", rec.Code)
		}
		if corsHeader := rec.Header().Get("Access-Control-Allow-Origin"); corsHeader != "" {
			t.Fatalf("CRITICAL SECURITY FLAW: native endpoint must not return Access-Control-Allow-Origin, got: %s", corsHeader)
		}
	})

	t.Run("sec-fetch-site to native endpoint is blocked", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/native/auth/passkey/login/verify", nil)
		req.Header.Set("Sec-Fetch-Site", "same-site")
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusForbidden {
			t.Fatalf("expected 403 Forbidden on sec-fetch-site to native endpoint, got %d", rec.Code)
		}
	})

	t.Run("native client without browser origin is allowed through", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/native/auth/passkey/login/verify", nil)
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200 OK for native client, got %d", rec.Code)
		}
		if corsHeader := rec.Header().Get("Access-Control-Allow-Origin"); corsHeader != "" {
			t.Fatalf("native response must not have CORS headers, got: %s", corsHeader)
		}
	})

	t.Run("web route with allowed origin receives CORS header", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/passkey/login/verify", nil)
		req.Header.Set("Origin", "https://app.airlance.org")
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200 OK for web route, got %d", rec.Code)
		}
		if corsHeader := rec.Header().Get("Access-Control-Allow-Origin"); corsHeader != "https://app.airlance.org" {
			t.Fatalf("expected Access-Control-Allow-Origin https://app.airlance.org, got: %s", corsHeader)
		}
	})
}

func TestNativeHostMiddleware_Enforcement(t *testing.T) {
	s := &Server{
		cfg: &config.Config{
			NativeAuthHostname: "native.airlance.org",
		},
	}

	dummyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := s.nativeHostMiddleware(dummyHandler)

	t.Run("native endpoint on correct native host passes", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/native/auth/passkey/login/verify", nil)
		req.Host = "native.airlance.org:443"
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", rec.Code)
		}
	})

	t.Run("native endpoint on web host is rejected with 404", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/native/auth/passkey/login/verify", nil)
		req.Host = "api.airlance.org"
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusNotFound {
			t.Fatalf("expected 404 on native route called via web host, got %d", rec.Code)
		}
	})

	t.Run("web endpoint on native host is rejected with 404", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/passkey/login/verify", nil)
		req.Host = "native.airlance.org"
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusNotFound {
			t.Fatalf("expected 404 on web route called via native host, got %d", rec.Code)
		}
	})
}
