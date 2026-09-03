package v1

import (
	"crypto/tls"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"

	"airlance.org/api/internal/config"
)

func TestCookie_SetAndClearSessionCookie(t *testing.T) {
	_, trustedCIDR, _ := net.ParseCIDR("10.0.0.0/8")
	cfg := &config.Config{
		SessionTTL:            30 * 24 * time.Hour,
		TLSTerminationIngress: true,
		TrustedProxies:        []*net.IPNet{trustedCIDR},
	}

	t.Run("development plaintext http", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/passkey/login/verify", nil)
		rec := httptest.NewRecorder()

		SetSessionCookie(rec, req, "test-token-123", cfg.SessionTTL, cfg)

		cookies := rec.Result().Cookies()
		if len(cookies) != 1 {
			t.Fatalf("expected 1 cookie, got %d", len(cookies))
		}
		c := cookies[0]
		if c.Name != DevSessionCookieName {
			t.Errorf("expected cookie name %s, got %s", DevSessionCookieName, c.Name)
		}
		if c.Value != "test-token-123" {
			t.Errorf("expected token value 'test-token-123', got %s", c.Value)
		}
		if !c.HttpOnly {
			t.Errorf("expected HttpOnly to be true")
		}
		if c.Secure {
			t.Errorf("expected Secure to be false on plaintext dev http")
		}
		if c.Path != "/" {
			t.Errorf("expected Path to be '/', got %s", c.Path)
		}
		if c.SameSite != http.SameSiteLaxMode {
			t.Errorf("expected SameSite Lax")
		}
		if c.MaxAge != int(cfg.SessionTTL.Seconds()) {
			t.Errorf("expected MaxAge %d, got %d", int(cfg.SessionTTL.Seconds()), c.MaxAge)
		}
	})

	t.Run("production direct TLS", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/passkey/login/verify", nil)
		req.TLS = &tls.ConnectionState{}
		rec := httptest.NewRecorder()

		SetSessionCookie(rec, req, "test-token-456", cfg.SessionTTL, cfg)

		cookies := rec.Result().Cookies()
		if len(cookies) != 1 {
			t.Fatalf("expected 1 cookie, got %d", len(cookies))
		}
		c := cookies[0]
		if c.Name != HostSessionCookieName {
			t.Errorf("expected host-only cookie name %s, got %s", HostSessionCookieName, c.Name)
		}
		if !c.Secure {
			t.Errorf("expected Secure to be true for __Host- cookie")
		}
		if !c.HttpOnly {
			t.Errorf("expected HttpOnly to be true")
		}
		if c.Path != "/" {
			t.Errorf("expected Path to be '/'")
		}
		if c.Domain != "" {
			t.Errorf("expected no Domain for host-only cookie, got %s", c.Domain)
		}
	})

	t.Run("production TLS termination ingress with X-Forwarded-Proto", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/passkey/login/verify", nil)
		req.RemoteAddr = "10.0.0.1:12345"
		req.Header.Set("X-Forwarded-Proto", "https")
		rec := httptest.NewRecorder()

		SetSessionCookie(rec, req, "test-token-789", cfg.SessionTTL, cfg)

		cookies := rec.Result().Cookies()
		if len(cookies) != 1 {
			t.Fatalf("expected 1 cookie, got %d", len(cookies))
		}
		c := cookies[0]
		if c.Name != HostSessionCookieName {
			t.Errorf("expected cookie name %s, got %s", HostSessionCookieName, c.Name)
		}
		if !c.Secure {
			t.Errorf("expected Secure=true with ingress TLS termination")
		}
	})

	t.Run("ClearSessionCookie removes both host and dev cookies", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/session/revoke", nil)
		rec := httptest.NewRecorder()

		ClearSessionCookie(rec, req)

		cookies := rec.Result().Cookies()
		if len(cookies) != 2 {
			t.Fatalf("expected 2 cookies cleared, got %d", len(cookies))
		}
		for _, c := range cookies {
			if c.MaxAge != -1 {
				t.Errorf("expected MaxAge -1 for cleared cookie %s, got %d", c.Name, c.MaxAge)
			}
			if c.Value != "" {
				t.Errorf("expected empty value for cleared cookie %s", c.Name)
			}
			if c.Path != "/" {
				t.Errorf("expected Path '/' for cleared cookie %s", c.Name)
			}
		}
	})
}

func TestDTO_WebAuthSuccessResponse(t *testing.T) {
	uid := uuid.New()
	dto := WebAuthSuccessResponse{
		User: WebAuthUserResponse{
			ID: uid,
		},
		IsNewUser: true,
	}

	bytes, err := json.Marshal(dto)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var m map[string]any
	if err := json.Unmarshal(bytes, &m); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	userObj, ok := m["user"].(map[string]any)
	if !ok {
		t.Fatalf("expected 'user' object in response")
	}
	if userObj["id"] != uid.String() {
		t.Errorf("expected user id %s, got %v", uid.String(), userObj["id"])
	}
	if m["is_new_user"] != true {
		t.Errorf("expected is_new_user=true")
	}

	forbiddenFields := []string{"token", "Token", "token_hash", "TokenHash", "session", "Session", "secret", "device"}
	for _, f := range forbiddenFields {
		if _, exists := m[f]; exists {
			t.Errorf("SECURITY LEAK: response must not contain field %q", f)
		}
	}
}

func TestAuthHandlers_ValidateBrowserOrigin(t *testing.T) {
	cfg := &config.Config{
		WebAuthnRPOrigins: []string{"https://app.airlance.org", "http://localhost:3000"},
	}
	h := &AuthHandlers{cfg: cfg}

	tests := []struct {
		name         string
		origin       string
		secFetchSite string
		wantAllowed  bool
		wantStatus   int
	}{
		{
			name:         "valid app origin",
			origin:       "https://app.airlance.org",
			secFetchSite: "same-site",
			wantAllowed:  true,
		},
		{
			name:         "valid localhost origin",
			origin:       "http://localhost:3000",
			secFetchSite: "same-origin",
			wantAllowed:  true,
		},
		{
			name:         "empty origin rejected deny-by-default",
			origin:       "",
			secFetchSite: "none",
			wantAllowed:  false,
			wantStatus:   http.StatusForbidden,
		},
		{
			name:         "cross-site sec-fetch-site rejected",
			origin:       "https://app.airlance.org",
			secFetchSite: "cross-site",
			wantAllowed:  false,
			wantStatus:   http.StatusForbidden,
		},
		{
			name:         "unauthorized evil origin rejected",
			origin:       "https://evil.com",
			secFetchSite: "same-site",
			wantAllowed:  false,
			wantStatus:   http.StatusForbidden,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/passkey/login/verify", nil)
			if tc.origin != "" {
				req.Header.Set("Origin", tc.origin)
			}
			if tc.secFetchSite != "" {
				req.Header.Set("Sec-Fetch-Site", tc.secFetchSite)
			}
			rec := httptest.NewRecorder()

			allowed := h.validateBrowserOrigin(rec, req)
			if allowed != tc.wantAllowed {
				t.Fatalf("expected allowed=%v, got %v", tc.wantAllowed, allowed)
			}
			if !tc.wantAllowed && rec.Code != tc.wantStatus {
				t.Fatalf("expected status %d, got %d", tc.wantStatus, rec.Code)
			}
		})
	}
}

func TestDTO_NativeAuthSuccessResponse(t *testing.T) {
	uid := uuid.New()
	dto := NativeAuthSuccessResponse{
		Token: "native-bearer-token-xyz",
		User: WebAuthUserResponse{
			ID: uid,
		},
		IsNewUser: false,
	}

	bytes, err := json.Marshal(dto)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var m map[string]any
	if err := json.Unmarshal(bytes, &m); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if m["token"] != "native-bearer-token-xyz" {
		t.Errorf("expected token in native response, got %v", m["token"])
	}
	userObj, ok := m["user"].(map[string]any)
	if !ok || userObj["id"] != uid.String() {
		t.Errorf("expected user id %s, got %v", uid.String(), m["user"])
	}
}
