package v1

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"airlance.org/api/internal/config"
)

func TestNativeAttestation_Validation(t *testing.T) {
	secretKey := "test-secret-key-32b-length-secure"
	appID := "org.airlance.native"
	challengeID := "test-challenge-12345"

	t.Run("valid attestation passes", func(t *testing.T) {
		token := GenerateNativeAttestation(secretKey, appID, challengeID, time.Now())
		req := httptest.NewRequest(http.MethodPost, "/api/v1/native/auth/passkey/login/verify", nil)
		req.Header.Set(AttestationHeader, token)

		err := ValidateNativeAttestation(req, secretKey, appID, challengeID)
		if err != nil {
			t.Fatalf("expected valid attestation, got error: %v", err)
		}
	})

	t.Run("missing attestation fails", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/native/auth/passkey/login/verify", nil)
		err := ValidateNativeAttestation(req, secretKey, appID, challengeID)
		if !errors.Is(err, ErrAttestationMissing) {
			t.Fatalf("expected ErrAttestationMissing, got: %v", err)
		}
	})

	t.Run("expired timestamp fails", func(t *testing.T) {
		expiredTime := time.Now().Add(-10 * time.Minute)
		token := GenerateNativeAttestation(secretKey, appID, challengeID, expiredTime)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/native/auth/passkey/login/verify", nil)
		req.Header.Set(AttestationHeader, token)

		err := ValidateNativeAttestation(req, secretKey, appID, challengeID)
		if !errors.Is(err, ErrAttestationExpired) {
			t.Fatalf("expected ErrAttestationExpired, got: %v", err)
		}
	})

	t.Run("wrong app ID fails", func(t *testing.T) {
		token := GenerateNativeAttestation(secretKey, "org.evil.app", challengeID, time.Now())
		req := httptest.NewRequest(http.MethodPost, "/api/v1/native/auth/passkey/login/verify", nil)
		req.Header.Set(AttestationHeader, token)

		err := ValidateNativeAttestation(req, secretKey, appID, challengeID)
		if !errors.Is(err, ErrAttestationAppID) {
			t.Fatalf("expected ErrAttestationAppID, got: %v", err)
		}
	})

	t.Run("wrong challenge ID fails signature", func(t *testing.T) {
		token := GenerateNativeAttestation(secretKey, appID, "different-challenge", time.Now())
		req := httptest.NewRequest(http.MethodPost, "/api/v1/native/auth/passkey/login/verify", nil)
		req.Header.Set(AttestationHeader, token)

		err := ValidateNativeAttestation(req, secretKey, appID, challengeID)
		if !errors.Is(err, ErrAttestationSignature) {
			t.Fatalf("expected ErrAttestationSignature, got: %v", err)
		}
	})

	t.Run("wrong secret key fails signature", func(t *testing.T) {
		token := GenerateNativeAttestation("wrong-secret-key-different", appID, challengeID, time.Now())
		req := httptest.NewRequest(http.MethodPost, "/api/v1/native/auth/passkey/login/verify", nil)
		req.Header.Set(AttestationHeader, token)

		err := ValidateNativeAttestation(req, secretKey, appID, challengeID)
		if !errors.Is(err, ErrAttestationSignature) {
			t.Fatalf("expected ErrAttestationSignature, got: %v", err)
		}
	})
}

func TestAuthHandlers_ValidateNativeContextReturnsStaticError(t *testing.T) {
	h := &AuthHandlers{cfg: &config.Config{
		NativeAppSecretKey: "test-secret-key-32b-length-secure",
		NativeAppID:        "org.airlance.native",
	}}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/native/auth/passkey/login/verify", nil)
	req.Header.Set(AttestationHeader, "malformed")
	rec := httptest.NewRecorder()

	if h.validateNativeContext(rec, req, "challenge-id") {
		t.Fatal("expected malformed request signature to be rejected")
	}
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}

	var body map[string]map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if got := body["error"]["message"]; got != "Native authentication verification failed" {
		t.Fatalf("expected a static client-safe message, got %q", got)
	}
}
