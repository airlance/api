package config

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"
)

func generateTestRSAPEM() string {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	b := x509.MarshalPKCS1PrivateKey(key)
	return string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: b}))
}

func TestLoadFromEnv_Defaults(t *testing.T) {
	cfg, err := LoadFromEnv()
	if err != nil {
		t.Fatalf("unexpected error loading config defaults: %v", err)
	}

	if cfg.HTTPPort != 8080 {
		t.Errorf("expected port 8080, got %d", cfg.HTTPPort)
	}
	if cfg.SessionTTL != 30*24*time.Hour {
		t.Errorf("expected session TTL 30 days, got %v", cfg.SessionTTL)
	}
	if len(cfg.TrustedProxies) == 0 {
		t.Errorf("expected default trusted proxies, got none")
	}
	if cfg.DeviceHMACKeyRing.CurrentKeyID != 1 {
		t.Errorf("expected device HMAC key id 1, got %d", cfg.DeviceHMACKeyRing.CurrentKeyID)
	}
	if cfg.JWTKeyRing.CurrentKID != "key-1" {
		t.Errorf("expected default JWT key id 'key-1', got %s", cfg.JWTKeyRing.CurrentKID)
	}
}

func TestLoadFromEnv_Custom(t *testing.T) {
	t.Setenv("PORT", "9090")
	t.Setenv("LOG_LEVEL", "debug")
	t.Setenv("TRUSTED_PROXIES", "10.0.0.1,192.168.1.0/24")

	cfg, err := LoadFromEnv()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.HTTPPort != 9090 {
		t.Errorf("expected port 9090, got %d", cfg.HTTPPort)
	}
	if cfg.LogLevel != "debug" {
		t.Errorf("expected debug log level, got %s", cfg.LogLevel)
	}
	if len(cfg.TrustedProxies) != 2 {
		t.Errorf("expected 2 trusted proxy subnets, got %d", len(cfg.TrustedProxies))
	}
}

func TestLoadFromEnv_Production_FailClosedWithoutKeys(t *testing.T) {
	t.Setenv("APP_ENV", "production")

	_, err := LoadFromEnv()
	if err == nil {
		t.Errorf("expected error in production when required keys are missing")
	}
}

func TestLoadFromEnv_Production_RequiresTLSByDefault(t *testing.T) {
	t.Setenv("APP_ENV", "production")
	t.Setenv("DEVICE_HMAC_KEYS", "1:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	t.Setenv("AUDIT_HMAC_KEYS", "1:fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210")
	t.Setenv("JWT_CURRENT_KID", "k1")
	t.Setenv("JWT_ED25519_KEYS", "k1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
	t.Setenv("WIREAUTH_RSA_KEY_PEM", generateTestRSAPEM())
	t.Setenv("REQUIRE_TLS", "")
	t.Setenv("TLS_LISTENER_ENABLED", "")
	t.Setenv("TLS_CERT_FILE", "")
	t.Setenv("TLS_KEY_FILE", "")
	t.Setenv("TLS_TERMINATION_INGRESS", "")

	_, err := LoadFromEnv()
	if err == nil {
		t.Fatal("expected production configuration without TLS or explicit ingress to fail")
	}
}

func TestLoadFromEnv_Production_RequireTLS_ExplicitIngress(t *testing.T) {
	rsaPEM := generateTestRSAPEM()

	t.Setenv("APP_ENV", "production")
	t.Setenv("DEVICE_HMAC_KEYS", "1:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	t.Setenv("AUDIT_HMAC_KEYS", "1:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	t.Setenv("JWT_CURRENT_KID", "k1")
	t.Setenv("JWT_ED25519_KEYS", "k1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
	t.Setenv("WIREAUTH_RSA_KEY_PEM", rsaPEM)
	t.Setenv("REQUIRE_TLS", "true")

	_, err := LoadFromEnv()
	if err == nil {
		t.Errorf("expected error in production when REQUIRE_TLS=true without explicit ingress mode")
	}

	t.Setenv("TLS_TERMINATION_INGRESS", "true")
	cfg, err := LoadFromEnv()
	if err != nil {
		t.Fatalf("expected success with explicit TLS_TERMINATION_INGRESS=true, got %v", err)
	}
	if !cfg.TLSTerminationIngress {
		t.Errorf("expected TLSTerminationIngress to be true")
	}

	t.Setenv("SMTP_ENABLED", "true")
	t.Setenv("SMTP_HOST", "smtp.example.test")
	t.Setenv("SMTP_PORT", "587")
	t.Setenv("SMTP_FROM", "no-reply@example.test")
	t.Setenv("SMTP_STARTTLS", "false")
	if _, err := LoadFromEnv(); err == nil {
		t.Fatal("expected production SMTP without STARTTLS to fail")
	}

	t.Setenv("SMTP_STARTTLS", "true")
	if _, err := LoadFromEnv(); err != nil {
		t.Fatalf("expected production SMTP with STARTTLS to load: %v", err)
	}
}

func TestLoadFromEnv_ShortHMACKey_Fails(t *testing.T) {
	t.Setenv("DEVICE_HMAC_KEYS", "1:too_short_key")

	_, err := LoadFromEnv()
	if err == nil {
		t.Errorf("expected error when HMAC key is shorter than 32 bytes")
	}
}

func TestLoadFromEnv_KeyRotation_MultiKey(t *testing.T) {
	t.Setenv("DEVICE_HMAC_KEYS", "1:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef,2:fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210")
	t.Setenv("DEVICE_HMAC_CURRENT_KEY_ID", "2")

	cfg, err := LoadFromEnv()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.DeviceHMACKeyRing.CurrentKeyID != 2 {
		t.Errorf("expected current key ID 2, got %d", cfg.DeviceHMACKeyRing.CurrentKeyID)
	}
	if len(cfg.DeviceHMACKeyRing.Keys) != 2 {
		t.Errorf("expected 2 keys in keyring, got %d", len(cfg.DeviceHMACKeyRing.Keys))
	}
}

func TestLoadFromEnv_SMTPEnabledRequiresSafeConfiguration(t *testing.T) {
	t.Setenv("APP_ENV", "development")
	t.Setenv("SMTP_ENABLED", "true")
	t.Setenv("SMTP_FROM", "no-reply@example.test")
	t.Setenv("SMTP_HOST", "")

	if _, err := LoadFromEnv(); err == nil {
		t.Fatal("expected enabled SMTP without SMTP_HOST to fail")
	}

	t.Setenv("SMTP_HOST", "smtp.example.test")
	t.Setenv("SMTP_PORT", "587")
	t.Setenv("SMTP_USERNAME", "mailer")
	t.Setenv("SMTP_PASSWORD", "")
	if _, err := LoadFromEnv(); err == nil {
		t.Fatal("expected SMTP credentials with missing password to fail")
	}
}
