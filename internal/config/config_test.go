package config

import (
	"os"
	"testing"
	"time"
)

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
	os.Setenv("PORT", "9090")
	os.Setenv("LOG_LEVEL", "debug")
	os.Setenv("TRUSTED_PROXIES", "10.0.0.1,192.168.1.0/24")
	defer func() {
		os.Unsetenv("PORT")
		os.Unsetenv("LOG_LEVEL")
		os.Unsetenv("TRUSTED_PROXIES")
	}()

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
