// Package config defines the application configuration loaded from environment variables and defaults.
package config

import (
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

var (
	// ErrInvalidConfig is returned when configuration values fail validation.
	ErrInvalidConfig = errors.New("config: invalid configuration")
)

// KeyRing represents versioned HMAC or asymmetric keys.
type KeyRing struct {
	CurrentKeyID uint16
	Keys         map[uint16][]byte
}

// Ed25519KeyRing represents versioned Ed25519 signing keys for external API JWTs.
type Ed25519KeyRing struct {
	CurrentKID  string
	PrivateKeys map[string]ed25519.PrivateKey
	PublicKeys  map[string]ed25519.PublicKey
}

// Config contains all service configuration settings.
type Config struct {
	// Service & Network
	Env         string
	HTTPPort    int
	ServiceName string

	// Database & Cache
	DatabaseDSN string
	RedisURL    string

	// Schema bounds for rolling deployments
	MinSchemaVersion uint
	MaxSchemaVersion uint

	// Logging
	LogLevel  string
	LogFormat string // "json" or "console"

	// Trusted Proxies for Client IP resolution
	TrustedProxies []*net.IPNet

	// Security: WebAuthn
	WebAuthnRPID          string
	WebAuthnRPDisplayName string
	WebAuthnRPOrigins     []string

	// Security: Sessions & Tokens
	SessionTTL  time.Duration
	WSTicketTTL time.Duration
	APITokenTTL time.Duration

	// Security: Key Rings
	DeviceHMACKeyRing       KeyRing
	AuditSubjectHMACKeyRing KeyRing
	JWTKeyRing              Ed25519KeyRing

	// Security: Wireauth RSA
	WireauthPrivateKey     *rsa.PrivateKey
	WireauthPrivateKeyPath string

	// Server-side timeouts & limits
	MaxHTTPBodyBytes        int64
	MaxWSFrameBytes         int64
	MaxWSConnections        int
	MaxWSConnectionsPerIP   int
	MaxWSConnectionsPerUser int
	MaxWSSendQueue          int

	HTTPReadTimeout     time.Duration
	HTTPWriteTimeout    time.Duration
	HTTPIdleTimeout     time.Duration
	WSPreUpgradeTimeout time.Duration
	WSHandshakeTimeout  time.Duration
	WSIdleTimeout       time.Duration

	// Protocol versioning
	MinSupportedProtocol uint32
	CurrentProtocol      uint32
}

// LoadFromEnv loads configuration from environment variables with sensible defaults.
func LoadFromEnv() (*Config, error) {
	cfg := &Config{
		Env:                     getEnv("APP_ENV", "development"),
		HTTPPort:                getEnvInt("PORT", 8080),
		ServiceName:             getEnv("SERVICE_NAME", "airlance-api"),
		DatabaseDSN:             getEnv("DATABASE_URL", "postgres://postgres:postgres@localhost:5432/airlance?sslmode=disable"),
		RedisURL:                getEnv("REDIS_URL", "redis://localhost:6379/0"),
		MinSchemaVersion:        uint(getEnvInt("MIN_SCHEMA_VERSION", 1)),
		MaxSchemaVersion:        uint(getEnvInt("MAX_SCHEMA_VERSION", 100)),
		LogLevel:                getEnv("LOG_LEVEL", "info"),
		LogFormat:               getEnv("LOG_FORMAT", "json"),
		WebAuthnRPID:            getEnv("WEBAUTHN_RP_ID", "localhost"),
		WebAuthnRPDisplayName:   getEnv("WEBAUTHN_RP_DISPLAY_NAME", "Airlance"),
		WebAuthnRPOrigins:       getEnvSlice("WEBAUTHN_RP_ORIGINS", []string{"http://localhost:3000", "http://localhost:8080"}),
		SessionTTL:              getEnvDuration("SESSION_TTL", 30*24*time.Hour),
		WSTicketTTL:             getEnvDuration("WS_TICKET_TTL", 30*time.Second),
		APITokenTTL:             getEnvDuration("API_TOKEN_TTL", 15*time.Minute),
		MaxHTTPBodyBytes:        getEnvInt64("MAX_HTTP_BODY_BYTES", 2*1024*1024), // 2MB
		MaxWSFrameBytes:         getEnvInt64("MAX_WS_FRAME_BYTES", 64*1024),      // 64KB
		MaxWSConnections:        getEnvInt("MAX_WS_CONNECTIONS", 10000),
		MaxWSConnectionsPerIP:   getEnvInt("MAX_WS_CONNECTIONS_PER_IP", 50),
		MaxWSConnectionsPerUser: getEnvInt("MAX_WS_CONNECTIONS_PER_USER", 10),
		MaxWSSendQueue:          getEnvInt("MAX_WS_SEND_QUEUE", 256),
		HTTPReadTimeout:         getEnvDuration("HTTP_READ_TIMEOUT", 10*time.Second),
		HTTPWriteTimeout:        getEnvDuration("HTTP_WRITE_TIMEOUT", 15*time.Second),
		HTTPIdleTimeout:         getEnvDuration("HTTP_IDLE_TIMEOUT", 60*time.Second),
		WSPreUpgradeTimeout:     getEnvDuration("WS_PRE_UPGRADE_TIMEOUT", 5*time.Second),
		WSHandshakeTimeout:      getEnvDuration("WS_HANDSHAKE_TIMEOUT", 5*time.Second),
		WSIdleTimeout:           getEnvDuration("WS_IDLE_TIMEOUT", 60*time.Second),
		MinSupportedProtocol:    uint32(getEnvInt("MIN_SUPPORTED_PROTOCOL", 1)),
		CurrentProtocol:         uint32(getEnvInt("CURRENT_PROTOCOL", 1)),
	}

	// Parse trusted proxies
	proxiesStr := getEnv("TRUSTED_PROXIES", "127.0.0.1/32,::1/128,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16")
	trusted, err := parseCIDRs(proxiesStr)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid trusted proxies: %v", ErrInvalidConfig, err)
	}
	cfg.TrustedProxies = trusted

	// Parse Device HMAC KeyRing
	deviceRing, err := parseHMACKeyRing("DEVICE_HMAC_KEYS", "DEVICE_HMAC_CURRENT_KEY_ID", "1:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", 1)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid device HMAC keys: %v", ErrInvalidConfig, err)
	}
	cfg.DeviceHMACKeyRing = deviceRing

	// Parse Audit Subject HMAC KeyRing
	auditRing, err := parseHMACKeyRing("AUDIT_HMAC_KEYS", "AUDIT_HMAC_CURRENT_KEY_ID", "1:fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210", 1)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid audit subject HMAC keys: %v", ErrInvalidConfig, err)
	}
	cfg.AuditSubjectHMACKeyRing = auditRing

	// Parse JWT Ed25519 KeyRing
	jwtRing, err := parseEd25519KeyRing()
	if err != nil {
		return nil, fmt.Errorf("%w: invalid JWT keys: %v", ErrInvalidConfig, err)
	}
	cfg.JWTKeyRing = jwtRing

	// Parse wireauth RSA private key
	wireauthKeyPath := getEnv("WIREAUTH_RSA_KEY_PATH", "")
	wireauthKeyPEM := getEnv("WIREAUTH_RSA_KEY_PEM", "")
	if wireauthKeyPath != "" {
		data, err := os.ReadFile(wireauthKeyPath)
		if err != nil {
			return nil, fmt.Errorf("%w: failed to read wireauth RSA key file: %v", ErrInvalidConfig, err)
		}
		key, err := parseRSAPrivateKey(data)
		if err != nil {
			return nil, fmt.Errorf("%w: failed to parse wireauth RSA key: %v", ErrInvalidConfig, err)
		}
		cfg.WireauthPrivateKey = key
		cfg.WireauthPrivateKeyPath = wireauthKeyPath
	} else if wireauthKeyPEM != "" {
		key, err := parseRSAPrivateKey([]byte(wireauthKeyPEM))
		if err != nil {
			return nil, fmt.Errorf("%w: failed to parse wireauth RSA key PEM: %v", ErrInvalidConfig, err)
		}
		cfg.WireauthPrivateKey = key
	}

	return cfg, nil
}

func parseCIDRs(raw string) ([]*net.IPNet, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	parts := strings.Split(raw, ",")
	res := make([]*net.IPNet, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if !strings.Contains(p, "/") {
			// Single IP -> /32 or /128
			ip := net.ParseIP(p)
			if ip == nil {
				return nil, fmt.Errorf("invalid IP: %s", p)
			}
			if ip.To4() != nil {
				p += "/32"
			} else {
				p += "/128"
			}
		}
		_, ipNet, err := net.ParseCIDR(p)
		if err != nil {
			return nil, err
		}
		res = append(res, ipNet)
	}
	return res, nil
}

func parseHMACKeyRing(keysEnv, currentEnv, defaultKeys string, defaultCurrent uint16) (KeyRing, error) {
	keysRaw := getEnv(keysEnv, defaultKeys)
	currentID := uint16(getEnvInt(currentEnv, int(defaultCurrent)))

	keyMap := make(map[uint16][]byte)
	entries := strings.Split(keysRaw, ",")
	for _, entry := range entries {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		parts := strings.SplitN(entry, ":", 2)
		if len(parts) != 2 {
			return KeyRing{}, fmt.Errorf("invalid key entry format (expected id:hex/base64): %s", entry)
		}
		idVal, err := strconv.ParseUint(parts[0], 10, 16)
		if err != nil {
			return KeyRing{}, fmt.Errorf("invalid key id: %s", parts[0])
		}
		secret := []byte(parts[1])
		keyMap[uint16(idVal)] = secret
	}

	if len(keyMap) == 0 {
		return KeyRing{}, errors.New("key ring cannot be empty")
	}
	if _, ok := keyMap[currentID]; !ok {
		return KeyRing{}, fmt.Errorf("current key id %d not present in key set", currentID)
	}

	return KeyRing{
		CurrentKeyID: currentID,
		Keys:         keyMap,
	}, nil
}

func parseEd25519KeyRing() (Ed25519KeyRing, error) {
	currentKID := getEnv("JWT_CURRENT_KID", "key-1")
	keysEnv := getEnv("JWT_ED25519_KEYS", "")

	privMap := make(map[string]ed25519.PrivateKey)
	pubMap := make(map[string]ed25519.PublicKey)

	if keysEnv == "" {
		// Generate deterministic or default test key pair if in dev
		seed := []byte("01234567890123456789012345678901") // 32 bytes
		priv := ed25519.NewKeyFromSeed(seed)
		pub := priv.Public().(ed25519.PublicKey)
		privMap["key-1"] = priv
		pubMap["key-1"] = pub
		return Ed25519KeyRing{
			CurrentKID:  "key-1",
			PrivateKeys: privMap,
			PublicKeys:  pubMap,
		}, nil
	}

	entries := strings.Split(keysEnv, ",")
	for _, entry := range entries {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		parts := strings.SplitN(entry, ":", 2)
		if len(parts) != 2 {
			return Ed25519KeyRing{}, fmt.Errorf("invalid JWT key entry format (expected kid:base64_priv): %s", entry)
		}
		kid := parts[0]
		rawKey, err := base64.StdEncoding.DecodeString(parts[1])
		if err != nil {
			return Ed25519KeyRing{}, fmt.Errorf("failed to decode private key for kid %s: %v", kid, err)
		}
		var priv ed25519.PrivateKey
		if len(rawKey) == ed25519.SeedSize {
			priv = ed25519.NewKeyFromSeed(rawKey)
		} else if len(rawKey) == ed25519.PrivateKeySize {
			priv = ed25519.PrivateKey(rawKey)
		} else {
			return Ed25519KeyRing{}, fmt.Errorf("invalid ed25519 key length %d for kid %s", len(rawKey), kid)
		}
		pub := priv.Public().(ed25519.PublicKey)
		privMap[kid] = priv
		pubMap[kid] = pub
	}

	if _, ok := privMap[currentKID]; !ok {
		return Ed25519KeyRing{}, fmt.Errorf("current JWT kid %s not found in key set", currentKID)
	}

	return Ed25519KeyRing{
		CurrentKID:  currentKID,
		PrivateKeys: privMap,
		PublicKeys:  pubMap,
	}, nil
}

func parseRSAPrivateKey(pemBytes []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("no PEM block found")
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	keyInterface, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	rsaKey, ok := keyInterface.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("not an RSA private key")
	}
	return rsaKey, nil
}

func getEnv(key, def string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return def
}

func getEnvInt(key string, def int) int {
	if val := os.Getenv(key); val != "" {
		if i, err := strconv.Atoi(val); err == nil {
			return i
		}
	}
	return def
}

func getEnvInt64(key string, def int64) int64 {
	if val := os.Getenv(key); val != "" {
		if i, err := strconv.ParseInt(val, 10, 64); err == nil {
			return i
		}
	}
	return def
}

func getEnvDuration(key string, def time.Duration) time.Duration {
	if val := os.Getenv(key); val != "" {
		if d, err := time.ParseDuration(val); err == nil {
			return d
		}
	}
	return def
}

func getEnvSlice(key string, def []string) []string {
	if val := os.Getenv(key); val != "" {
		parts := strings.Split(val, ",")
		var res []string
		for _, p := range parts {
			if s := strings.TrimSpace(p); s != "" {
				res = append(res, s)
			}
		}
		return res
	}
	return def
}
