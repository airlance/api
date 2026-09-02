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

	"airlance.org/api/internal/domain/crypto"
)

var (
	ErrInvalidConfig = errors.New("config: invalid configuration")
)

type KeyRing = crypto.KeyRing

type Ed25519KeyRing struct {
	CurrentKID  string
	PrivateKeys map[string]ed25519.PrivateKey
	PublicKeys  map[string]ed25519.PublicKey
}

type Config struct {
	Env                     string
	HTTPPort                int
	ServiceName             string
	TLSListenerEnabled      bool
	TLSCertFile             string
	TLSKeyFile              string
	TLSTerminationIngress   bool
	RequireTLS              bool
	DatabaseDSN             string
	RedisURL                string
	MinSchemaVersion        uint
	MaxSchemaVersion        uint
	LogLevel                string
	LogFormat               string
	TrustedProxies          []*net.IPNet
	MetricsAllowedCIDRs     []*net.IPNet
	WebAuthnRPID            string
	WebAuthnRPDisplayName   string
	WebAuthnRPOrigins       []string
	AllowedWSOrigins        []string
	SessionTTL              time.Duration
	WSTicketTTL             time.Duration
	APITokenTTL             time.Duration
	DeviceHMACKeyRing       KeyRing
	AuditSubjectHMACKeyRing KeyRing
	JWTKeyRing              Ed25519KeyRing
	WireauthPrivateKey      *rsa.PrivateKey
	WireauthPrivateKeyPath  string
	MaxHTTPBodyBytes        int64
	MaxWSFrameBytes         int64
	MaxWSConnections        int
	MaxWSConnectionsPerIP   int
	MaxWSConnectionsPerUser int
	MaxWSSendQueue          int
	HTTPReadTimeout         time.Duration
	HTTPWriteTimeout        time.Duration
	HTTPIdleTimeout         time.Duration
	WSPreUpgradeTimeout     time.Duration
	WSHandshakeTimeout      time.Duration
	WSIdleTimeout           time.Duration
	MinSupportedProtocol    uint32
	CurrentProtocol         uint32
}

func LoadFromEnv() (*Config, error) {
	env := getEnv("APP_ENV", "development")
	isDevOrTest := env == "development" || env == "test"

	cfg := &Config{
		Env:                     env,
		HTTPPort:                getEnvInt("PORT", 8080),
		ServiceName:             getEnv("SERVICE_NAME", "airlance-api"),
		TLSListenerEnabled:      getEnvBool("TLS_LISTENER_ENABLED", false),
		TLSCertFile:             getEnv("TLS_CERT_FILE", ""),
		TLSKeyFile:              getEnv("TLS_KEY_FILE", ""),
		TLSTerminationIngress:   getEnvBool("TLS_TERMINATION_INGRESS", false),
		RequireTLS:              getEnvBool("REQUIRE_TLS", !isDevOrTest),
		DatabaseDSN:             getEnv("DATABASE_URL", "postgres://postgres:postgres@localhost:5432/airlance?sslmode=disable"),
		RedisURL:                getEnv("REDIS_URL", "redis://localhost:6379/0"),
		MinSchemaVersion:        uint(getEnvInt("MIN_SCHEMA_VERSION", 1)),
		MaxSchemaVersion:        uint(getEnvInt("MAX_SCHEMA_VERSION", 100)),
		LogLevel:                getEnv("LOG_LEVEL", "info"),
		LogFormat:               getEnv("LOG_FORMAT", "json"),
		WebAuthnRPID:            getEnv("WEBAUTHN_RP_ID", "localhost"),
		WebAuthnRPDisplayName:   getEnv("WEBAUTHN_RP_DISPLAY_NAME", "Airlance"),
		WebAuthnRPOrigins:       getEnvSlice("WEBAUTHN_RP_ORIGINS", []string{"http://localhost:3000", "http://localhost:8080", "https://localhost:3000", "https://localhost:8080"}),
		AllowedWSOrigins:        getEnvSlice("ALLOWED_WS_ORIGINS", []string{"http://localhost:3000", "http://localhost:8080", "https://localhost:3000", "https://localhost:8080"}),
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

	proxiesStr := getEnv("TRUSTED_PROXIES", "127.0.0.1/32,::1/128,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16")
	trusted, err := parseCIDRs(proxiesStr)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid trusted proxies: %v", ErrInvalidConfig, err)
	}
	cfg.TrustedProxies = trusted
	metricsCIDRs, err := parseCIDRs(getEnv("METRICS_ALLOWED_CIDRS", "127.0.0.1/32,::1/128"))
	if err != nil {
		return nil, fmt.Errorf("%w: invalid metrics allowed CIDRs: %v", ErrInvalidConfig, err)
	}
	cfg.MetricsAllowedCIDRs = metricsCIDRs

	deviceDefault := ""
	if isDevOrTest {
		deviceDefault = "1:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	}
	deviceRing, err := parseHMACKeyRing("DEVICE_HMAC_KEYS", "DEVICE_HMAC_CURRENT_KEY_ID", deviceDefault, 1, isDevOrTest)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid device HMAC keys: %v", ErrInvalidConfig, err)
	}
	cfg.DeviceHMACKeyRing = deviceRing

	auditDefault := ""
	if isDevOrTest {
		auditDefault = "1:fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
	}
	auditRing, err := parseHMACKeyRing("AUDIT_HMAC_KEYS", "AUDIT_HMAC_CURRENT_KEY_ID", auditDefault, 1, isDevOrTest)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid audit subject HMAC keys: %v", ErrInvalidConfig, err)
	}
	cfg.AuditSubjectHMACKeyRing = auditRing

	jwtRing, err := parseEd25519KeyRing(isDevOrTest)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid JWT keys: %v", ErrInvalidConfig, err)
	}
	cfg.JWTKeyRing = jwtRing

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
		if key.N.BitLen() < 2048 {
			return nil, fmt.Errorf("%w: wireauth RSA key must be at least 2048 bits (got %d)", ErrInvalidConfig, key.N.BitLen())
		}
		cfg.WireauthPrivateKey = key
		cfg.WireauthPrivateKeyPath = wireauthKeyPath
	} else if wireauthKeyPEM != "" {
		key, err := parseRSAPrivateKey([]byte(wireauthKeyPEM))
		if err != nil {
			return nil, fmt.Errorf("%w: failed to parse wireauth RSA key PEM: %v", ErrInvalidConfig, err)
		}
		if key.N.BitLen() < 2048 {
			return nil, fmt.Errorf("%w: wireauth RSA key must be at least 2048 bits (got %d)", ErrInvalidConfig, key.N.BitLen())
		}
		cfg.WireauthPrivateKey = key
	} else if !isDevOrTest {
		return nil, fmt.Errorf("%w: WIREAUTH_RSA_KEY_PATH or WIREAUTH_RSA_KEY_PEM required in %s environment", ErrInvalidConfig, env)
	}

	if cfg.RequireTLS && !isDevOrTest {
		hasLocalTLS := cfg.TLSListenerEnabled && cfg.TLSCertFile != "" && cfg.TLSKeyFile != ""
		hasExplicitIngress := cfg.TLSTerminationIngress && len(cfg.TrustedProxies) > 0
		if !hasLocalTLS && !hasExplicitIngress {
			return nil, fmt.Errorf("%w: REQUIRE_TLS=true in %s requires either local TLS certificate/key (TLS_LISTENER_ENABLED, TLS_CERT_FILE, TLS_KEY_FILE) or explicit TLS_TERMINATION_INGRESS=true with TRUSTED_PROXIES", ErrInvalidConfig, env)
		}
	}

	if !isDevOrTest {
		for _, origins := range [][]string{cfg.AllowedWSOrigins, cfg.WebAuthnRPOrigins} {
			for _, origin := range origins {
				if origin == "*" {
					return nil, fmt.Errorf("%w: wildcard origins are not allowed outside development", ErrInvalidConfig)
				}
			}
		}
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

func parseHMACKeyRing(keysEnv, currentEnv, defaultKeys string, defaultCurrent uint16, isDev bool) (KeyRing, error) {
	keysRaw := os.Getenv(keysEnv)
	if keysRaw == "" {
		if !isDev || defaultKeys == "" {
			return KeyRing{}, fmt.Errorf("missing required environment variable %s", keysEnv)
		}
		keysRaw = defaultKeys
	}

	currentIDVal := os.Getenv(currentEnv)
	var currentID uint16
	if currentIDVal == "" {
		currentID = defaultCurrent
	} else {
		id64, err := strconv.ParseUint(currentIDVal, 10, 16)
		if err != nil {
			return KeyRing{}, fmt.Errorf("invalid %s: %v", currentEnv, err)
		}
		currentID = uint16(id64)
	}

	keyMap := make(map[uint16][]byte)
	entries := strings.Split(keysRaw, ",")
	for _, entry := range entries {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		parts := strings.SplitN(entry, ":", 2)
		if len(parts) != 2 {
			return KeyRing{}, fmt.Errorf("invalid key entry format (expected id:secret): %s", entry)
		}
		idVal, err := strconv.ParseUint(parts[0], 10, 16)
		if err != nil {
			return KeyRing{}, fmt.Errorf("invalid key id: %s", parts[0])
		}
		secret := []byte(parts[1])
		if len(secret) < 32 {
			return KeyRing{}, fmt.Errorf("key id %d size must be at least 32 bytes (got %d bytes)", idVal, len(secret))
		}
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

func parseEd25519KeyRing(isDev bool) (Ed25519KeyRing, error) {
	currentKID := getEnv("JWT_CURRENT_KID", "key-1")
	keysEnv := getEnv("JWT_ED25519_KEYS", "")

	privMap := make(map[string]ed25519.PrivateKey)
	pubMap := make(map[string]ed25519.PublicKey)

	if keysEnv == "" {
		if !isDev {
			return Ed25519KeyRing{}, errors.New("missing required environment variable JWT_ED25519_KEYS")
		}
		seed := []byte("01234567890123456789012345678901")
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

func getEnvBool(key string, def bool) bool {
	if val := os.Getenv(key); val != "" {
		b, err := strconv.ParseBool(val)
		if err == nil {
			return b
		}
	}
	return def
}
