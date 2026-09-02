package crypto

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
)

// KeyRing represents versioned HMAC keys.
type KeyRing struct {
	CurrentKeyID uint16
	Keys         map[uint16][]byte
}

// GenerateOpaqueToken generates cryptographically secure random bytes and returns the hex-encoded
// raw token alongside its SHA-256 hash byte slice.
func GenerateOpaqueToken(byteLength int) (token string, hash []byte, err error) {
	if byteLength <= 0 {
		return "", nil, errors.New("crypto: byteLength must be positive")
	}
	bytes := make([]byte, byteLength)
	if _, err := rand.Read(bytes); err != nil {
		return "", nil, fmt.Errorf("crypto: rand read failed: %w", err)
	}
	rawToken := hex.EncodeToString(bytes)
	return rawToken, HashToken(rawToken), nil
}

// HashToken calculates the deterministic SHA-256 hash bytes of an opaque token.
func HashToken(token string) []byte {
	h := sha256.Sum256([]byte(token))
	return h[:]
}

// HashTokenHex calculates the hex-encoded SHA-256 hash of an opaque token.
func HashTokenHex(token string) string {
	return hex.EncodeToString(HashToken(token))
}

// ComputeHMAC computes HMAC-SHA256 of data using the given key.
func ComputeHMAC(data, key []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}

// ConstantTimeCompareBytes performs constant-time comparison of two byte slices.
func ConstantTimeCompareBytes(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}

// ComputeKeyRingHMAC computes HMAC using the current key in the ring and returns (hash, keyID, error).
func ComputeKeyRingHMAC(data []byte, ring KeyRing) ([]byte, uint16, error) {
	key, ok := ring.Keys[ring.CurrentKeyID]
	if !ok || len(key) == 0 {
		return nil, 0, errors.New("crypto: current key not found in key ring")
	}
	return ComputeHMAC(data, key), ring.CurrentKeyID, nil
}
