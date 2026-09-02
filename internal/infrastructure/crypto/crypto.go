// Package crypto provides cryptographically secure token generation, hashing, and HMAC functions.
package crypto

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"

	"airlance.org/api/internal/config"
)

// GenerateOpaqueToken generates a secure random token and its SHA-256 hash.
func GenerateOpaqueToken(byteLen int) (plaintext string, tokenHash []byte, err error) {
	if byteLen < 16 {
		byteLen = 32
	}
	buf := make([]byte, byteLen)
	if _, err := rand.Read(buf); err != nil {
		return "", nil, fmt.Errorf("crypto: random read failed: %w", err)
	}

	plaintext = base64.RawURLEncoding.EncodeToString(buf)
	h := HashToken(plaintext)
	return plaintext, h, nil
}

// HashToken computes the SHA-256 hash of a plaintext token.
func HashToken(token string) []byte {
	sum := sha256.Sum256([]byte(token))
	res := make([]byte, len(sum))
	copy(res, sum[:])
	return res
}

// ConstantTimeCompareBytes compares two byte slices in constant time.
func ConstantTimeCompareBytes(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}

// ComputeHMAC computes HMAC-SHA256 over data with the given key.
func ComputeHMAC(data, key []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}

// ComputeKeyRingHMAC computes HMAC using the current key in the keyring.
func ComputeKeyRingHMAC(data []byte, ring config.KeyRing) ([]byte, uint16, error) {
	key, ok := ring.Keys[ring.CurrentKeyID]
	if !ok {
		return nil, 0, fmt.Errorf("crypto: current key %d missing from keyring", ring.CurrentKeyID)
	}
	return ComputeHMAC(data, key), ring.CurrentKeyID, nil
}

// VerifyKeyRingHMAC checks if the data matches the hash under any key in the keyring.
// Returns (matched, keyID, needsRotation).
func VerifyKeyRingHMAC(data, expectedHash []byte, ring config.KeyRing) (bool, uint16, bool) {
	// First check current key
	if currentKey, ok := ring.Keys[ring.CurrentKeyID]; ok {
		currentMAC := ComputeHMAC(data, currentKey)
		if ConstantTimeCompareBytes(currentMAC, expectedHash) {
			return true, ring.CurrentKeyID, false
		}
	}

	// Check older keys in ring
	for kid, key := range ring.Keys {
		if kid == ring.CurrentKeyID {
			continue
		}
		mac := ComputeHMAC(data, key)
		if ConstantTimeCompareBytes(mac, expectedHash) {
			return true, kid, true // Matched older key, caller should rotate
		}
	}

	return false, 0, false
}
