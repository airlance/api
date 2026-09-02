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

type KeyRing struct {
	CurrentKeyID uint16
	Keys         map[uint16][]byte
}

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

func HashToken(token string) []byte {
	h := sha256.Sum256([]byte(token))
	return h[:]
}

func HashTokenHex(token string) string {
	return hex.EncodeToString(HashToken(token))
}

func ComputeHMAC(data, key []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}

func ConstantTimeCompareBytes(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}

func ComputeKeyRingHMAC(data []byte, ring KeyRing) ([]byte, uint16, error) {
	key, ok := ring.Keys[ring.CurrentKeyID]
	if !ok || len(key) == 0 {
		return nil, 0, errors.New("crypto: current key not found in key ring")
	}
	return ComputeHMAC(data, key), ring.CurrentKeyID, nil
}
