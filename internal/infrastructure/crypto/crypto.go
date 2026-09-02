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

func HashToken(token string) []byte {
	sum := sha256.Sum256([]byte(token))
	res := make([]byte, len(sum))
	copy(res, sum[:])
	return res
}

func ConstantTimeCompareBytes(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}

func ComputeHMAC(data, key []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}

func ComputeKeyRingHMAC(data []byte, ring config.KeyRing) ([]byte, uint16, error) {
	key, ok := ring.Keys[ring.CurrentKeyID]
	if !ok {
		return nil, 0, fmt.Errorf("crypto: current key %d missing from keyring", ring.CurrentKeyID)
	}
	return ComputeHMAC(data, key), ring.CurrentKeyID, nil
}

func VerifyKeyRingHMAC(data, expectedHash []byte, ring config.KeyRing) (bool, uint16, bool) {
	if currentKey, ok := ring.Keys[ring.CurrentKeyID]; ok {
		currentMAC := ComputeHMAC(data, currentKey)
		if ConstantTimeCompareBytes(currentMAC, expectedHash) {
			return true, ring.CurrentKeyID, false
		}
	}

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
