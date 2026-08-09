package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
)

func generateAuthKeyID() (uint64, error) {
	buf := make([]byte, 8)
	if _, err := rand.Read(buf); err != nil {
		return 0, fmt.Errorf("generate auth key id: %w", err)
	}
	return binary.BigEndian.Uint64(buf), nil
}

func generateResumeSecret() (raw string, hash string, err error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", "", fmt.Errorf("generate resume secret: %w", err)
	}
	raw = base64.RawURLEncoding.EncodeToString(buf)
	return raw, hashResumeSecret(raw), nil
}

func hashResumeSecret(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return base64.StdEncoding.EncodeToString(sum[:])
}
