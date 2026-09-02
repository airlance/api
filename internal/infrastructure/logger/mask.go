package logger

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"

	"github.com/google/uuid"
)

// MaskIdentifier computes a deterministic 16-character keyed hash for subjects
// (e.g. user IDs, session IDs, device IDs, IP rate limit keys) so logs never contain raw identifiers.
func MaskIdentifier(raw string, secret []byte) string {
	if raw == "" {
		return "[EMPTY]"
	}
	if len(secret) == 0 {
		// Fallback deterministic mask if no secret ring provided
		h := sha256.Sum256([]byte(raw))
		return "h:" + hex.EncodeToString(h[:8])
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(raw))
	hash := hex.EncodeToString(mac.Sum(nil))
	return "h:" + hash[:16]
}

// MaskUUID masks a UUID.
func MaskUUID(id uuid.UUID, secret []byte) string {
	if id == uuid.Nil {
		return "[NIL]"
	}
	return MaskIdentifier(id.String(), secret)
}
