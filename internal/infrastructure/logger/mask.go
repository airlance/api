package logger

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"

	"github.com/google/uuid"
)

func MaskIdentifier(raw string, secret []byte) string {
	if raw == "" {
		return "[EMPTY]"
	}
	if len(secret) == 0 {
		h := sha256.Sum256([]byte(raw))
		return "h:" + hex.EncodeToString(h[:8])
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(raw))
	hash := hex.EncodeToString(mac.Sum(nil))
	return "h:" + hash[:16]
}

func MaskUUID(id uuid.UUID, secret []byte) string {
	if id == uuid.Nil {
		return "[NIL]"
	}
	return MaskIdentifier(id.String(), secret)
}
