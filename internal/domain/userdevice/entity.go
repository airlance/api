package userdevice

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"

	"github.com/airlance/api/internal/domain/clientcontext"
)

var ErrNotFound = errors.New("userdevice: not found")

type Device struct {
	ID          int64
	UserID      int32
	Fingerprint string
	DeviceName  string
	Platform    clientcontext.Platform
	OS          string
	FirstSeenAt time.Time
	LastSeenAt  time.Time
}

func ComputeFingerprint(ctx clientcontext.ClientContext) string {
	h := sha256.Sum256([]byte(ctx.UserAgent + "|" + ctx.IPAddress))
	return hex.EncodeToString(h[:])
}
