package v1

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

var (
	ErrAttestationMissing   = errors.New("missing X-App-Attestation header")
	ErrAttestationMalformed = errors.New("malformed X-App-Attestation header")
	ErrAttestationAppID     = errors.New("unauthorized app ID in attestation")
	ErrAttestationExpired   = errors.New("expired or premature attestation timestamp")
	ErrAttestationSignature = errors.New("invalid cryptographic attestation signature")
)

const (
	AttestationHeader       = "X-App-Attestation"
	MaxAttestationClockSkew = 5 * time.Minute
)

func GenerateNativeAttestation(secretKey, appID, challengeID string, t time.Time) string {
	tsStr := strconv.FormatInt(t.Unix(), 10)
	message := fmt.Sprintf("%s:%s:%s", appID, tsStr, challengeID)
	mac := hmac.New(sha256.New, []byte(secretKey))
	mac.Write([]byte(message))
	sigHex := hex.EncodeToString(mac.Sum(nil))
	return fmt.Sprintf("%s:%s:%s", appID, tsStr, sigHex)
}

func ValidateNativeAttestation(r *http.Request, secretKey, expectedAppID, challengeID string) error {
	headerVal := strings.TrimSpace(r.Header.Get(AttestationHeader))
	if headerVal == "" {
		return ErrAttestationMissing
	}

	parts := strings.Split(headerVal, ":")
	if len(parts) != 3 {
		return ErrAttestationMalformed
	}

	appID, tsStr, sigHex := parts[0], parts[1], parts[2]
	if expectedAppID != "" && appID != expectedAppID {
		return ErrAttestationAppID
	}

	tsUnix, err := strconv.ParseInt(tsStr, 10, 64)
	if err != nil {
		return ErrAttestationMalformed
	}

	now := time.Now()
	tokenTime := time.Unix(tsUnix, 0)
	diff := now.Sub(tokenTime)
	if diff < 0 {
		diff = -diff
	}
	if diff > MaxAttestationClockSkew {
		return ErrAttestationExpired
	}

	sigBytes, err := hex.DecodeString(sigHex)
	if err != nil {
		return ErrAttestationMalformed
	}

	message := fmt.Sprintf("%s:%s:%s", appID, tsStr, challengeID)
	mac := hmac.New(sha256.New, []byte(secretKey))
	mac.Write([]byte(message))
	expectedSig := mac.Sum(nil)

	if !hmac.Equal(sigBytes, expectedSig) {
		return ErrAttestationSignature
	}

	return nil
}
