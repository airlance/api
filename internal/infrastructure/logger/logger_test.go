package logger

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
)

func TestLogger_SensitiveValuesNotEmittedRaw(t *testing.T) {
	var buf bytes.Buffer
	zl := zerolog.New(&buf).With().Timestamp().Logger()
	log := &Logger{z: zl}

	secret := []byte("01234567890123456789012345678901")
	rawSessionToken := "sess_secret_token_1234567890"
	rawTicket := "ticket_abcdef123456789"
	rawUserID := uuid.New()
	rawDeviceID := uuid.New()

	log.Named(CategoryRateLimit).Error(
		errors.New("rate limit backend error"),
		"Rate limiter backend check failed",
		"masked_key", MaskIdentifier("ip:192.168.1.100", secret),
		"masked_user", MaskUUID(rawUserID, secret),
		"masked_device", MaskUUID(rawDeviceID, secret),
	)

	out := buf.String()

	if strings.Contains(out, "192.168.1.100") {
		t.Errorf("raw IP leaked into log output: %s", out)
	}
	if strings.Contains(out, rawUserID.String()) {
		t.Errorf("raw User ID leaked into log output: %s", out)
	}
	if strings.Contains(out, rawDeviceID.String()) {
		t.Errorf("raw Device ID leaked into log output: %s", out)
	}
	if strings.Contains(out, rawSessionToken) {
		t.Errorf("raw session token leaked into log output: %s", out)
	}
	if strings.Contains(out, rawTicket) {
		t.Errorf("raw ticket leaked into log output: %s", out)
	}

	if !strings.Contains(out, "masked_key") || !strings.Contains(out, "h:") {
		t.Errorf("expected masked_key with HMAC prefix: %s", out)
	}
}
