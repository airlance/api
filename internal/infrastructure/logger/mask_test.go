package logger

import (
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestMaskIdentifier(t *testing.T) {
	secret := []byte("01234567890123456789012345678901")
	rawID := "user-1234-sensitive-id"

	masked := MaskIdentifier(rawID, secret)
	if masked == rawID {
		t.Fatalf("masked output must not equal raw ID")
	}
	if strings.Contains(masked, "user-1234") {
		t.Fatalf("masked output must not contain substring of raw ID")
	}

	// Determinism check
	masked2 := MaskIdentifier(rawID, secret)
	if masked != masked2 {
		t.Errorf("expected deterministic mask, got %s and %s", masked, masked2)
	}

	// Distinct inputs produce distinct outputs
	maskedOther := MaskIdentifier("user-5678-other", secret)
	if masked == maskedOther {
		t.Errorf("different inputs should produce distinct masks")
	}
}

func TestMaskUUID(t *testing.T) {
	secret := []byte("01234567890123456789012345678901")
	uid := uuid.New()

	masked := MaskUUID(uid, secret)
	if strings.Contains(masked, uid.String()) {
		t.Fatalf("masked UUID must not contain raw UUID string")
	}
}
