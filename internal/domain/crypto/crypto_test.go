package crypto

import (
	"testing"
)

func TestGenerateAndVerifyNumericCode(t *testing.T) {
	ring := KeyRing{
		CurrentKeyID: 1,
		Keys: map[uint16][]byte{
			1: []byte("0123456789abcdef0123456789abcdef"),
			2: []byte("fedcba9876543210fedcba9876543210"),
		},
	}

	code, hash, keyID, err := GenerateNumericCode(6, ring)
	if err != nil {
		t.Fatalf("GenerateNumericCode failed: %v", err)
	}
	if len(code) != 6 {
		t.Errorf("expected code length 6, got %d", len(code))
	}
	if keyID != 1 {
		t.Errorf("expected keyID 1, got %d", keyID)
	}
	if len(hash) != 32 {
		t.Errorf("expected hash length 32, got %d", len(hash))
	}

	// Correct code and key verifies
	if !VerifyNumericCode(code, hash, keyID, ring) {
		t.Errorf("VerifyNumericCode should return true for valid code and key")
	}

	// Wrong code fails
	wrongCode := "000000"
	if code == "000000" {
		wrongCode = "111111"
	}
	if VerifyNumericCode(wrongCode, hash, keyID, ring) {
		t.Errorf("VerifyNumericCode should return false for incorrect code")
	}

	// Wrong keyID fails
	if VerifyNumericCode(code, hash, 2, ring) {
		t.Errorf("VerifyNumericCode should return false for mismatched keyID")
	}

	// Unknown keyID fails
	if VerifyNumericCode(code, hash, 999, ring) {
		t.Errorf("VerifyNumericCode should return false for non-existent keyID")
	}
}

func TestGenerateNumericCode_InvalidDigits(t *testing.T) {
	ring := KeyRing{
		CurrentKeyID: 1,
		Keys: map[uint16][]byte{
			1: []byte("0123456789abcdef0123456789abcdef"),
		},
	}

	_, _, _, err := GenerateNumericCode(0, ring)
	if err == nil {
		t.Errorf("expected error for 0 digits")
	}

	_, _, _, err = GenerateNumericCode(-1, ring)
	if err == nil {
		t.Errorf("expected error for negative digits")
	}
}
